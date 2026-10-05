//! Machine facts: the slow-changing description sent on connect.

use daemon_protocol::{DiskFact, InterfaceFact, MachineFacts};

use crate::platform;
use crate::procfs;
mod hosting;

pub fn gather_facts() -> MachineFacts {
    let os_release = platform::read_optional(platform::OS_RELEASE).unwrap_or_default();
    let cpuinfo = platform::read_optional(platform::PROC_CPUINFO).unwrap_or_default();
    let meminfo =
        platform::read_optional(platform::PROC_MEMINFO).and_then(|t| procfs::parse_meminfo(&t));
    let stat =
        platform::read_optional(platform::PROC_STAT).and_then(|t| procfs::parse_proc_stat(&t));
    let mounts = platform::read_optional(platform::PROC_MOUNTS)
        .map(|t| procfs::parse_mounts(&t))
        .unwrap_or_default();

    MachineFacts {
        hostname: hostname(),
        os: os_release_field(&os_release, "ID").unwrap_or_else(|| std::env::consts::OS.to_string()),
        os_version: os_release_field(&os_release, "VERSION_ID").unwrap_or_default(),
        kernel: kernel_version(),
        arch: std::env::consts::ARCH.to_string(),
        libc: libc_flavour(),
        cpu_model: cpu_model(&cpuinfo).unwrap_or_default(),
        cpu_cores: stat
            .as_ref()
            .map(|s| s.per_core.len() as u32)
            .filter(|n| *n > 0)
            .unwrap_or_else(available_parallelism),
        memory_bytes: meminfo.map(|m| m.total).unwrap_or(0),
        disks: mounts
            .iter()
            .map(|m| DiskFact {
                mount: m.mount_point.clone(),
                device: m.device.clone(),
                fs_type: m.fs_type.clone(),
                total_bytes: platform::statvfs(std::path::Path::new(&m.mount_point))
                    .map(|u| u.total_bytes)
                    .unwrap_or(0),
            })
            .collect(),
        interfaces: interfaces(),
        timezone: timezone(),
        boot_ts: stat.map(|s| s.boot_ts).unwrap_or(0),
        init_system: init_system(),
        docker_version: None,
        hosting: hosting::detect(),
    }
}

fn hostname() -> String {
    platform::read_optional(platform::HOSTNAME)
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".into())
}

/// `KEY="value"` or `KEY=value` from os-release.
pub fn os_release_field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
    })
}

fn kernel_version() -> String {
    // "Linux version 6.8.0-45-generic (buildd@...) ..." → 6.8.0-45-generic
    platform::read_optional(platform::PROC_VERSION)
        .and_then(|v| v.split_whitespace().nth(2).map(str::to_string))
        .unwrap_or_default()
}

fn libc_flavour() -> String {
    if cfg!(target_env = "musl") {
        "musl".into()
    } else if cfg!(target_env = "gnu") {
        "glibc".into()
    } else {
        "unknown".into()
    }
}

pub fn cpu_model(cpuinfo: &str) -> Option<String> {
    cpuinfo.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        let key = k.trim();
        (key == "model name" || key == "Model" || key == "cpu model").then(|| v.trim().to_string())
    })
}

fn available_parallelism() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

fn timezone() -> String {
    if let Some(tz) = platform::read_optional(platform::TIMEZONE) {
        return tz.trim().to_string();
    }

    // /etc/localtime → /usr/share/zoneinfo/Europe/London
    std::fs::read_link(platform::LOCALTIME)
        .ok()
        .and_then(|p| {
            let s = p.to_string_lossy().into_owned();
            s.split_once("zoneinfo/").map(|(_, tz)| tz.to_string())
        })
        .unwrap_or_else(|| "UTC".into())
}

fn init_system() -> String {
    if std::path::Path::new("/run/systemd/system").is_dir() {
        "systemd".into()
    } else if std::path::Path::new("/sbin/openrc").exists() {
        "openrc".into()
    } else {
        "unknown".into()
    }
}

/// Interfaces and their addresses. Read from sysfs and the `ip` output
/// is deliberately avoided: `/sys/class/net/*/address` gives MACs and
/// `getifaddrs` gives addresses without spawning anything.
fn interfaces() -> Vec<InterfaceFact> {
    #[cfg(unix)]
    {
        let mut by_name: std::collections::BTreeMap<String, InterfaceFact> =
            std::collections::BTreeMap::new();
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();

        if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
            return Vec::new();
        }

        let mut cursor = addrs;

        while !cursor.is_null() {
            let entry = unsafe { &*cursor };
            let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }
                .to_string_lossy()
                .into_owned();

            if name != "lo" && !entry.ifa_addr.is_null() {
                let family = unsafe { (*entry.ifa_addr).sa_family } as i32;
                let address = match family {
                    libc::AF_INET => {
                        let sa = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                        Some(std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)).to_string())
                    }
                    libc::AF_INET6 => {
                        let sa = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                        let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
                        (!ip.is_unicast_link_local()).then(|| ip.to_string())
                    }
                    _ => None,
                };

                let fact = by_name
                    .entry(name.clone())
                    .or_insert_with(|| InterfaceFact {
                        name: name.clone(),
                        addresses: Vec::new(),
                        mac: platform::read_optional(&format!("/sys/class/net/{name}/address"))
                            .map(|m| m.trim().to_string()),
                    });

                if let Some(address) = address {
                    fact.addresses.push(address);
                }
            }

            cursor = entry.ifa_next;
        }

        unsafe { libc::freeifaddrs(addrs) };

        by_name
            .into_values()
            .filter(|i| !i.addresses.is_empty())
            .collect()
    }

    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_os_release_fields_with_and_without_quotes() {
        let text = "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n";

        assert_eq!(os_release_field(text, "ID").as_deref(), Some("ubuntu"));
        assert_eq!(
            os_release_field(text, "VERSION_ID").as_deref(),
            Some("24.04")
        );
        assert_eq!(os_release_field(text, "NOPE"), None);
    }

    #[test]
    fn reads_cpu_model_from_cpuinfo() {
        assert_eq!(
            cpu_model("processor\t: 0\nmodel name\t: AMD EPYC 7B13\n").as_deref(),
            Some("AMD EPYC 7B13")
        );
    }

    #[test]
    fn facts_are_always_gatherable() {
        let facts = gather_facts();

        assert!(!facts.hostname.is_empty());
        assert!(!facts.arch.is_empty());
        assert!(facts.cpu_cores >= 1);
    }
}
