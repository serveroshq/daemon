//! Listening sockets and the processes behind them, from `/proc` alone.
//! No `ss`, no `lsof`: the parsers read `/proc/net/tcp{,6}` and map the
//! socket inode to a pid by walking `/proc/*/fd`, which is bounded by the
//! process count and costs nothing on a normal machine.

use std::collections::HashMap;
use std::path::Path;

use daemon_protocol::Listener;

/// One row of `/proc/net/tcp` or `/proc/net/tcp6` in LISTEN state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub address: String,
    pub port: u16,
    pub inode: u64,
    pub uid: u32,
    pub v6: bool,
}

/// TCP state 0A is LISTEN.
pub fn parse_proc_net_tcp(text: &str, v6: bool) -> Vec<Socket> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 10 || parts[3] != "0A" {
                return None;
            }

            let (addr_hex, port_hex) = parts[1].split_once(':')?;
            let port = u16::from_str_radix(port_hex, 16).ok()?;
            let uid = parts[7].parse().ok()?;
            let inode = parts[9].parse().ok()?;

            Some(Socket {
                address: decode_address(addr_hex, v6)?,
                port,
                inode,
                uid,
                v6,
            })
        })
        .collect()
}

fn decode_address(hex: &str, v6: bool) -> Option<String> {
    if v6 {
        if hex.len() != 32 {
            return None;
        }

        // Four little-endian 32-bit words.
        let mut bytes = [0u8; 16];

        for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
            let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }

        let ip = std::net::Ipv6Addr::from(bytes);

        Some(match ip.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None if ip.is_unspecified() => "::".into(),
            None => ip.to_string(),
        })
    } else {
        let word = u32::from_str_radix(hex, 16).ok()?;

        Some(std::net::Ipv4Addr::from(word.to_le_bytes()).to_string())
    }
}

/// What `/proc/<pid>` tells us about a process, read once per pid.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub uid: Option<u32>,
    pub ppid: Option<u32>,
    /// `/proc/<pid>/comm`: the kernel's 15-character name.
    pub kernel_comm: Option<String>,
    /// The `name` pm2 sets in the environment of the apps it runs.
    pub pm2_name: Option<String>,
}

impl ProcessInfo {
    pub fn cmdline_text(&self) -> String {
        self.cmdline.join(" ")
    }

    /// The program name, without its path. The first argument wins when it
    /// is a plain name (`redis-server`, even though the binary on disk is
    /// the multi-call `redis-check-rdb`); then the kernel's comm; then the
    /// executable, for processes that rewrote their title.
    pub fn comm(&self) -> Option<&str> {
        let plain =
            |s: &str| !s.is_empty() && !s.contains(char::is_whitespace) && !s.ends_with(':');

        self.cmdline
            .first()
            .map(String::as_str)
            .filter(|c| plain(c))
            .map(|c| c.rsplit('/').next().unwrap_or(c))
            .or_else(|| self.kernel_comm.as_deref().filter(|c| plain(c)))
            .or_else(|| {
                self.exe
                    .as_deref()
                    .map(|e| e.rsplit('/').next().unwrap_or(e))
            })
            .or(self.kernel_comm.as_deref())
    }
}

/// The one thing we take from a process environment: pm2's app name. The
/// rest of the environment is dropped unread into anything; it holds
/// secrets.
pub fn pm2_name_from_environ(raw: &[u8]) -> Option<String> {
    let entries: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
    let under_pm2 = entries
        .iter()
        .any(|e| e.starts_with(b"PM2_HOME=") || e.starts_with(b"pm_id="));

    if !under_pm2 {
        return None;
    }

    entries.iter().find_map(|e| {
        e.strip_prefix(b"name=")
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .filter(|v| !v.is_empty())
    })
}

pub fn parse_cmdline(raw: &[u8]) -> Vec<String> {
    raw.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// `Uid:` and `PPid:` lines from `/proc/<pid>/status`.
pub fn parse_status(text: &str) -> (Option<u32>, Option<u32>) {
    let mut uid = None;
    let mut ppid = None;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().ok();
        }
    }

    (uid, ppid)
}

/// `/etc/passwd` uid → name.
pub fn parse_passwd(text: &str) -> HashMap<u32, String> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split(':');
            let name = parts.next()?;
            parts.next();
            let uid = parts.next()?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

/// Read everything about one process. Any unreadable piece is `None`
/// rather than a failure; a process may exit mid-scan.
pub fn read_process(proc_root: &Path, pid: u32, users: &HashMap<u32, String>) -> ProcessInfo {
    let dir = proc_root.join(pid.to_string());
    let (uid, ppid) = std::fs::read_to_string(dir.join("status"))
        .map(|t| parse_status(&t))
        .unwrap_or((None, None));

    ProcessInfo {
        pid,
        exe: std::fs::read_link(dir.join("exe")).ok().map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        }),
        cmdline: std::fs::read(dir.join("cmdline"))
            .map(|b| parse_cmdline(&b))
            .unwrap_or_default(),
        cwd: std::fs::read_link(dir.join("cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned()),
        user: uid.and_then(|u| users.get(&u).cloned()),
        uid,
        ppid,
        kernel_comm: std::fs::read_to_string(dir.join("comm"))
            .ok()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty()),
        pm2_name: std::fs::read(dir.join("environ"))
            .ok()
            .and_then(|raw| pm2_name_from_environ(&raw)),
    }
}

/// Map socket inodes to pids by walking `/proc/*/fd`. Bounded: at most
/// `max_processes` are inspected, newest pids first, since a runaway
/// machine with tens of thousands of processes should not stall discovery.
pub fn map_inodes_to_pids(
    proc_root: &Path,
    wanted: &[u64],
    max_processes: usize,
) -> HashMap<u64, u32> {
    let mut found = HashMap::new();
    let wanted: std::collections::HashSet<u64> = wanted.iter().copied().collect();

    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return found;
    };
    let mut pids: Vec<u32> = entries
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable_by(|a, b| b.cmp(a));

    for pid in pids.into_iter().take(max_processes) {
        let Ok(fds) = std::fs::read_dir(proc_root.join(pid.to_string()).join("fd")) else {
            continue;
        };

        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();

            if let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            {
                if wanted.contains(&inode) {
                    found.entry(inode).or_insert(pid);
                }
            }
        }

        if found.len() == wanted.len() {
            break;
        }
    }

    found
}

/// The full listener picture for the machine.
pub fn discover(proc_root: &Path) -> (Vec<Listener>, HashMap<u32, ProcessInfo>) {
    let users = std::fs::read_to_string("/etc/passwd")
        .map(|t| parse_passwd(&t))
        .unwrap_or_default();
    let mut sockets = std::fs::read_to_string(proc_root.join("net/tcp"))
        .map(|t| parse_proc_net_tcp(&t, false))
        .unwrap_or_default();
    sockets.extend(
        std::fs::read_to_string(proc_root.join("net/tcp6"))
            .map(|t| parse_proc_net_tcp(&t, true))
            .unwrap_or_default(),
    );

    let inodes: Vec<u64> = sockets.iter().map(|s| s.inode).collect();
    let owners = map_inodes_to_pids(proc_root, &inodes, 20_000);
    let mut processes: HashMap<u32, ProcessInfo> = HashMap::new();

    for pid in owners.values() {
        processes
            .entry(*pid)
            .or_insert_with(|| read_process(proc_root, *pid, &users));
    }

    // Ancestors too: who started a listener (pm2, screen, cron) is only
    // visible up the parent chain, and parents rarely listen themselves.
    let owners_only: Vec<u32> = processes.keys().copied().collect();
    for pid in owners_only {
        let mut cursor = processes.get(&pid).and_then(|p| p.ppid);
        let mut hops = 0;

        while let Some(ppid) = cursor {
            if ppid <= 1 || hops > 8 {
                break;
            }

            let parent = processes
                .entry(ppid)
                .or_insert_with(|| read_process(proc_root, ppid, &users));
            cursor = parent.ppid;
            hops += 1;
        }
    }

    let listeners = sockets
        .into_iter()
        .map(|socket| {
            let pid = owners.get(&socket.inode).copied();
            let process = pid.map(|p| {
                processes
                    .entry(p)
                    .or_insert_with(|| read_process(proc_root, p, &users))
                    .clone()
            });

            Listener {
                proto: if socket.v6 {
                    "tcp6".into()
                } else {
                    "tcp".into()
                },
                address: socket.address,
                port: socket.port,
                pid,
                exe: process.as_ref().and_then(|p| p.exe.clone()),
                user: process
                    .as_ref()
                    .and_then(|p| p.user.clone())
                    .or_else(|| users.get(&socket.uid).cloned()),
                cmdline: process
                    .as_ref()
                    .map(|p| p.cmdline_text())
                    .filter(|c| !c.is_empty()),
            }
        })
        .collect();

    (dedupe(listeners), processes)
}

/// A dual-stack listener shows up once for v4 and once for v6 on the
/// same port and pid; keep one row.
fn dedupe(listeners: Vec<Listener>) -> Vec<Listener> {
    let mut seen = std::collections::HashSet::new();

    listeners
        .into_iter()
        .filter(|l| seen.insert((l.port, l.pid, l.address.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 67890 1 0000000000000000 100 0 0 10 0\n   2: 0100007F:E4B2 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 20 4 30 10 -1\n";

    #[test]
    fn parses_listening_tcp4_sockets_only() {
        let sockets = parse_proc_net_tcp(TCP, false);

        assert_eq!(sockets.len(), 2);
        assert_eq!(
            sockets[0],
            Socket {
                address: "0.0.0.0".into(),
                port: 80,
                inode: 12345,
                uid: 0,
                v6: false
            }
        );
        assert_eq!(sockets[1].address, "127.0.0.1");
        assert_eq!(sockets[1].port, 5432);
        assert_eq!(sockets[1].uid, 999);
    }

    #[test]
    fn decodes_v6_and_mapped_v4_addresses() {
        let text = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1 0000000000000000 100 0 0 10 0\n   1: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 556 1 0000000000000000 100 0 0 10 0\n";
        let sockets = parse_proc_net_tcp(text, true);

        assert_eq!(sockets[0].address, "::");
        assert_eq!(sockets[0].port, 443);
        assert_eq!(sockets[1].address, "127.0.0.1");
        assert_eq!(sockets[1].port, 8080);
    }

    #[test]
    fn splits_cmdline_on_nul() {
        assert_eq!(
            parse_cmdline(b"/usr/bin/node\0server.js\0--port=3000\0"),
            vec!["/usr/bin/node", "server.js", "--port=3000"]
        );
    }

    #[test]
    fn reads_uid_and_ppid_from_status() {
        assert_eq!(
            parse_status("Name:\tnginx\nPPid:\t1\nUid:\t33\t33\t33\t33\n"),
            (Some(33), Some(1))
        );
    }

    #[test]
    fn maps_passwd_uids_to_names() {
        let users = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n",
        );

        assert_eq!(users[&33], "www-data");
    }

    #[test]
    fn maps_socket_inodes_to_pids_from_a_fake_proc() {
        let dir = tempfile::tempdir().unwrap();
        let fd_dir = dir.path().join("4242").join("fd");
        std::fs::create_dir_all(&fd_dir).unwrap();
        std::os::unix::fs::symlink("socket:[12345]", fd_dir.join("3")).unwrap();
        std::os::unix::fs::symlink("/dev/null", fd_dir.join("0")).unwrap();

        let owners = map_inodes_to_pids(dir.path(), &[12345, 99999], 100);

        assert_eq!(owners.get(&12345), Some(&4242));
        assert_eq!(owners.get(&99999), None);
    }

    #[test]
    fn the_program_name_prefers_the_argument_over_a_multicall_binary() {
        let redis = ProcessInfo {
            exe: Some("/usr/bin/redis-check-rdb".into()),
            cmdline: vec!["redis-server 127.0.0.1:6379".into()],
            kernel_comm: Some("redis-server".into()),
            ..Default::default()
        };
        assert_eq!(redis.comm(), Some("redis-server"));

        let nginx = ProcessInfo {
            exe: Some("/usr/sbin/nginx".into()),
            cmdline: vec!["nginx: master process nginx".into()],
            kernel_comm: Some("nginx".into()),
            ..Default::default()
        };
        assert_eq!(nginx.comm(), Some("nginx"));

        let titled = ProcessInfo {
            exe: Some("/usr/bin/node".into()),
            cmdline: vec!["node /srv/app/server.js".into()],
            kernel_comm: Some("node /srv/app/s".into()),
            ..Default::default()
        };
        assert_eq!(titled.comm(), Some("node"));

        let plain = ProcessInfo {
            exe: Some("/usr/lib/postgresql/15/bin/postgres".into()),
            cmdline: vec!["/usr/lib/postgresql/15/bin/postgres".into(), "-D".into()],
            ..Default::default()
        };
        assert_eq!(plain.comm(), Some("postgres"));
    }

    #[test]
    fn only_pm2_s_app_name_is_taken_from_the_environment() {
        assert_eq!(
            pm2_name_from_environ(b"PATH=/bin\0PM2_HOME=/root/.pm2\0name=shop-api\0SECRET=x\0"),
            Some("shop-api".into())
        );
        assert_eq!(pm2_name_from_environ(b"PATH=/bin\0name=shop-api\0"), None);
    }
}
