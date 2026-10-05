use std::path::Path;

use crate::TelemetryError;

pub const PROC_STAT: &str = "/proc/stat";
pub const PROC_MEMINFO: &str = "/proc/meminfo";
pub const PROC_LOADAVG: &str = "/proc/loadavg";
pub const PROC_NET_DEV: &str = "/proc/net/dev";
pub const PROC_MOUNTS: &str = "/proc/mounts";
pub const PROC_DISKSTATS: &str = "/proc/diskstats";
pub const PROC_PRESSURE_MEMORY: &str = "/proc/pressure/memory";
pub const PROC_UPTIME: &str = "/proc/uptime";
pub const PROC_CPUINFO: &str = "/proc/cpuinfo";
pub const PROC_VERSION: &str = "/proc/version";
pub const OS_RELEASE: &str = "/etc/os-release";
pub const HOSTNAME: &str = "/etc/hostname";
pub const TIMEZONE: &str = "/etc/timezone";
pub const LOCALTIME: &str = "/etc/localtime";
pub const KMSG_OOM_MARKER: &str = "Out of memory: Killed process";

pub fn read(path: &str) -> Result<String, TelemetryError> {
    std::fs::read_to_string(path).map_err(|source| TelemetryError::Read {
        path: path.into(),
        source,
    })
}

pub fn read_optional(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

#[cfg(unix)]
pub fn statvfs(mount: &Path) -> Option<FsUsage> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(mount.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };

    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }

    let block = stat.f_frsize as u64;

    Some(FsUsage {
        total_bytes: stat.f_blocks as u64 * block,
        free_bytes: stat.f_bfree as u64 * block,
        available_bytes: stat.f_bavail as u64 * block,
        inodes_total: stat.f_files as u64,
        inodes_free: stat.f_ffree as u64,
    })
}

#[cfg(not(unix))]
pub fn statvfs(_mount: &Path) -> Option<FsUsage> {
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsUsage {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub inodes_total: u64,
    pub inodes_free: u64,
}

impl FsUsage {
    pub fn used_bytes(&self) -> u64 {
        self.total_bytes.saturating_sub(self.free_bytes)
    }

    pub fn inodes_used(&self) -> u64 {
        self.inodes_total.saturating_sub(self.inodes_free)
    }
}

pub fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

#[cfg(unix)]
pub fn clock_ticks() -> u64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 {
        ticks as u64
    } else {
        100
    }
}

#[cfg(not(unix))]
pub fn clock_ticks() -> u64 {
    100
}

#[cfg(unix)]
pub fn page_size() -> u64 {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as u64
    } else {
        4096
    }
}

#[cfg(not(unix))]
pub fn page_size() -> u64 {
    4096
}
