//! Parsers for the handful of procfs and sysfs files telemetry reads.
//! Each takes the file's text and returns numbers; none does IO.

use std::collections::BTreeMap;

/// CPU time counters from `/proc/stat`, in jiffies. The first entry is the
/// aggregate; the rest are per core in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTimes {
    pub fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    pub fn busy(&self) -> u64 {
        self.total() - self.idle - self.iowait
    }

    /// Busy percentage between two readings.
    pub fn percent_since(&self, earlier: &CpuTimes) -> f32 {
        let total = self.total().saturating_sub(earlier.total());

        if total == 0 {
            return 0.0;
        }

        (self.busy().saturating_sub(earlier.busy()) as f32 / total as f32 * 100.0).clamp(0.0, 100.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcStat {
    pub aggregate: CpuTimes,
    pub per_core: Vec<CpuTimes>,
    pub processes_forked: u64,
    pub procs_running: u32,
    pub boot_ts: i64,
}

pub fn parse_proc_stat(text: &str) -> Option<ProcStat> {
    let mut stat = ProcStat::default();
    let mut seen_aggregate = false;

    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(label) = parts.next() else { continue };

        if label.starts_with("cpu") {
            let nums: Vec<u64> = parts.filter_map(|p| p.parse().ok()).collect();

            if nums.len() < 4 {
                continue;
            }

            let times = CpuTimes {
                user: nums[0],
                nice: nums[1],
                system: nums[2],
                idle: nums[3],
                iowait: *nums.get(4).unwrap_or(&0),
                irq: *nums.get(5).unwrap_or(&0),
                softirq: *nums.get(6).unwrap_or(&0),
                steal: *nums.get(7).unwrap_or(&0),
            };

            if label == "cpu" {
                stat.aggregate = times;
                seen_aggregate = true;
            } else {
                stat.per_core.push(times);
            }
        } else if label == "processes" {
            stat.processes_forked = parts.next()?.parse().ok()?;
        } else if label == "procs_running" {
            stat.procs_running = parts.next()?.parse().ok()?;
        } else if label == "btime" {
            stat.boot_ts = parts.next()?.parse().ok()?;
        }
    }

    seen_aggregate.then_some(stat)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemInfo {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

impl MemInfo {
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.available)
    }

    pub fn swap_used(&self) -> u64 {
        self.swap_total.saturating_sub(self.swap_free)
    }
}

/// `/proc/meminfo`, values converted from kB to bytes.
pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut values: BTreeMap<&str, u64> = BTreeMap::new();

    for line in text.lines() {
        let (key, rest) = line.split_once(':')?;
        let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
        values.insert(key.trim(), kb * 1024);
    }

    let get = |k: &str| values.get(k).copied().unwrap_or(0);
    let total = *values.get("MemTotal")?;
    let free = get("MemFree");
    let buffers = get("Buffers");
    let cached = get("Cached") + get("SReclaimable");

    Some(MemInfo {
        total,
        free,
        // Older kernels lack MemAvailable; approximate it the way `free` does.
        available: values
            .get("MemAvailable")
            .copied()
            .unwrap_or(free + buffers + cached),
        buffers,
        cached,
        swap_total: get("SwapTotal"),
        swap_free: get("SwapFree"),
    })
}

/// `/proc/loadavg`: the three averages and the running/total process counts.
pub fn parse_loadavg(text: &str) -> Option<([f32; 3], u32, u32)> {
    let mut parts = text.split_whitespace();
    let load = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    let (running, total) = parts.next()?.split_once('/')?;

    Some((load, running.parse().ok()?, total.parse().ok()?))
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// `/proc/net/dev` summed over every interface but loopback.
pub fn parse_net_dev(text: &str) -> NetCounters {
    let mut totals = NetCounters::default();

    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };

        if name.trim() == "lo" {
            continue;
        }

        let nums: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|p| p.parse().ok())
            .collect();

        if nums.len() < 12 {
            continue;
        }

        totals.rx_bytes += nums[0];
        totals.rx_errors += nums[2];
        totals.tx_bytes += nums[8];
        totals.tx_errors += nums[10];
    }

    totals
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
}

/// Real filesystems from `/proc/mounts`; pseudo and overlay mounts are
/// skipped because their usage says nothing about the disk.
pub fn parse_mounts(text: &str) -> Vec<Mount> {
    const SKIP_TYPES: &[&str] = &[
        "proc",
        "sysfs",
        "devtmpfs",
        "devpts",
        "tmpfs",
        "cgroup",
        "cgroup2",
        "pstore",
        "bpf",
        "securityfs",
        "debugfs",
        "tracefs",
        "configfs",
        "fusectl",
        "mqueue",
        "hugetlbfs",
        "autofs",
        "overlay",
        "squashfs",
        "nsfs",
        "binfmt_misc",
        "rpc_pipefs",
        "efivarfs",
        "ramfs",
        "fuse.lxcfs",
        "fuse.portal",
        "fuse.gvfsd-fuse",
    ];

    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let device = parts.next()?;
            let mount_point = parts.next()?;
            let fs_type = parts.next()?;

            if SKIP_TYPES.contains(&fs_type)
                || mount_point.starts_with("/snap/")
                || mount_point.starts_with("/var/lib/docker/")
            {
                return None;
            }

            Some(Mount {
                device: device.to_string(),
                mount_point: mount_point.replace("\\040", " "),
                fs_type: fs_type.to_string(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiskIo {
    pub read_bytes: u64,
    pub write_bytes: u64,
}

/// `/proc/diskstats` sectors read/written per device name, in bytes
/// (sectors are 512 bytes in this file regardless of the disk).
pub fn parse_diskstats(text: &str) -> BTreeMap<String, DiskIo> {
    text.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 10 {
                return None;
            }

            let read_sectors: u64 = parts[5].parse().ok()?;
            let write_sectors: u64 = parts[9].parse().ok()?;

            Some((
                parts[2].to_string(),
                DiskIo {
                    read_bytes: read_sectors * 512,
                    write_bytes: write_sectors * 512,
                },
            ))
        })
        .collect()
}

/// The device name `/proc/diskstats` uses for a mount's device path.
pub fn device_short_name(device: &str) -> &str {
    device.rsplit('/').next().unwrap_or(device)
}

/// `/proc/pressure/memory` "some avg10=1.23 ..." → avg10 for `some`.
pub fn parse_psi_some_avg10(text: &str) -> Option<f32> {
    text.lines()
        .find(|l| l.starts_with("some"))?
        .split_whitespace()
        .find_map(|kv| kv.strip_prefix("avg10=")?.parse().ok())
}

/// `/proc/PID/stat` fields we care about: state, ppid, utime+stime, rss pages, start time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidStat {
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub cpu_jiffies: u64,
    pub rss_pages: u64,
    pub start_jiffies: u64,
}

pub fn parse_pid_stat(text: &str) -> Option<PidStat> {
    // comm can contain spaces and parens; it is bounded by the last ')'.
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let comm = text[open + 1..close].to_string();
    let rest: Vec<&str> = text[close + 1..].split_whitespace().collect();

    Some(PidStat {
        comm,
        state: rest.first()?.chars().next()?,
        ppid: rest.get(1)?.parse().ok()?,
        cpu_jiffies: rest.get(11)?.parse::<u64>().ok()? + rest.get(12)?.parse::<u64>().ok()?,
        rss_pages: rest.get(21)?.parse().ok()?,
        start_jiffies: rest.get(19)?.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str = "cpu  10 2 5 100 3 0 1 0 0 0\ncpu0 5 1 2 50 1 0 0 0 0 0\ncpu1 5 1 3 50 2 0 1 0 0 0\nintr 1 2 3\nctxt 99\nbtime 1700000000\nprocesses 4242\nprocs_running 3\nprocs_blocked 0\n";

    #[test]
    fn parses_proc_stat_with_per_core_lines() {
        let stat = parse_proc_stat(STAT).unwrap();

        assert_eq!(stat.per_core.len(), 2);
        assert_eq!(stat.aggregate.idle, 100);
        assert_eq!(stat.boot_ts, 1_700_000_000);
        assert_eq!(stat.procs_running, 3);
    }

    #[test]
    fn cpu_percent_is_the_busy_share_of_the_delta() {
        let earlier = CpuTimes {
            user: 0,
            idle: 100,
            ..Default::default()
        };
        let later = CpuTimes {
            user: 50,
            idle: 150,
            ..Default::default()
        };

        assert_eq!(later.percent_since(&earlier), 50.0);
        assert_eq!(earlier.percent_since(&earlier), 0.0);
    }

    #[test]
    fn parses_meminfo_in_bytes() {
        let text = "MemTotal:       16000000 kB\nMemFree:         2000000 kB\nMemAvailable:    9000000 kB\nBuffers:          500000 kB\nCached:          4000000 kB\nSwapTotal:       1000000 kB\nSwapFree:         750000 kB\n";
        let mem = parse_meminfo(text).unwrap();

        assert_eq!(mem.total, 16_000_000 * 1024);
        assert_eq!(mem.used(), (16_000_000 - 9_000_000) * 1024);
        assert_eq!(mem.swap_used(), 250_000 * 1024);
    }

    #[test]
    fn parses_loadavg() {
        let (load, running, total) = parse_loadavg("0.52 0.41 0.30 2/412 91234\n").unwrap();

        assert_eq!(load, [0.52, 0.41, 0.30]);
        assert_eq!((running, total), (2, 412));
    }

    #[test]
    fn sums_net_dev_without_loopback() {
        let text = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n  eth0: 5000 50 1 0 0 0 0 0 7000 70 2 0 0 0 0 0\n";
        let net = parse_net_dev(text);

        assert_eq!(
            (net.rx_bytes, net.tx_bytes, net.rx_errors, net.tx_errors),
            (5000, 7000, 1, 2)
        );
    }

    #[test]
    fn mounts_skip_pseudo_filesystems() {
        let text = "proc /proc proc rw 0 0\n/dev/vda1 / ext4 rw,relatime 0 0\ntmpfs /run tmpfs rw 0 0\n/dev/vdb1 /mnt/data\\040disk xfs rw 0 0\noverlay /var/lib/docker/overlay2/abc/merged overlay rw 0 0\n";
        let mounts = parse_mounts(text);

        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[1].mount_point, "/mnt/data disk");
    }

    #[test]
    fn diskstats_convert_sectors_to_bytes() {
        let text = " 253       0 vda 100 0 2000 0 50 0 4000 0 0 0 0\n";
        let io = parse_diskstats(text);

        assert_eq!(
            io["vda"],
            DiskIo {
                read_bytes: 2000 * 512,
                write_bytes: 4000 * 512
            }
        );
        assert_eq!(device_short_name("/dev/vda"), "vda");
    }

    #[test]
    fn pid_stat_handles_parens_in_comm() {
        let text = "1234 (my (odd) app) S 1 1234 1234 0 -1 4194560 100 0 0 0 30 20 0 0 20 0 1 0 5000 1000000 300 18446744073709551615";
        let stat = parse_pid_stat(text).unwrap();

        assert_eq!(stat.comm, "my (odd) app");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.cpu_jiffies, 50);
        assert_eq!(stat.rss_pages, 300);
        assert_eq!(stat.start_jiffies, 5000);
    }

    #[test]
    fn psi_reads_the_some_line() {
        assert_eq!(parse_psi_some_avg10("some avg10=2.50 avg60=1.00 avg300=0.50 total=1\nfull avg10=0.10 avg60=0.00 avg300=0.00 total=0\n"), Some(2.5));
    }
}
