//! Takes one sample. Keeps the previous CPU, disk, and network counters so
//! each sample carries rates rather than raw counters.

use std::collections::BTreeMap;
use std::path::Path;

use daemon_protocol::{DiskSample, Sample};

use crate::platform::{self, FsUsage};
use crate::procfs::{self, CpuTimes, DiskIo};
use crate::TelemetryError;

#[derive(Default)]
pub struct Collector {
    previous_cpu: Option<CpuTimes>,
    previous_cores: Vec<CpuTimes>,
    previous_disk_io: BTreeMap<String, DiskIo>,
}

impl Collector {
    pub fn new() -> Self {
        Self::default()
    }

    /// One machine-wide sample. The first call establishes the CPU
    /// baseline and reports 0% rather than a made-up number.
    pub fn sample(&mut self, now_ts: i64) -> Result<Sample, TelemetryError> {
        if !platform::is_linux() {
            return Err(TelemetryError::Unsupported);
        }

        let stat = procfs::parse_proc_stat(&platform::read(platform::PROC_STAT)?).ok_or(
            TelemetryError::Parse {
                path: platform::PROC_STAT.into(),
            },
        )?;
        let mem = procfs::parse_meminfo(&platform::read(platform::PROC_MEMINFO)?).ok_or(
            TelemetryError::Parse {
                path: platform::PROC_MEMINFO.into(),
            },
        )?;
        let (load, _, process_count) = procfs::parse_loadavg(&platform::read(
            platform::PROC_LOADAVG,
        )?)
        .ok_or(TelemetryError::Parse {
            path: platform::PROC_LOADAVG.into(),
        })?;
        let net = procfs::parse_net_dev(&platform::read(platform::PROC_NET_DEV)?);
        let mounts = procfs::parse_mounts(&platform::read(platform::PROC_MOUNTS)?);
        let disk_io = platform::read_optional(platform::PROC_DISKSTATS)
            .map(|t| procfs::parse_diskstats(&t))
            .unwrap_or_default();

        let cpu_percent = self
            .previous_cpu
            .map(|prev| stat.aggregate.percent_since(&prev))
            .unwrap_or(0.0);
        let cpu_per_core = stat
            .per_core
            .iter()
            .enumerate()
            .map(|(i, core)| {
                self.previous_cores
                    .get(i)
                    .map(|prev| core.percent_since(prev))
                    .unwrap_or(0.0)
            })
            .collect();

        let disks = mounts
            .iter()
            .filter_map(|m| {
                let usage: FsUsage = platform::statvfs(Path::new(&m.mount_point))?;
                let device = procfs::device_short_name(&m.device).to_string();
                let io_now = disk_io.get(&device).copied().unwrap_or_default();
                let io_prev = self
                    .previous_disk_io
                    .get(&device)
                    .copied()
                    .unwrap_or(io_now);

                Some(DiskSample {
                    mount: m.mount_point.clone(),
                    used_bytes: usage.used_bytes(),
                    free_bytes: usage.available_bytes,
                    inodes_used: usage.inodes_used(),
                    inodes_free: usage.inodes_free,
                    read_bytes: io_now.read_bytes.saturating_sub(io_prev.read_bytes),
                    write_bytes: io_now.write_bytes.saturating_sub(io_prev.write_bytes),
                })
            })
            .collect();

        self.previous_cpu = Some(stat.aggregate);
        self.previous_cores = stat.per_core;
        self.previous_disk_io = disk_io;

        Ok(Sample {
            ts: now_ts,
            service: None,
            cpu_percent,
            cpu_per_core,
            load,
            mem_total: mem.total,
            mem_used: mem.used(),
            mem_available: mem.available,
            mem_cached: mem.cached,
            swap_total: mem.swap_total,
            swap_used: mem.swap_used(),
            disks,
            net_rx_bytes: net.rx_bytes,
            net_tx_bytes: net.tx_bytes,
            net_rx_errors: net.rx_errors,
            net_tx_errors: net.tx_errors,
            process_count,
        })
    }

    /// Memory pressure (PSI `some avg10`), when the kernel exposes it.
    pub fn memory_pressure(&self) -> Option<f32> {
        platform::read_optional(platform::PROC_PRESSURE_MEMORY)
            .and_then(|t| procfs::parse_psi_some_avg10(&t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_linux_the_collector_says_so_instead_of_inventing_numbers() {
        let mut collector = Collector::new();
        let result = collector.sample(0);

        if platform::is_linux() {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(TelemetryError::Unsupported)));
        }
    }
}
