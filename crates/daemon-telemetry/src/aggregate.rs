//! Ten-second samples become one-minute points for the wire and
//! five-minute points for anything older than a day.

use daemon_protocol::{DiskSample, Sample};

/// Fold `samples` (any order) into one point stamped at the bucket start.
/// Gauges are averaged, counters take the last value, disk usage takes
/// the last value and IO sums.
pub fn fold(samples: &[Sample], bucket_ts: i64) -> Option<Sample> {
    let mut sorted: Vec<&Sample> = samples.iter().collect();
    sorted.sort_by_key(|s| s.ts);
    let last = *sorted.last()?;
    let n = sorted.len() as f32;

    let mut cpu_per_core = vec![0.0f32; last.cpu_per_core.len()];

    for s in &sorted {
        for (i, v) in s.cpu_per_core.iter().enumerate() {
            if let Some(slot) = cpu_per_core.get_mut(i) {
                *slot += v / n;
            }
        }
    }

    let disks = last
        .disks
        .iter()
        .map(|d| DiskSample {
            mount: d.mount.clone(),
            used_bytes: d.used_bytes,
            free_bytes: d.free_bytes,
            inodes_used: d.inodes_used,
            inodes_free: d.inodes_free,
            read_bytes: sorted
                .iter()
                .flat_map(|s| s.disks.iter().filter(|x| x.mount == d.mount))
                .map(|x| x.read_bytes)
                .sum(),
            write_bytes: sorted
                .iter()
                .flat_map(|s| s.disks.iter().filter(|x| x.mount == d.mount))
                .map(|x| x.write_bytes)
                .sum(),
        })
        .collect();

    Some(Sample {
        ts: bucket_ts,
        service: last.service.clone(),
        cpu_percent: sorted.iter().map(|s| s.cpu_percent).sum::<f32>() / n,
        cpu_per_core,
        load: [
            sorted.iter().map(|s| s.load[0]).sum::<f32>() / n,
            sorted.iter().map(|s| s.load[1]).sum::<f32>() / n,
            sorted.iter().map(|s| s.load[2]).sum::<f32>() / n,
        ],
        mem_total: last.mem_total,
        mem_used: (sorted.iter().map(|s| s.mem_used as f64).sum::<f64>() / n as f64) as u64,
        mem_available: (sorted.iter().map(|s| s.mem_available as f64).sum::<f64>() / n as f64)
            as u64,
        mem_cached: last.mem_cached,
        swap_total: last.swap_total,
        swap_used: last.swap_used,
        disks,
        net_rx_bytes: last.net_rx_bytes,
        net_tx_bytes: last.net_tx_bytes,
        net_rx_errors: last.net_rx_errors,
        net_tx_errors: last.net_tx_errors,
        process_count: last.process_count,
        started_at: last.started_at,
        restarts: last.restarts,
    })
}

/// Group samples into `bucket_secs` buckets and fold each.
pub fn downsample(samples: &[Sample], bucket_secs: i64) -> Vec<Sample> {
    let mut buckets: std::collections::BTreeMap<(i64, Option<String>), Vec<Sample>> =
        std::collections::BTreeMap::new();

    for s in samples {
        buckets
            .entry((s.ts - s.ts.rem_euclid(bucket_secs), s.service.clone()))
            .or_default()
            .push(s.clone());
    }

    buckets
        .into_iter()
        .filter_map(|((ts, _), group)| fold(&group, ts))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ts: i64, cpu: f32, used: u64) -> Sample {
        Sample {
            ts,
            service: None,
            cpu_percent: cpu,
            cpu_per_core: vec![cpu],
            load: [1.0, 1.0, 1.0],
            mem_total: 100,
            mem_used: used,
            mem_available: 100 - used,
            mem_cached: 0,
            swap_total: 0,
            swap_used: 0,
            disks: vec![DiskSample {
                mount: "/".into(),
                used_bytes: used,
                free_bytes: 1,
                inodes_used: 1,
                inodes_free: 1,
                read_bytes: 10,
                write_bytes: 5,
            }],
            net_rx_bytes: ts as u64,
            net_tx_bytes: 0,
            net_rx_errors: 0,
            net_tx_errors: 0,
            process_count: 1,
            started_at: None,
            restarts: None,
        }
    }

    #[test]
    fn folds_gauges_by_average_and_counters_by_last() {
        let point = fold(
            &[
                sample(10, 20.0, 40),
                sample(0, 40.0, 60),
                sample(20, 60.0, 80),
            ],
            0,
        )
        .unwrap();

        assert_eq!(point.ts, 0);
        assert_eq!(point.cpu_percent, 40.0);
        assert_eq!(point.cpu_per_core, vec![40.0]);
        assert_eq!(point.mem_used, 60);
        assert_eq!(point.net_rx_bytes, 20);
        assert_eq!(point.disks[0].read_bytes, 30);
        assert_eq!(point.disks[0].used_bytes, 80);
    }

    #[test]
    fn downsampling_buckets_by_time() {
        let points = downsample(
            &[sample(0, 1.0, 1), sample(30, 3.0, 1), sample(60, 5.0, 1)],
            60,
        );

        assert_eq!(points.len(), 2);
        assert_eq!(points[0].cpu_percent, 2.0);
        assert_eq!(points[1].ts, 60);
    }
}
