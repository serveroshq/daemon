//! A backup bigger than the daemon's memory ceiling must not cost the
//! daemon its own size in memory. It used to: the archive was read whole
//! to checksum it, the daemon went over 120 MB, restarted itself (exit
//! 75) and systemd killed the backup with it.
//!
//! Its own test binary, so the peak memory it reads is only this test's.
#![cfg(target_os = "linux")]

/// Matches daemon_supervisor::RSS_RESTART_BYTES.
const CEILING: u64 = 120 * 1024 * 1024;

fn peak_rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        .unwrap()
        * 1024
}

#[tokio::test]
async fn hashing_a_backup_over_the_ceiling_stays_under_it() {
    let file = tempfile::NamedTempFile::new().unwrap();
    // Sparse: costs no disk, but reads back as 3x the ceiling of zeros.
    file.as_file().set_len(CEILING * 3).unwrap();

    let (bytes, _) = daemon_backup::sha256_file(file.path()).await.unwrap();

    assert_eq!(bytes, CEILING * 3);
    assert!(
        peak_rss() < CEILING / 2,
        "peak memory {} MB while hashing",
        peak_rss() / (1024 * 1024)
    );
}
