use std::cmp::Ordering;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Files bigger than this aren't parsed: a lockfile this size is unusual,
/// and reading one shouldn't take the daemon's memory with it.
pub const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// A file's text, or None when it's missing, too big or unreadable.
pub fn read(path: &Path) -> Option<String> {
    read_limited(path, MAX_FILE_BYTES)
}

pub fn read_limited(path: &Path, max: u64) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > max {
        return None;
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    std::fs::File::open(path)
        .ok()?
        .take(max)
        .read_to_end(&mut bytes)
        .ok()?;

    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The first `max` bytes of a file, for headers (a WordPress plugin's).
pub fn read_head(path: &Path, max: u64) -> Option<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(max)
        .read_to_end(&mut bytes)
        .ok()?;

    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// A command's stdout (and stderr, which some print versions to), or None
/// if it's missing, fails or takes longer than `timeout`.
pub fn run(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C")
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let mut stderr = child.stderr.take()?;
    let out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stdout).take(16 * 1024 * 1024).read_to_end(&mut buf);
        buf
    });
    let err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stderr).take(64 * 1024).read_to_end(&mut buf);
        buf
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let mut text = out.join().ok()?;
    text.extend(err.join().ok()?);

    status
        .success()
        .then(|| String::from_utf8_lossy(&text).into_owned())
}

/// Version strings compared the way people read them: runs of digits as
/// numbers, everything else as text ("6.8.0-47" after "6.8.0-45", "10"
/// after "9").
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let parts = |s: &str| {
        let mut out: Vec<(bool, String)> = Vec::new();
        // A separator ends a run: "1.02" is 1 then 02, not 102.
        let mut joined = false;
        for c in s.chars() {
            if !c.is_ascii_alphanumeric() {
                joined = false;
                continue;
            }
            let digit = c.is_ascii_digit();
            match out.last_mut() {
                Some((d, run)) if joined && *d == digit => run.push(c),
                _ => out.push((digit, c.to_string())),
            }
            joined = true;
        }
        out
    };
    let (a, b) = (parts(a), parts(b));
    for (x, y) in a.iter().zip(b.iter()) {
        let order = match (x.0, y.0) {
            (true, true) => {
                let (x, y) = (x.1.trim_start_matches('0'), y.1.trim_start_matches('0'));
                x.len().cmp(&y.len()).then_with(|| x.cmp(y))
            }
            _ => x.1.cmp(&y.1),
        };
        if order != Ordering::Equal {
            return order;
        }
    }

    a.len().cmp(&b.len())
}

/// Cut to `max` characters, on a character boundary.
pub fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions_numerically() {
        assert_eq!(
            compare_versions("6.8.0-47-generic", "6.8.0-45-generic"),
            Ordering::Greater
        );
        assert_eq!(compare_versions("5.15.0-9", "5.15.0-10"), Ordering::Less);
        assert_eq!(compare_versions("1.2", "1.2.0"), Ordering::Less);
        assert_eq!(compare_versions("1.02", "1.2"), Ordering::Equal);
    }

    #[test]
    fn clips_on_characters() {
        assert_eq!(clip("héllo world", 5), "héll…");
        assert_eq!(clip("short", 10), "short");
    }
}
