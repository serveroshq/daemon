//! The daemon's own log: `daemon.log`, redacted at write time, plus
//! stderr when running in a terminal.

use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use daemon_core::redact::redact;
use tracing_subscriber::EnvFilter;

/// A writer that scrubs each line before it reaches the file, so a
/// secret that slips into a log call is caught once.
struct RedactingFile {
    file: Mutex<std::fs::File>,
    partial: Mutex<Vec<u8>>,
}

impl Write for &RedactingFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut partial = self.partial.lock().unwrap_or_else(|p| p.into_inner());
        partial.extend_from_slice(buf);

        while let Some(pos) = partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = partial.drain(..=pos).collect();
            let clean = redact(&String::from_utf8_lossy(&line));
            self.file
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .write_all(clean.as_bytes())?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.lock().unwrap_or_else(|p| p.into_inner()).flush()
    }
}

static LOG_FILE: std::sync::OnceLock<RedactingFile> = std::sync::OnceLock::new();

pub fn init(log_path: &Path, also_stderr: bool) -> anyhow::Result<()> {
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    let sink = LOG_FILE.get_or_init(|| RedactingFile {
        file: Mutex::new(file),
        partial: Mutex::new(Vec::new()),
    });
    let filter = EnvFilter::try_from_env("SERVEROS_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(false)
        .with_writer(move || sink);

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    if also_stderr {
        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .with_writer(std::io::stderr),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .init();
    }

    Ok(())
}

pub fn is_terminal() -> bool {
    unsafe { libc::isatty(libc::STDERR_FILENO) == 1 }
}
