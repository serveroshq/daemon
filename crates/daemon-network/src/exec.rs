//! How networking touches the machine: running `ip`, `wg`, the firewall
//! tools and the package manager, and asking whether a tool is installed.
//! Behind a trait so the tests can script the answers.

use std::future::Future;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

/// Enough for any listing these tools print for one machine; error
/// messages are cut shorter where they become a job's output.
const KEEP_LINES: usize = 20_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecOutput {
    pub ok: bool,
    /// stdout then stderr.
    pub lines: Vec<String>,
}

pub trait Exec: Send + Sync {
    fn run(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> impl Future<Output = ExecOutput> + Send;

    /// Whether any of these files exists.
    fn has(&self, paths: &[&str]) -> bool;
}

/// The real machine.
pub struct SystemExec;

impl Exec for SystemExec {
    async fn run(&self, program: &str, args: &[String], timeout: Duration) -> ExecOutput {
        let child = tokio::process::Command::new(program)
            .args(args)
            .env("DEBIAN_FRONTEND", "noninteractive")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output();

        match tokio::time::timeout(timeout, child).await {
            Ok(Ok(out)) => {
                let mut lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .chain(String::from_utf8_lossy(&out.stderr).lines())
                    .map(str::to_string)
                    .collect();
                if lines.len() > KEEP_LINES {
                    lines.drain(..lines.len() - KEEP_LINES);
                }
                ExecOutput {
                    ok: out.status.success(),
                    lines,
                }
            }
            Ok(Err(e)) => ExecOutput {
                ok: false,
                lines: vec![format!("couldn't run {program}: {e}")],
            },
            Err(_) => ExecOutput {
                ok: false,
                lines: vec![format!("{program} gave no answer within {timeout:?}")],
            },
        }
    }

    fn has(&self, paths: &[&str]) -> bool {
        paths.iter().any(|p| Path::new(p).exists())
    }
}

#[cfg(test)]
pub mod fake {
    use std::sync::Mutex;

    use super::*;

    /// Records every command as one line and answers from a script: the
    /// first rule whose prefix matches wins; anything else succeeds with no
    /// output.
    #[derive(Default)]
    pub struct Scripted {
        pub calls: Mutex<Vec<String>>,
        pub rules: Mutex<Vec<(String, ExecOutput)>>,
        pub present: Mutex<Vec<String>>,
    }

    impl Scripted {
        pub fn with_tools(tools: &[&str]) -> Self {
            let fake = Self::default();
            fake.present
                .lock()
                .unwrap()
                .extend(tools.iter().map(|t| t.to_string()));
            fake
        }

        pub fn answer(&self, prefix: &str, ok: bool, lines: &[&str]) {
            self.rules.lock().unwrap().push((
                prefix.to_string(),
                ExecOutput {
                    ok,
                    lines: lines.iter().map(|l| l.to_string()).collect(),
                },
            ));
        }

        pub fn take(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
    }

    impl Exec for Scripted {
        async fn run(&self, program: &str, args: &[String], _timeout: Duration) -> ExecOutput {
            let line = std::iter::once(program.to_string())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>()
                .join(" ");
            self.calls.lock().unwrap().push(line.clone());
            self.rules
                .lock()
                .unwrap()
                .iter()
                .find(|(prefix, _)| line.starts_with(prefix.as_str()))
                .map(|(_, out)| out.clone())
                .unwrap_or(ExecOutput {
                    ok: true,
                    lines: vec![],
                })
        }

        fn has(&self, paths: &[&str]) -> bool {
            let present = self.present.lock().unwrap();
            paths.iter().any(|p| present.iter().any(|t| t == p))
        }
    }
}
