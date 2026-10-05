use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::InventoryError;

pub async fn output(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .env("LC_ALL", "C")
        .output();

    match tokio::time::timeout(timeout, child).await {
        Ok(Ok(out)) if out.status.success() => {
            Some(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        _ => None,
    }
}

pub async fn output_stderr_ok(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("LC_ALL", "C")
        .output();

    match tokio::time::timeout(timeout, child).await {
        Ok(Ok(out)) if out.status.success() => {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push('\n');
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            Some(text)
        }
        _ => None,
    }
}

pub async fn output_or_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Option<String>, InventoryError> {
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .env("LC_ALL", "C")
        .output();

    match tokio::time::timeout(timeout, child).await {
        Ok(Ok(out)) if out.status.success() => {
            Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
        }
        Ok(_) => Ok(None),
        Err(_) => Err(InventoryError::Timeout(format!(
            "{program} {}",
            args.join(" ")
        ))),
    }
}

pub fn version_from_banner(banner: &str) -> Option<String> {
    banner
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | '(' | ')' | '/' | '='))
        .map(|t| t.trim_start_matches('v'))
        .find(|t| {
            let mut parts = t.split('.');
            matches!((parts.next(), parts.next()), (Some(a), Some(b)) if a.chars().all(|c| c.is_ascii_digit()) && b.chars().next().is_some_and(|c| c.is_ascii_digit()))
        })
        .map(|t| t.trim_end_matches(|c: char| !c.is_ascii_alphanumeric()).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pulls_versions_out_of_common_banners() {
        assert_eq!(
            version_from_banner("postgres (PostgreSQL) 16.3 (Ubuntu 16.3-1)").as_deref(),
            Some("16.3")
        );
        assert_eq!(
            version_from_banner("nginx version: nginx/1.24.0").as_deref(),
            Some("1.24.0")
        );
        assert_eq!(
            version_from_banner("Redis server v=7.2.4 sha=00000000:0").as_deref(),
            Some("7.2.4")
        );
        assert_eq!(
            version_from_banner("mysqld  Ver 8.0.36-0ubuntu0.22.04.1 for Linux").as_deref(),
            Some("8.0.36-0ubuntu0.22.04.1")
        );
        assert_eq!(version_from_banner("no numbers here"), None);
    }
}
