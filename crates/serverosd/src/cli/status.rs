//! `serverosd status`: ask the running daemon over its local socket.

use std::io::{Read, Write};

use daemon_core::Paths;

pub fn run(paths: Paths, json: bool) -> anyhow::Result<()> {
    let socket = paths.control_socket();
    let mut stream = std::os::unix::net::UnixStream::connect(&socket).map_err(|e| {
        anyhow::anyhow!("the daemon is not running or {} is not reachable ({e}). Try `systemctl status serverosd`.", socket.display())
    })?;

    stream.write_all(b"status\n")?;
    let mut body = String::new();
    stream.read_to_string(&mut body)?;

    if json {
        println!("{body}");
        return Ok(());
    }

    let status: serde_json::Value = serde_json::from_str(&body)?;
    let get = |k: &str| status.get(k).cloned().unwrap_or(serde_json::Value::Null);

    println!("serverosd {}", get("version").as_str().unwrap_or("?"));
    println!(
        "  machine:     {}",
        get("machine_id").as_str().unwrap_or("?")
    );
    println!("  panel:       {}", get("panel").as_str().unwrap_or("?"));
    println!(
        "  connection:  {}",
        if get("connected").as_bool().unwrap_or(false) {
            format!("connected (protocol v{})", get("protocol_major"))
        } else {
            format!("reconnecting (attempt {})", get("reconnect_attempt"))
        }
    );
    println!("  uptime:      {}s", get("uptime_secs"));
    println!(
        "  jobs:        {} running, {} queued for the panel",
        get("running_jobs"),
        get("outbox")
    );
    println!("  managed:     {} services", get("managed_services"));
    println!(
        "  mode:        {}",
        get("mode").as_str().unwrap_or("managed")
    );
    println!(
        "  memory:      {} MB",
        get("rss_bytes").as_u64().unwrap_or(0) / (1024 * 1024)
    );
    println!("  audit log:   {}", paths.actions_log().display());

    Ok(())
}
