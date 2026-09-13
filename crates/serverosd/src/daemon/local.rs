//! The local control socket: root-only, answers `status` for the CLI.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::warn;

use super::app::App;

pub fn serve(app: Arc<App>) {
    let path = app.paths.control_socket();
    let _ = std::fs::remove_file(&path);

    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, path = %path.display(), "local control socket unavailable; `serverosd status` will not work");
            return;
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let app = Arc::clone(&app);

            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut line = String::new();
                let _ = BufReader::new(read).read_line(&mut line).await;

                let body = match line.trim() {
                    "status" => status(&app),
                    other => serde_json::json!({"error": format!("unknown request {other:?}")})
                        .to_string(),
                };

                let _ = write.write_all(body.as_bytes()).await;
                let _ = write.shutdown().await;
            });
        }
    });
}

fn status(app: &App) -> String {
    let status = app.status.read().unwrap().clone();
    let config = app.config.read().unwrap();

    serde_json::json!({
        "version": app.build.version,
        "commit": app.build.commit,
        "machine_id": config.machine.id,
        "panel": config.panel.host,
        "connected": status.connected,
        "protocol_major": status.protocol_major,
        "reconnect_attempt": status.reconnect_attempt,
        "mode": format!("{:?}", status.mode).to_lowercase(),
        "uptime_secs": app.uptime_secs(),
        "running_jobs": app.running_jobs(),
        "outbox": app.state.outbox_len().unwrap_or(0),
        "managed_services": daemon_services::Registry::new(&app.state).all().map(|m| m.len()).unwrap_or(0),
        "terminal_sessions": app.sessions.count(),
        "rss_bytes": daemon_supervisor::own_rss().unwrap_or(0),
        "on_trial": app.on_trial.as_ref().map(|(from, to)| format!("{from} → {to}")),
        "workers": app.supervisor.worker_health().iter().map(|(k, v)| (k.to_string(), format!("{v:?}").to_lowercase())).collect::<std::collections::BTreeMap<_, _>>(),
    })
    .to_string()
}
