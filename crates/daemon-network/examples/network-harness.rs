//! Test harness for project networks; not shipped. It does what serverosd
//! does with a `network` job, minus the panel connection: on start it
//! brings every stored network back up (the restore-on-start path), then
//! takes jobs as the panel sends them, one JSON line per connection on a
//! unix socket, runs each through the real job runner and answers with
//! the job's final update as one JSON line.
//!
//!   network-harness serve --state /var/lib/serveros --firewall ufw \
//!       --socket /run/sosnet.sock
//!   echo '{"type":"network",...}' | socat - UNIX-CONNECT:/run/sosnet.sock
//!
//! It also takes `service_exec` jobs, run through the daemon's own `exec`
//! (settings handed to `docker exec -e NAME` by name, their values scrubbed
//! from the log), with `service` naming the container directly since the
//! harness keeps no registry of services.
//!
//! Every job update is also appended to `{state}/harness.log`.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use daemon_core::config::FirewallBackend;
use daemon_jobs::{Failure, Handler, HandlerFuture, JobContext, Runner};
use daemon_network::exec::SystemExec;
use daemon_network::Networks;
use daemon_protocol::{Actor, ActorKind, Command, Job, JobUpdate};
use daemon_state::State;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::mpsc;

struct NetworkHandler {
    networks: Arc<Networks>,
    backend: FirewallBackend,
}

impl Handler for NetworkHandler {
    fn handle(&self, ctx: JobContext) -> HandlerFuture {
        let networks = Arc::clone(&self.networks);
        let backend = self.backend;
        Box::pin(async move {
            match ctx.command.job.clone() {
                // As serverosd's handler: the id is checked first, then applied.
                Job::Network(spec) => {
                    daemon_network::spec::check_network_id(&spec.network)?;
                    networks
                        .apply(&SystemExec, backend, &spec, Some(&ctx.progress))
                        .await
                }
                Job::ServiceExec {
                    service,
                    command,
                    timeout_secs,
                    env,
                } => {
                    daemon_services::exec::exec(&ctx, &service, &command, timeout_secs, &env).await
                }
                _ => Err(Failure::new(
                    "harness",
                    "only network and service_exec jobs here",
                )),
            }
        })
    }

    // As serverosd's handler: an exec job's settings are scrubbed from its log.
    fn known_secrets(&self, job: &Job) -> Vec<String> {
        daemon_services::exec::secrets(job)
    }
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn log(path: &PathBuf, line: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("serve") {
        eprintln!("usage: network-harness serve --state DIR --firewall ufw|nftables|iptables|none --socket PATH");
        std::process::exit(2);
    }
    let state_dir = PathBuf::from(arg(&args, "--state").unwrap_or("/var/lib/serveros".into()));
    let socket = PathBuf::from(arg(&args, "--socket").unwrap_or("/run/sosnet.sock".into()));
    let backend: FirewallBackend = serde_json::from_value(serde_json::Value::String(
        arg(&args, "--firewall").unwrap_or("ufw".into()),
    ))?;
    let log_path = state_dir.join("harness.log");

    std::fs::create_dir_all(&state_dir)?;
    let state = Arc::new(State::open(&state_dir.join("state.db"))?);
    let networks = Arc::new(Networks::new(
        Arc::clone(&state),
        state_dir.join("networks"),
    ));

    let restored = networks
        .restore(
            &SystemExec,
            backend,
            |_| Some(()),
            |(), network, result| {
                let line = match result {
                    Ok(v) => format!("restore {network}: ok {v}"),
                    Err(e) => format!("restore {network}: failed {e}"),
                };
                eprintln!("{line}");
                log(&log_path, &line);
            },
        )
        .await;
    eprintln!("restored {restored} network(s); firewall {backend:?}");

    let (tx, mut updates) = mpsc::channel::<JobUpdate>(256);
    let runner = Runner::new(
        Arc::clone(&state),
        Arc::new(NetworkHandler { networks, backend }),
        tx,
        Duration::from_secs(3600),
    );

    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    eprintln!("listening on {}", socket.display());

    loop {
        let (stream, _) = listener.accept().await?;
        let (read, mut write) = stream.into_split();
        let mut line = String::new();
        BufReader::new(read).read_line(&mut line).await?;

        let job: Job = match serde_json::from_str(&line) {
            Ok(job) => job,
            Err(e) => {
                let answer = serde_json::json!({"state": "rejected", "error": e.to_string()});
                write.write_all(format!("{answer}\n").as_bytes()).await?;
                continue;
            }
        };
        let id = uuid::Uuid::new_v4();
        runner
            .submit(
                id,
                Command {
                    actor: Actor {
                        kind: ActorKind::Panel,
                        name: "e2e".into(),
                        id: None,
                        via: None,
                        client: None,
                        tool: None,
                        call: None,
                    },
                    confirmed: false,
                    timeout_secs: None,
                    job,
                },
            )
            .await;

        let mut lines = Vec::new();
        while let Some(update) = updates.recv().await {
            let text = serde_json::to_string(&update)?;
            log(&log_path, &text);
            if update.job_id != id {
                continue;
            }
            lines.extend(update.log.clone());
            if update.state.is_terminal() {
                let answer = serde_json::json!({
                    "state": update.state,
                    "result": update.result,
                    "error": update.error,
                    "log": lines,
                });
                write.write_all(format!("{answer}\n").as_bytes()).await?;
                break;
            }
        }
    }
}
