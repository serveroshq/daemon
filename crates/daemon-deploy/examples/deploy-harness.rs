//! Test harness for deploys; not shipped. It does what serverosd does with
//! `deploy`, `repo_inspect`, `docker_install` and `resolve_ref` jobs, minus
//! the panel connection: it takes jobs as the panel sends them, one JSON
//! line per connection on a unix socket, runs each through the real job
//! runner and the daemon's own Deployer, and answers with the job's final
//! update and its log as one JSON line. Secrets are scrubbed from the log
//! as serverosd scrubs them.
//!
//!   deploy-harness serve --socket /run/sosdeploy.sock
//!   echo '{"type":"deploy",...}' | socat - UNIX-CONNECT:/run/sosdeploy.sock
//!
//! Every job update is also appended to `/var/lib/serveros/harness.log`.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use daemon_core::Paths;
use daemon_deploy::container::BuildLimits;
use daemon_deploy::proxy::Proxy;
use daemon_deploy::Deployer;
use daemon_jobs::{Failure, Handler, HandlerFuture, JobContext, Runner};
use daemon_protocol::{Actor, ActorKind, Command, Job, JobUpdate};
use daemon_state::State;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::mpsc;

struct DeployHandler {
    deployer: Arc<Deployer>,
}

impl Handler for DeployHandler {
    fn handle(&self, ctx: JobContext) -> HandlerFuture {
        let deployer = Arc::clone(&self.deployer);
        Box::pin(async move {
            let mut cancel = ctx.cancel.clone();
            let value = |v: serde_json::Result<serde_json::Value>| v.unwrap_or_default();
            match ctx.command.job.clone() {
                Job::Deploy(spec) => deployer
                    .deploy(&ctx, &spec)
                    .await
                    .map(|r| value(serde_json::to_value(r))),
                Job::RepoInspect {
                    service,
                    repo,
                    git_ref,
                    base_dir,
                    repo_token,
                } => deployer
                    .inspect_repo(
                        &ctx.id.to_string(),
                        service.as_deref(),
                        &repo,
                        git_ref.as_deref(),
                        base_dir.as_deref(),
                        repo_token.as_ref().map(|t| t.0.as_str()),
                        &mut cancel,
                    )
                    .await
                    .map(|r| value(serde_json::to_value(r))),
                Job::DockerInstall => {
                    daemon_deploy::docker_install::install(&mut cancel, &ctx.progress)
                        .await
                        .map(|r| value(serde_json::to_value(r)))
                }
                Job::ResolveRef {
                    service,
                    repo,
                    git_ref,
                    repo_token,
                } => deployer
                    .resolve_ref(
                        &service,
                        &repo,
                        git_ref.as_deref(),
                        repo_token.as_ref().map(|t| t.0.as_str()),
                        &mut cancel,
                    )
                    .await
                    .map(|r| value(serde_json::to_value(r))),
                _ => Err(Failure::new(
                    "harness",
                    "only deploy, repo_inspect, docker_install and resolve_ref jobs here",
                )),
            }
        })
    }

    // As serverosd's handler: settings, build settings, tokens and
    // registry passwords are scrubbed from the log.
    fn known_secrets(&self, job: &Job) -> Vec<String> {
        match job {
            Job::Deploy(spec) => spec
                .env
                .values()
                .cloned()
                .chain(spec.build.iter().flat_map(|b| b.args.values().cloned()))
                .chain(spec.repo_token.iter().map(|t| t.0.clone()))
                .chain(spec.registries.iter().map(|r| r.password.0.clone()))
                .filter(|s| !s.is_empty())
                .collect(),
            Job::RepoInspect { repo_token, .. } | Job::ResolveRef { repo_token, .. } => {
                repo_token.iter().map(|t| t.0.clone()).collect()
            }
            _ => Vec::new(),
        }
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
        eprintln!("usage: deploy-harness serve --socket PATH");
        std::process::exit(2);
    }
    let socket = PathBuf::from(arg(&args, "--socket").unwrap_or("/run/sosdeploy.sock".into()));
    let paths = Paths::default();
    for (dir, _) in paths.owned_directories() {
        std::fs::create_dir_all(dir)?;
    }
    let log_path = paths.state_dir.join("harness.log");
    let state = Arc::new(State::open(&paths.state_db())?);
    let deployer = Arc::new(Deployer {
        paths: paths.clone(),
        state: Arc::clone(&state),
        proxy: std::sync::RwLock::new(Proxy::default()),
        build_limits: BuildLimits {
            cpu_percent: 200,
            memory_mb: 4096,
        },
    });

    let (tx, mut updates) = mpsc::channel::<JobUpdate>(1024);
    let runner = Runner::new(
        Arc::clone(&state),
        Arc::new(DeployHandler { deployer }),
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
        if BufReader::new(read).read_line(&mut line).await.is_err() {
            continue;
        }

        let job: Job = match serde_json::from_str(&line) {
            Ok(job) => job,
            Err(e) => {
                let answer = serde_json::json!({"state": "rejected", "error": e.to_string()});
                let _ = write.write_all(format!("{answer}\n").as_bytes()).await;
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
                    confirmed: true,
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
                // A client that went away doesn't stop the harness; the
                // answer is in harness.log either way.
                let _ = write.write_all(format!("{answer}\n").as_bytes()).await;
                break;
            }
        }
    }
}
