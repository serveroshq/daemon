//! Deploys against a real Docker: `SERVEROS_LIVE_DOCKER=1 cargo test -p
//! daemon-deploy --test deploy_live -- --ignored --nocapture`. Needs Docker
//! and the busybox image (pulled if missing). Leaves nothing behind.

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use daemon_core::Paths;
use daemon_deploy::container::BuildLimits;
use daemon_deploy::proxy::Proxy;
use daemon_deploy::{Deployer, ReleaseLedger};
use daemon_jobs::{JobContext, Progress};
use daemon_protocol::{Actor, ActorKind, DeploySpec, HealthCheck, Job, VolumeMount};
use daemon_state::State;
use tokio::sync::watch;
use uuid::Uuid;

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker").args(args).output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn context(state: &Arc<State>) -> (JobContext, watch::Sender<bool>) {
    let id = Uuid::new_v4();
    state.record_job(id, "test", "deploy", "{}").unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(4096);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let progress = Progress::new(id, Arc::clone(state), tx, vec!["s3cret-value".into()]);
    let (cancel_tx, cancel) = watch::channel(false);
    let ctx = JobContext {
        id,
        command: daemon_protocol::Command {
            actor: Actor {
                kind: ActorKind::Panel,
                name: "test".into(),
                id: None,
                via: None,
                client: None,
                tool: None,
                call: None,
            },
            confirmed: true,
            timeout_secs: None,
            job: Job::Discover,
        },
        progress,
        cancel,
        timeout: Duration::from_secs(600),
    };
    (ctx, cancel_tx)
}

fn log_of(state: &State, ctx: &JobContext) -> String {
    state.job(ctx.id).unwrap().unwrap().log
}

const DOCKERFILE: &str = "FROM busybox:1.36
EXPOSE 8080
VOLUME [\"/declared\"]
CMD [\"sh\", \"-c\", \"mkdir -p /www && echo ok > /www/index.html && printenv MULTI > /www/multi.txt && exec httpd -f -p $PORT -h /www\"]
";

fn spec(service: &str, commit: &str, network: &str) -> DeploySpec {
    let mut spec: DeploySpec = serde_json::from_value(serde_json::json!({
        "service": service,
        "commit": commit,
        "files": {"Dockerfile": DOCKERFILE},
    }))
    .unwrap();
    spec.snapshot_before = false;
    spec.env = BTreeMap::from([
        ("MULTI".to_string(), "line one\nline two".to_string()),
        ("APP_TOKEN".to_string(), "s3cret-value".to_string()),
    ]);
    spec.volumes = vec![VolumeMount {
        name: "data".into(),
        path: "/data".into(),
    }];
    spec.network = Some(network.into());
    spec.release_command =
        Some("echo migrating; printenv MULTI | wc -l > /data/release.txt".into());
    spec.post_deploy_command = Some("cat /data/release.txt".into());
    spec.health = Some(HealthCheck {
        path: "/".into(),
        expected_status: 0,
        timeout_secs: 5,
        retries: 3,
        start_period_secs: 10,
        interval_secs: Some(1),
    });
    spec
}

#[tokio::test]
#[ignore]
async fn deploys_runs_its_commands_and_rolls_back_on_a_real_docker() {
    if std::env::var("SERVEROS_LIVE_DOCKER").is_err() {
        return;
    }
    let service = format!("sos-live-{}", std::process::id());
    let network = format!("sos-live-net-{}", std::process::id());
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(State::in_memory().unwrap());
    let deployer = Deployer {
        paths: Paths::under(dir.path()),
        state: Arc::clone(&state),
        proxy: std::sync::RwLock::new(Proxy::default()),
        build_limits: BuildLimits {
            cpu_percent: 200,
            memory_mb: 2048,
        },
    };
    let a = "a".repeat(40);
    let b = "b".repeat(40);
    let _cleanup = Cleanup {
        service: service.clone(),
        network: network.clone(),
    };

    {
        // A first deploy: port from EXPOSE, settings over lines, its own
        // volume, the shared network, a release and a post-deploy command.
        let (ctx, _c) = context(&state);
        let result = deployer.deploy(&ctx, &spec(&service, &a, &network)).await;
        let log = log_of(&state, &ctx);
        println!("{log}");
        let result = result.unwrap_or_else(|f| panic!("{f:?}\n{log}"));
        assert_eq!(result.container_port, Some(8080));
        assert!(log.contains("from the image's EXPOSE"), "{log}");
        assert!(log.contains("PORT is set to 8080"), "{log}");
        assert!(log.contains("migrating"), "{log}");
        assert!(log.contains("the post-deploy command finished"), "{log}");
        assert!(!log.contains("s3cret-value"), "{log}");

        let name = &result.container;
        let env = docker(&["inspect", "--format", "{{json .Config.Env}}", name]);
        let env: Vec<String> = serde_json::from_str(&env).unwrap();
        assert!(
            env.contains(&"MULTI=line one\nline two".to_string()),
            "{env:?}"
        );
        assert!(env.contains(&"PORT=8080".to_string()), "{env:?}");
        assert_eq!(
            docker(&["exec", name, "cat", "/www/multi.txt"]),
            "line one\nline two"
        );
        assert_eq!(docker(&["exec", name, "cat", "/data/release.txt"]), "2");

        let networks = docker(&[
            "inspect",
            "--format",
            "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{join $v.Aliases \",\"}} {{end}}",
            name,
        ]);
        assert!(networks.contains("bridge="), "{networks}");
        assert!(networks.contains(&format!("{network}=")), "{networks}");
        assert!(networks.contains(&service), "{networks}");
        let hosts = docker(&[
            "inspect",
            "--format",
            "{{json .HostConfig.ExtraHosts}}",
            name,
        ]);
        assert!(
            hosts.contains("host.docker.internal:host-gateway"),
            "{hosts}"
        );
        let logs = docker(&[
            "inspect",
            "--format",
            "{{json .HostConfig.LogConfig.Config}}",
            name,
        ]);
        assert!(logs.contains("\"max-size\":\"10m\""), "{logs}");
        let volume = format!("serveros-{service}-data");
        assert_eq!(
            docker(&[
                "volume",
                "inspect",
                "--format",
                "{{index .Labels \"com.serveros.app\"}}",
                &volume
            ]),
            service
        );
        let release = ReleaseLedger::new(&state).current(&service).unwrap();
        assert_eq!(release.network.as_deref(), Some(network.as_str()));
        assert_eq!(release.health.as_ref().unwrap().start_period_secs, 10);
        // The release command's container is gone.
        assert_eq!(
            docker(&["ps", "-aq", "--filter", &format!("name={name}-release")]),
            ""
        );

        // A release command that fails: nothing changes, and it says so.
        let (ctx, _c) = context(&state);
        let mut failing = spec(&service, &b, &network);
        failing.release_command = Some("echo nope; exit 3".into());
        let failure = deployer.deploy(&ctx, &failing).await.unwrap_err();
        let log = log_of(&state, &ctx);
        assert_eq!(failure.phase, "release", "{failure:?}");
        assert!(
            failure.output_tail.iter().any(|l| l == "nope"),
            "{failure:?}"
        );
        assert!(
            log.contains(&format!("{service} is still live on release aaaaaaa")),
            "{log}"
        );
        assert_eq!(
            docker(&["inspect", "--format", "{{.State.Status}}", name]),
            "running"
        );

        // An app that listens on another port than it's checked on.
        let (ctx, _c) = context(&state);
        let mut wrong = spec(&service, &b, &network);
        wrong.release_command = None;
        wrong.env.insert("PORT".into(), "9999".into());
        wrong.health.as_mut().unwrap().start_period_secs = 2;
        wrong.health.as_mut().unwrap().retries = 2;
        let failure = deployer.deploy(&ctx, &wrong).await.unwrap_err();
        assert_eq!(failure.phase, "health", "{failure:?}");
        assert!(
            failure
                .message
                .contains("nothing is accepting connections on port 8080"),
            "{failure:?}"
        );
        assert!(failure.next_step.unwrap().contains("0.0.0.0"));
        let gone = docker(&[
            "ps",
            "-aq",
            "--filter",
            &format!("name=serveros-{service}-bbbbbbbbbbbb"),
        ]);
        assert_eq!(gone, "", "the failed release's container was removed");

        // A second release, then back to the first.
        let (ctx, _c) = context(&state);
        let second = deployer.deploy(&ctx, &spec(&service, &b, &network)).await;
        let second = second.unwrap_or_else(|f| panic!("{f:?}\n{}", log_of(&state, &ctx)));
        assert_eq!(
            docker(&["inspect", "--format", "{{.State.Status}}", name]),
            "exited",
            "the first release was stopped"
        );
        let (ctx, _c) = context(&state);
        let back = deployer
            .rollback(&ctx, &service, Some("aaaaaaa"), &[])
            .await;
        let log = log_of(&state, &ctx);
        let back = back.unwrap_or_else(|f| panic!("{f:?}\n{log}"));
        assert_eq!(back.container, *name);
        assert_eq!(back.container_port, Some(8080));
        assert!(log.contains("giving it 10 seconds to start"), "{log}");
        assert_eq!(docker(&["exec", name, "cat", "/data/release.txt"]), "2");
        let networks = docker(&[
            "inspect",
            "--format",
            "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
            name,
        ]);
        assert!(networks.contains(&network), "{networks}");
        assert_eq!(
            docker(&[
                "inspect",
                "--format",
                "{{.State.Status}}",
                &second.container
            ]),
            "exited"
        );
    }
}

/// Leaves nothing behind, even when an assertion fails.
struct Cleanup {
    service: String,
    network: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let label = format!("label=com.serveros.app={}", self.service);
        for id in docker(&["ps", "-aq", "--filter", &label]).split_whitespace() {
            docker(&["rm", "-f", id]);
        }
        for volume in docker(&["volume", "ls", "-q", "--filter", &label]).split_whitespace() {
            docker(&["volume", "rm", volume]);
        }
        docker(&["network", "rm", &self.network]);
        let images = docker(&["images", "-q", &format!("serveros/{}", self.service)]);
        for image in images.split_whitespace() {
            docker(&["rmi", "-f", image]);
        }
    }
}

const COMPOSE: &str = "services:
  web:
    image: busybox:1.36
    command: [\"sh\", \"-c\", \"mkdir -p /www && printenv GREETING > /www/index.html && exec httpd -f -p 8080 -h /www\"]
    environment:
      GREETING: ${GREETING}
    ports: [\"127.0.0.1:${HOST_PORT}:8080\"]
";

const CRASHING: &str = "services:
  web:
    image: busybox:1.36
    command: [\"sh\", \"-c\", \"echo broken; exit 1\"]
    ports: [\"127.0.0.1:${HOST_PORT}:8080\"]
";

fn get(port: u16) -> String {
    use std::io::{Read, Write};
    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return String::new();
    };
    let _ = stream.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n");
    let mut body = String::new();
    let _ = stream.read_to_string(&mut body);
    body
}

#[tokio::test]
#[ignore]
async fn a_failed_compose_deploy_puts_the_live_stack_back_on_a_real_docker() {
    if std::env::var("SERVEROS_LIVE_DOCKER").is_err() {
        return;
    }
    let service = format!("sos-compose-{}", std::process::id());
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(State::in_memory().unwrap());
    let deployer = Deployer {
        paths: Paths::under(dir.path()),
        state: Arc::clone(&state),
        proxy: std::sync::RwLock::new(Proxy::default()),
        build_limits: BuildLimits {
            cpu_percent: 200,
            memory_mb: 2048,
        },
    };
    let _cleanup = ComposeCleanup(format!("serveros-{service}"));
    let compose = |commit: &str, file: &str, with_port: bool| {
        let mut spec: DeploySpec = serde_json::from_value(serde_json::json!({
            "service": service,
            "commit": commit,
            "compose_file": "compose.yaml",
            "files": {"compose.yaml": file},
        }))
        .unwrap();
        spec.snapshot_before = false;
        spec.port = with_port.then_some(port);
        spec.env = BTreeMap::from([
            ("GREETING".to_string(), "it's $HOME, \"quoted\"".to_string()),
            ("HOST_PORT".to_string(), port.to_string()),
        ]);
        spec
    };

    let (ctx, _c) = context(&state);
    let first = deployer
        .deploy(&ctx, &compose(&"a".repeat(40), COMPOSE, true))
        .await;
    let log = log_of(&state, &ctx);
    first.unwrap_or_else(|f| panic!("{f:?}\n{log}"));
    assert!(
        get(port).ends_with("it's $HOME, \"quoted\"\n"),
        "{}",
        get(port)
    );

    // A stack whose web service crashes: its port never answers, and the
    // live files go back and come up again.
    let (ctx, _c) = context(&state);
    let failure = deployer
        .deploy(&ctx, &compose(&"b".repeat(40), CRASHING, true))
        .await
        .unwrap_err();
    let log = log_of(&state, &ctx);
    println!("{log}");
    assert_eq!(failure.phase, "health", "{failure:?}");
    assert!(
        log.contains("putting back the Compose files of release aaaaaaa"),
        "{log}"
    );
    assert!(log.contains("started release aaaaaaa again"), "{log}");
    assert!(!log.contains("still live"), "{log}");
    assert!(
        get(port).ends_with("it's $HOME, \"quoted\"\n"),
        "{}",
        get(port)
    );

    // Without a port, the stack's containers have to keep running.
    let (ctx, _c) = context(&state);
    let failure = deployer
        .deploy(&ctx, &compose(&"c".repeat(40), CRASHING, false))
        .await
        .unwrap_err();
    assert_eq!(failure.phase, "health", "{failure:?}");
    assert!(failure.message.contains("exited 1"), "{failure:?}");
    assert!(
        failure.output_tail.iter().any(|l| l.contains("broken")),
        "{failure:?}"
    );
    assert!(get(port).ends_with("it's $HOME, \"quoted\"\n"));
}

struct ComposeCleanup(String);

impl Drop for ComposeCleanup {
    fn drop(&mut self) {
        let label = format!("label=com.docker.compose.project={}", self.0);
        for id in docker(&["ps", "-aq", "--filter", &label]).split_whitespace() {
            docker(&["rm", "-f", id]);
        }
        docker(&["network", "rm", &format!("{}_default", self.0)]);
    }
}
