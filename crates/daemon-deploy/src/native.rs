//! Releases of apps that run straight on the machine rather than in a
//! container: a Laravel app behind PHP-FPM, a Node app under systemd. The
//! app's folder is a git checkout; a release moves it to a commit, runs the
//! app's steps as the app's user, reloads its services and checks it
//! answers. If any of that fails, the commit that was there goes back, with
//! its install and build steps run again, so the app keeps running the
//! code it had.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use daemon_jobs::{run_child, ChildOutcome, Failure, JobContext, Progress};
use daemon_protocol::{ReleaseReload, ReleaseSpec, ReleaseStep};
use serde::Serialize;
use tokio::sync::watch;

use crate::git;

const GIT_TIMEOUT: Duration = Duration::from_secs(300);

/// Who a release runs as: never root, so a step can't do more than the
/// app itself could.
#[derive(Debug, Clone)]
pub struct AppUser {
    pub name: String,
    /// None runs as the daemon's own user (tests only).
    pub ids: Option<(u32, u32)>,
    pub home: PathBuf,
}

impl AppUser {
    pub fn lookup(name: &str) -> Result<Self, Failure> {
        let passwd = std::fs::read_to_string("/etc/passwd")
            .map_err(|e| Failure::new("prepare", format!("could not read /etc/passwd: {e}")))?;
        let user = parse_passwd(&passwd, name).ok_or_else(|| {
            Failure::new(
                "prepare",
                format!("there's no user called {name:?} on this machine"),
            )
        })?;
        if user.ids.is_some_and(|(uid, _)| uid == 0) {
            return Err(Failure::new(
                "prepare",
                format!("{name} is root, and releases never run as root"),
            )
            .with_next_step("Pick the user the app runs as, like www-data."));
        }
        Ok(user)
    }
}

fn parse_passwd(text: &str, name: &str) -> Option<AppUser> {
    text.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 || fields[0] != name {
            return None;
        }
        Some(AppUser {
            name: name.to_string(),
            ids: Some((fields[2].parse().ok()?, fields[3].parse().ok()?)),
            home: PathBuf::from(fields[5]),
        })
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct StepRun {
    pub name: String,
    pub secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReleaseResult {
    pub service: String,
    pub commit: String,
    pub previous: Option<String>,
    pub steps: Vec<StepRun>,
}

pub type ReloadFuture = Pin<Box<dyn Future<Output = Result<(), Failure>> + Send>>;

/// Reloads one of the app's services; the daemon passes in its own, which
/// goes through the broker like any other service action.
pub type Reloader<'a> = &'a (dyn Fn(ReleaseReload) -> ReloadFuture + Send + Sync);

static RUNNING: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

/// One release per folder at a time: two at once would check out over
/// each other.
struct Running(PathBuf);

impl Running {
    fn claim(path: &Path) -> Option<Self> {
        let mut running = RUNNING.lock().unwrap_or_else(|p| p.into_inner());
        running
            .insert(path.to_path_buf())
            .then(|| Running(path.to_path_buf()))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        RUNNING
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.0);
    }
}

pub async fn release(
    ctx: &JobContext,
    spec: &ReleaseSpec,
    user: &AppUser,
    reload: Reloader<'_>,
) -> Result<ReleaseResult, Failure> {
    release_with(&ctx.progress, ctx.cancel.clone(), spec, user, reload).await
}

async fn release_with(
    progress: &Progress,
    mut cancel: watch::Receiver<bool>,
    spec: &ReleaseSpec,
    user: &AppUser,
    reload: Reloader<'_>,
) -> Result<ReleaseResult, Failure> {
    let path = PathBuf::from(&spec.path);

    progress.phase("prepare", Some(5)).await;
    validate(spec, &path)?;
    let _running = Running::claim(&path).ok_or_else(|| {
        Failure::new(
            "prepare",
            format!("{} is already being released", spec.path),
        )
        .with_next_step("Wait for that release to finish, then try again.")
    })?;

    let checkout = Checkout {
        path: &path,
        user,
        repo: &spec.repo,
        token: spec.repo_token.as_ref().map(|t| t.0.as_str()),
    };

    let previous = checkout
        .git(&["rev-parse", "HEAD"], &mut cancel, progress)
        .await
        .ok()
        .and_then(|lines| lines.into_iter().find(|l| git::valid_commit(l.trim())))
        .map(|l| l.trim().to_string());

    let changed = checkout
        .git(
            &["status", "--porcelain", "--untracked-files=no"],
            &mut cancel,
            progress,
        )
        .await?;
    let changed: Vec<String> = changed
        .into_iter()
        .filter(|l| !l.trim().is_empty())
        .collect();
    if !changed.is_empty() {
        if !spec.discard_changes {
            return Err(Failure::new(
                "checkout",
                format!(
                    "{} file(s) in {} were edited on the machine, so nothing was released",
                    changed.len(),
                    spec.path
                ),
            )
            .with_output(changed)
            .with_next_step(
                "Commit those edits to the repository, or turn on discarding edits made on the machine.",
            ));
        }
        progress
            .line(format!(
                "discarding edits to {} file(s) made on the machine",
                changed.len()
            ))
            .await;
    }

    progress.phase("fetch", Some(15)).await;
    checkout.fetch(&spec.commit, &mut cancel, progress).await?;

    progress.phase("checkout", Some(25)).await;
    checkout.reset(&spec.commit, &mut cancel, progress).await?;
    progress
        .line(format!("{} is on {}", spec.path, short(&spec.commit)))
        .await;

    match finish(spec, &checkout, reload, &mut cancel, progress).await {
        Ok(steps) => Ok(ReleaseResult {
            service: spec.service.clone(),
            commit: spec.commit.clone(),
            previous,
            steps,
        }),
        Err(failure) => {
            let Some(previous) = previous.filter(|p| p != &spec.commit) else {
                return Err(failure);
            };
            // A cancelled release still puts the old code back: the new
            // commit is checked out but only half set up.
            let mut cancel = watch::channel(false).1;
            progress.phase("rollback", Some(90)).await;
            progress
                .line(format!("putting {} back", short(&previous)))
                .await;
            let back = put_back(spec, &checkout, &previous, reload, &mut cancel, progress).await;
            Err(match back {
                Ok(()) => failure.with_next_step(format!(
                    "{} is running {} again, as it was before. Fix the problem and push again.",
                    spec.path,
                    short(&previous)
                )),
                Err(back) => Failure {
                    next_step: Some(format!(
                        "Putting {} back failed too ({}: {}), so the app may be down. Check it from its service page.",
                        short(&previous),
                        back.phase,
                        back.message
                    )),
                    ..failure
                },
            })
        }
    }
}

fn validate(spec: &ReleaseSpec, path: &Path) -> Result<(), Failure> {
    if !git::valid_commit(&spec.commit) {
        return Err(Failure::new(
            "prepare",
            format!(
                "{:?} is not a commit SHA; releases pin to a commit, not a branch",
                spec.commit
            ),
        ));
    }
    if !git::valid_repo(&spec.repo) {
        return Err(Failure::new(
            "prepare",
            format!(
                "{:?} is not a repository URL ServerOS will fetch from",
                spec.repo
            ),
        ));
    }
    if !path.is_absolute() || path == Path::new("/") {
        return Err(Failure::new(
            "prepare",
            format!("{} is not a folder an app can be released into", spec.path),
        ));
    }
    if !path.join(".git").exists() {
        return Err(Failure::new(
            "prepare",
            format!("{} is not a git checkout", spec.path),
        )
        .with_next_step("Clone the repository there first; releases update a checkout, they don't create one."));
    }
    Ok(())
}

/// The steps, then the reloads, then the health check: everything after
/// the checkout that can fail.
async fn finish(
    spec: &ReleaseSpec,
    checkout: &Checkout<'_>,
    reload: Reloader<'_>,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<Vec<StepRun>, Failure> {
    let mut ran = Vec::new();
    let count = spec.steps.len().max(1);
    for (i, step) in spec.steps.iter().enumerate() {
        progress
            .phase(&step.name, Some((30 + 50 * i / count) as u8))
            .await;
        let started = Instant::now();
        checkout.step(step, cancel, progress).await?;
        ran.push(StepRun {
            name: step.name.clone(),
            secs: started.elapsed().as_secs(),
        });
    }

    if !spec.reload.is_empty() {
        progress.phase("reload", Some(82)).await;
        for wanted in &spec.reload {
            reload(wanted.clone()).await?;
            progress
                .line(format!("{:?} {}", wanted.action, wanted.service).to_lowercase())
                .await;
        }
    }

    if let Some(url) = &spec.health_url {
        progress.phase("health", Some(88)).await;
        check_health(url, progress).await?;
    }

    Ok(ran)
}

async fn put_back(
    spec: &ReleaseSpec,
    checkout: &Checkout<'_>,
    previous: &str,
    reload: Reloader<'_>,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    checkout.reset(previous, cancel, progress).await?;
    for step in spec.steps.iter().filter(|s| s.on_rollback) {
        checkout.step(step, cancel, progress).await?;
    }
    for wanted in &spec.reload {
        reload(wanted.clone()).await?;
    }
    progress
        .line(format!("{} is back on {}", spec.path, short(previous)))
        .await;
    Ok(())
}

pub async fn check_health(url: &str, progress: &Progress) -> Result<(), Failure> {
    let client = daemon_http::Client::new(daemon_http::Trust::WebPki, "serverosd (release health)")
        .with_timeout(Duration::from_secs(15))
        .with_max_body(1024 * 1024);
    let mut last = String::new();
    for attempt in 1..=5u32 {
        match client.get(url).await {
            Ok(response) if (200..300).contains(&response.status) => {
                progress
                    .line(format!("{url} answered HTTP {}", response.status))
                    .await;
                return Ok(());
            }
            Ok(response) => last = format!("HTTP {}", response.status),
            Err(e) => last = e.to_string(),
        }
        progress
            .line(format!("health check {attempt}/5: {url} {last}"))
            .await;
        tokio::time::sleep(Duration::from_secs(2u64.pow(attempt.min(4)))).await;
    }
    Err(
        Failure::new("health", format!("{url} never answered: {last}"))
            .with_next_step("Check the app's logs; the release changed the code it runs."),
    )
}

struct Checkout<'a> {
    path: &'a Path,
    user: &'a AppUser,
    repo: &'a str,
    token: Option<&'a str>,
}

impl Checkout<'_> {
    fn env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("HOME", self.user.home.to_string_lossy().into_owned()),
            ("USER", self.user.name.clone()),
            ("LOGNAME", self.user.name.clone()),
        ]
    }

    fn git_env(&self) -> Vec<(&'static str, String)> {
        let mut env = self.env();
        env.push(("GIT_TERMINAL_PROMPT", "0".into()));
        env.push((
            "GIT_SSH_COMMAND",
            "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new".into(),
        ));
        // The token goes in as an auth header through git's environment, so
        // it's never in the remote URL, .git/config or the output.
        if let Some(token) = self.token.filter(|t| !t.is_empty()) {
            env.extend(git::token_env(self.repo, token));
        }
        env
    }

    async fn git(
        &self,
        args: &[&str],
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<Vec<String>, Failure> {
        let safe = format!("safe.directory={}", self.path.display());
        let mut full = vec!["-c", safe.as_str()];
        full.extend_from_slice(args);
        let env = self.git_env();
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let outcome = run_child(
            "git",
            &full,
            Some(self.path),
            &env,
            GIT_TIMEOUT,
            cancel,
            progress,
            self.user.ids,
        )
        .await;
        let name = args.first().copied().unwrap_or("git");
        settle(outcome, "checkout", &format!("git {name}"))
    }

    async fn fetch(
        &self,
        commit: &str,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        self.git(&["fetch", "-q", "--no-tags", self.repo, commit], cancel, progress)
            .await
            .map(|_| ())
            .map_err(|f| Failure { phase: "fetch".into(), ..f }.with_next_step(
                "Check the repository address and that ServerOS can read it (its GitHub App is installed on the repository).",
            ))
    }

    async fn reset(
        &self,
        commit: &str,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        self.git(&["reset", "-q", "--hard", commit], cancel, progress)
            .await
            .map(|_| ())
    }

    async fn step(
        &self,
        step: &ReleaseStep,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        progress.line(format!("$ {}", step.run)).await;
        let env = self.env();
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let outcome = run_child(
            "sh",
            &["-c", &step.run],
            Some(self.path),
            &env,
            Duration::from_secs(step.timeout_secs.max(1)),
            cancel,
            progress,
            self.user.ids,
        )
        .await;
        settle(outcome, &step.name, &step.name).map(|_| ())
    }
}

fn settle(outcome: ChildOutcome, phase: &str, what: &str) -> Result<Vec<String>, Failure> {
    match outcome {
        ChildOutcome::Exited { code: 0, tail } => Ok(tail),
        ChildOutcome::Exited { code, tail } => {
            Err(Failure::new(phase, format!("{what} exited with code {code}")).with_output(tail))
        }
        ChildOutcome::TimedOut { tail } => {
            Err(Failure::new(phase, format!("{what} timed out")).with_output(tail))
        }
        ChildOutcome::Cancelled { tail } => Err(Failure::new(
            "cancelled",
            format!("release cancelled during {what}"),
        )
        .with_output(tail)),
        ChildOutcome::Unstartable(e) => Err(Failure::new(phase, e)),
    }
}

fn short(commit: &str) -> &str {
    &commit[..7.min(commit.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_app_user_from_passwd() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n";
        let user = parse_passwd(passwd, "www-data").unwrap();
        assert_eq!(user.ids, Some((33, 33)));
        assert_eq!(user.home, PathBuf::from("/var/www"));
        assert!(parse_passwd(passwd, "nobody").is_none());
    }

    #[test]
    fn one_release_per_folder_at_a_time() {
        let path = Path::new("/srv/one-at-a-time");
        let first = Running::claim(path);
        assert!(first.is_some());
        assert!(Running::claim(path).is_none());
        drop(first);
        assert!(Running::claim(path).is_some());
    }

    fn sh(dir: &Path, script: &str) -> String {
        let out = std::process::Command::new("sh")
            .args(["-c", script])
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn spec(
        app: &Path,
        upstream: &Path,
        commit: &str,
        steps: &[(&str, &str, bool)],
    ) -> ReleaseSpec {
        ReleaseSpec {
            service: "systemd:php8.4-fpm.service".into(),
            path: app.display().to_string(),
            user: "test".into(),
            repo: format!("file://{}", upstream.display()),
            commit: commit.into(),
            steps: steps
                .iter()
                .map(|(name, run, on_rollback)| ReleaseStep {
                    name: (*name).into(),
                    run: (*run).into(),
                    on_rollback: *on_rollback,
                    timeout_secs: 30,
                })
                .collect(),
            reload: vec![ReleaseReload {
                service: "systemd:php8.4-fpm.service".into(),
                action: daemon_protocol::ServiceAction::Reload,
            }],
            health_url: None,
            discard_changes: false,
            repo_token: None,
        }
    }

    #[tokio::test]
    async fn releases_a_commit_and_puts_the_old_one_back_when_a_step_fails() {
        let dir = tempfile::tempdir().unwrap();
        let upstream = dir.path().join("upstream");
        let app = dir.path().join("app");
        std::fs::create_dir_all(&upstream).unwrap();
        sh(
            &upstream,
            "git init -q -b main && echo one > version && git add . && git commit -qm one",
        );
        sh(dir.path(), "git clone -q upstream app");
        let one = sh(&upstream, "git rev-parse HEAD");
        sh(&upstream, "echo two > version && git commit -qam two");
        let two = sh(&upstream, "git rev-parse HEAD");
        sh(&upstream, "echo three > version && git commit -qam three");
        let three = sh(&upstream, "git rev-parse HEAD");

        let state = std::sync::Arc::new(daemon_state::State::in_memory().unwrap());
        let (tx, _rx) = tokio::sync::mpsc::channel(1024);
        let progress = Progress::new(uuid::Uuid::new_v4(), state, tx, vec![]);
        let cancel = watch::channel(false).1;
        let user = AppUser {
            name: "test".into(),
            ids: None,
            home: dir.path().to_path_buf(),
        };
        let reloads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = reloads.clone();
        let reload = move |_: ReleaseReload| -> ReloadFuture {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        };

        let built = [("build", "cp version built", true)];
        let done = release_with(
            &progress,
            cancel.clone(),
            &spec(&app, &upstream, &two, &built),
            &user,
            &reload,
        )
        .await
        .unwrap();
        assert_eq!(done.previous.as_deref(), Some(one.as_str()));
        assert_eq!(
            std::fs::read_to_string(app.join("built")).unwrap().trim(),
            "two"
        );
        assert_eq!(reloads.load(std::sync::atomic::Ordering::SeqCst), 1);

        // The migration fails: three is checked out, then two goes back with
        // its build run again but not the migration.
        let failing = [
            ("build", "cp version built", true),
            ("migrate", "echo migrated >> migrations; exit 3", false),
        ];
        let failure = release_with(
            &progress,
            cancel.clone(),
            &spec(&app, &upstream, &three, &failing),
            &user,
            &reload,
        )
        .await
        .unwrap_err();
        assert_eq!(failure.phase, "migrate");
        assert!(failure.next_step.unwrap().contains("running"));
        assert_eq!(sh(&app, "git rev-parse HEAD"), two);
        assert_eq!(
            std::fs::read_to_string(app.join("built")).unwrap().trim(),
            "two"
        );
        assert_eq!(
            std::fs::read_to_string(app.join("migrations"))
                .unwrap()
                .lines()
                .count(),
            1
        );

        // Edits made on the machine stop a release unless they may go.
        std::fs::write(app.join("version"), "edited\n").unwrap();
        let failure = release_with(
            &progress,
            cancel.clone(),
            &spec(&app, &upstream, &three, &built),
            &user,
            &reload,
        )
        .await
        .unwrap_err();
        assert_eq!(failure.phase, "checkout");
        assert_eq!(
            std::fs::read_to_string(app.join("version")).unwrap(),
            "edited\n"
        );

        let mut discard = spec(&app, &upstream, &three, &built);
        discard.discard_changes = true;
        release_with(&progress, cancel, &discard, &user, &reload)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(app.join("built")).unwrap().trim(),
            "three"
        );
    }
}
