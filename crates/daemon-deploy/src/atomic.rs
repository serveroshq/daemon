//! Atomic releases of apps that run on the machine. Each release is built
//! in a folder of its own beside the app's (/var/www/app-releases/<when>-<commit>),
//! with what every release shares (.env, storage) linked in from
//! /var/www/app-releases/shared. Only when it's built does the app's folder,
//! by then a link, switch to it, in one rename: the app never runs half set
//! up, a failed build changes nothing, and going back to a kept release is a
//! switch rather than a build.
//!
//! The first atomic release of an app that's a plain folder moves that
//! folder in as the first kept release and puts a link where it was.

use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use daemon_jobs::{Failure, Progress};
use daemon_protocol::ReleaseSpec;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::git;
use crate::native::{go_live, run_steps, short, AppUser, Checkout, ReleaseResult, Reloader};

struct Layout {
    app: PathBuf,
    releases: PathBuf,
    shared: PathBuf,
    ledger: PathBuf,
}

impl Layout {
    fn of(app: &Path) -> Result<Self, Failure> {
        let (Some(parent), Some(name)) = (app.parent(), app.file_name()) else {
            return Err(Failure::new(
                "prepare",
                format!(
                    "{} has no folder above it to keep releases in",
                    app.display()
                ),
            ));
        };
        let releases = parent.join(format!("{}-releases", name.to_string_lossy()));

        Ok(Self {
            app: app.to_path_buf(),
            shared: releases.join("shared"),
            ledger: releases.join("releases.json"),
            releases,
        })
    }

    /// Where the app's link points now.
    fn live(&self) -> Result<PathBuf, Failure> {
        let target = std::fs::read_link(&self.app).map_err(|e| {
            Failure::new(
                "prepare",
                format!("could not read where {} points: {e}", self.app.display()),
            )
        })?;

        Ok(match self.app.parent() {
            Some(parent) if target.is_relative() => parent.join(target),
            _ => target,
        })
    }

    /// A folder this module made: <unix time>-<commit or "initial">.
    fn is_release(&self, dir: &Path) -> bool {
        dir.parent() == Some(self.releases.as_path())
            && dir
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.split_once('-'))
                .is_some_and(|(when, what)| {
                    !when.is_empty()
                        && when.chars().all(|c| c.is_ascii_digit())
                        && (what == "initial"
                            || (!what.is_empty() && what.chars().all(|c| c.is_ascii_hexdigit())))
                })
    }
}

/// A release that went live, kept for going back to; oldest first.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Kept {
    dir: PathBuf,
    commit: String,
    at: u64,
}

fn load(ledger: &Path) -> Vec<Kept> {
    std::fs::read(ledger)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save(ledger: &Path, kept: &[Kept]) {
    if let Ok(json) = serde_json::to_vec_pretty(kept) {
        let _ = std::fs::write(ledger, json);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Paths inside the app: relative, no "..", and never its .git.
fn check_relative(paths: &[String], what: &str) -> Result<(), Failure> {
    for path in paths {
        let p = Path::new(path);
        let plain = !path.is_empty()
            && p.components().all(|c| matches!(c, Component::Normal(_)))
            && p.components().next() != Some(Component::Normal(".git".as_ref()));
        if !plain {
            return Err(Failure::new(
                "prepare",
                format!(
                    "{path:?} can't be {what}: it should be a path inside the app, like storage"
                ),
            ));
        }
    }
    Ok(())
}

fn owned_by(path: &Path, user: &AppUser) {
    if let Some((uid, gid)) = user.ids {
        let _ = std::os::unix::fs::lchown(path, Some(uid), Some(gid));
    }
}

fn make_dir(path: &Path, user: &AppUser) -> Result<(), Failure> {
    if !path.is_dir() {
        std::fs::create_dir_all(path).map_err(|e| {
            Failure::new(
                "prepare",
                format!("could not create {}: {e}", path.display()),
            )
        })?;
        owned_by(path, user);
    }
    Ok(())
}

fn remove(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn link(target: &Path, at: &Path, user: &AppUser) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, at)?;
    owned_by(at, user);
    Ok(())
}

/// Point the app's link at a release, in one rename.
fn switch(layout: &Layout, dir: &Path, user: &AppUser) -> Result<(), Failure> {
    let name = layout.app.file_name().unwrap_or_default().to_string_lossy();
    let next = layout.app.with_file_name(format!(".{name}.next"));
    let _ = std::fs::remove_file(&next);
    link(dir, &next, user)
        .and_then(|()| std::fs::rename(&next, &layout.app))
        .map_err(|e| {
            let _ = std::fs::remove_file(&next);
            Failure::new(
                "switch",
                format!(
                    "could not point {} at {}: {e}",
                    layout.app.display(),
                    dir.display()
                ),
            )
        })
}

pub(crate) async fn release(
    progress: &Progress,
    mut cancel: watch::Receiver<bool>,
    spec: &ReleaseSpec,
    user: &AppUser,
    reload: Reloader<'_>,
) -> Result<ReleaseResult, Failure> {
    let layout = Layout::of(Path::new(&spec.path))?;
    check_relative(&spec.shared, "shared")?;
    check_relative(&spec.trim, "trimmed")?;
    make_dir(&layout.releases, user)?;
    make_dir(&layout.shared, user)?;
    let token = spec.repo_token.as_ref().map(|t| t.0.as_str());
    let mut kept = load(&layout.ledger);

    let is_link = std::fs::symlink_metadata(&layout.app).is_ok_and(|m| m.file_type().is_symlink());
    if !is_link {
        convert(&layout, spec, user, &mut kept, &mut cancel, progress).await?;
    }

    let live = layout.live()?;
    let previous = commit_of(&live, user, spec, &mut cancel, progress).await;
    if !kept.iter().any(|k| k.dir == live) {
        if let Some(commit) = &previous {
            kept.push(Kept {
                dir: live.clone(),
                commit: commit.clone(),
                at: now(),
            });
        }
    }

    // A kept release of this commit: switch back to it, no build. The live
    // one is built again (a release run again by hand means "rebuild").
    let reuse = kept
        .iter()
        .rev()
        .find(|k| k.commit == spec.commit && k.dir != live && k.dir.is_dir())
        .map(|k| k.dir.clone());

    let (dir, steps, reused) = match reuse {
        Some(dir) => {
            progress
                .line(format!(
                    "{} is kept in {}; switching back to it",
                    short(&spec.commit),
                    dir.display()
                ))
                .await;
            (dir, Vec::new(), true)
        }
        None => {
            let dir = layout.releases.join(format!(
                "{}-{}",
                now(),
                &spec.commit[..12.min(spec.commit.len())]
            ));
            match build(
                &layout,
                spec,
                user,
                token,
                &live,
                &dir,
                &mut cancel,
                progress,
            )
            .await
            {
                Ok(steps) => (dir, steps, false),
                Err(failure) => {
                    let _ = remove(&dir);
                    let still = previous
                        .as_deref()
                        .map(short)
                        .unwrap_or("the release it had");
                    return Err(failure.with_next_step(format!(
                        "Nothing changed: {} is still on {still}. Fix the problem and push again.",
                        spec.path
                    )));
                }
            }
        }
    };

    progress.phase("switch", Some(80)).await;
    switch(&layout, &dir, user)?;
    progress
        .line(format!("{} now points at {}", spec.path, dir.display()))
        .await;

    if let Err(failure) = go_live(spec, reload, progress).await {
        progress.phase("rollback", Some(90)).await;
        let back = match switch(&layout, &live, user) {
            Ok(()) => {
                let mut reloaded = Ok(());
                for wanted in &spec.reload {
                    if let Err(e) = reload(wanted.clone()).await {
                        reloaded = Err(e);
                    }
                }
                reloaded
            }
            Err(e) => Err(e),
        };
        if !reused {
            let _ = remove(&dir);
        }
        let was = previous.as_deref().map(short).unwrap_or("the last release");
        return Err(match back {
            Ok(()) => failure.with_next_step(format!(
                "{} is back on {was}, as it was before. Fix the problem and push again.",
                spec.path
            )),
            Err(back) => Failure {
                next_step: Some(format!(
                    "Switching back to {was} failed too ({}: {}), so the app may be down. Check it from its service page.",
                    back.phase, back.message
                )),
                ..failure
            },
        });
    }

    kept.retain(|k| k.dir != dir);
    kept.push(Kept {
        dir: dir.clone(),
        commit: spec.commit.clone(),
        at: now(),
    });
    prune(&layout, spec, &mut kept, &dir, progress).await;
    save(&layout.ledger, &kept);

    Ok(ReleaseResult {
        service: spec.service.clone(),
        commit: spec.commit.clone(),
        previous,
        steps,
        release: Some(dir.display().to_string()),
        reused,
    })
}

async fn commit_of(
    dir: &Path,
    user: &AppUser,
    spec: &ReleaseSpec,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Option<String> {
    let checkout = Checkout {
        path: dir,
        user,
        repo: &spec.repo,
        token: None,
    };
    checkout
        .git(&["rev-parse", "HEAD"], cancel, progress)
        .await
        .ok()?
        .into_iter()
        .map(|l| l.trim().to_string())
        .find(|l| git::valid_commit(l))
}

/// The first atomic release of a plain folder: it becomes the first kept
/// release, with a link where it was and what's shared moved out of it.
async fn convert(
    layout: &Layout,
    spec: &ReleaseSpec,
    user: &AppUser,
    kept: &mut Vec<Kept>,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    if !layout.app.is_dir() {
        return Err(Failure::new(
            "prepare",
            format!("{} is not a folder", layout.app.display()),
        ));
    }
    let commit = commit_of(&layout.app, user, spec, cancel, progress).await;
    let dir = layout.releases.join(format!(
        "{}-{}",
        now(),
        commit
            .as_deref()
            .map(|c| &c[..12.min(c.len())])
            .unwrap_or("initial")
    ));
    progress
        .line(format!(
            "first atomic release: {} moves to {} and becomes a link to it",
            spec.path,
            dir.display()
        ))
        .await;

    std::fs::rename(&layout.app, &dir).map_err(|e| {
        Failure::new(
            "prepare",
            format!("could not move {} into {}: {e}", spec.path, dir.display()),
        )
    })?;
    if let Err(e) = link(&dir, &layout.app, user) {
        // Put the folder back rather than leave the app without one.
        let _ = std::fs::rename(&dir, &layout.app);
        return Err(Failure::new(
            "prepare",
            format!("could not link {} to {}: {e}", spec.path, dir.display()),
        ));
    }

    for path in &spec.shared {
        let inside = dir.join(path);
        let out = layout.shared.join(path);
        if std::fs::symlink_metadata(&inside).is_err() {
            continue;
        }
        if std::fs::symlink_metadata(&out).is_ok() {
            progress
                .line(format!(
                    "{path} is already shared, so the copy in the app was left as it is"
                ))
                .await;
            continue;
        }
        if let Some(parent) = out.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::rename(&inside, &out)
            .and_then(|()| link(&out, &inside, user))
            .map_err(|e| Failure::new("prepare", format!("could not share {path}: {e}")))?;
        progress
            .line(format!("{path} is now shared by every release"))
            .await;
    }

    if let Some(commit) = commit {
        kept.push(Kept {
            dir,
            commit,
            at: now(),
        });
        save(&layout.ledger, kept);
    }
    Ok(())
}

/// A new release folder: a clone of the live one moved to the commit, with
/// what's shared linked in, then the app's commands.
#[allow(clippy::too_many_arguments)]
async fn build(
    layout: &Layout,
    spec: &ReleaseSpec,
    user: &AppUser,
    token: Option<&str>,
    live: &Path,
    dir: &Path,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<Vec<crate::native::StepRun>, Failure> {
    progress.phase("fetch", Some(15)).await;
    let releases = Checkout {
        path: &layout.releases,
        user,
        repo: &spec.repo,
        token: None,
    };
    let (live_arg, dir_arg) = (live.to_string_lossy(), dir.to_string_lossy());
    releases
        .git(
            &["clone", "-q", "--no-checkout", &live_arg, &dir_arg],
            cancel,
            progress,
        )
        .await?;

    let checkout = Checkout {
        path: dir,
        user,
        repo: &spec.repo,
        token,
    };
    checkout.fetch(&spec.commit, cancel, progress).await?;
    progress.phase("checkout", Some(25)).await;
    checkout
        .git(
            &["checkout", "-q", "-f", "--detach", &spec.commit],
            cancel,
            progress,
        )
        .await?;

    for path in &spec.shared {
        let source = layout.shared.join(path);
        if std::fs::symlink_metadata(&source).is_err() {
            progress
                .line(format!(
                    "nothing shared at {path} yet, so the release keeps its own"
                ))
                .await;
            continue;
        }
        let at = dir.join(path);
        if let Some(parent) = at.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        remove(&at)
            .and_then(|()| link(&source, &at, user))
            .map_err(|e| Failure::new("checkout", format!("could not link {path}: {e}")))?;
    }

    run_steps(spec, &checkout, cancel, progress).await
}

/// Keep the newest releases, trim the ones that aren't live, and clear out
/// anything left by failed builds. Only ever touches release folders.
async fn prune(
    layout: &Layout,
    spec: &ReleaseSpec,
    kept: &mut Vec<Kept>,
    live: &Path,
    progress: &Progress,
) {
    let keep = spec.keep.max(1) as usize;
    while kept.len() > keep {
        let Some(i) = kept.iter().position(|k| k.dir != live) else {
            break;
        };
        let old = kept.remove(i);
        if layout.is_release(&old.dir) && remove(&old.dir).is_ok() {
            progress
                .line(format!(
                    "removed the release of {} to keep {keep}",
                    short(&old.commit)
                ))
                .await;
        }
    }

    for k in kept.iter().filter(|k| k.dir != live) {
        for path in &spec.trim {
            let _ = remove(&k.dir.join(path));
        }
    }

    if let Ok(entries) = std::fs::read_dir(&layout.releases) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if dir != live && layout.is_release(&dir) && !kept.iter().any(|k| k.dir == dir) {
                let _ = remove(&dir);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_paths_inside_the_app_are_shared() {
        assert!(check_relative(
            &[".env".into(), "storage".into(), "public/uploads".into()],
            "shared"
        )
        .is_ok());
        for bad in ["", "/etc", "../x", "a/../../b", ".git", "./storage"] {
            assert!(check_relative(&[bad.into()], "shared").is_err(), "{bad}");
        }
    }

    #[test]
    fn only_release_folders_count_as_releases() {
        let layout = Layout::of(Path::new("/var/www/app")).unwrap();
        assert_eq!(layout.releases, PathBuf::from("/var/www/app-releases"));
        assert!(layout.is_release(Path::new("/var/www/app-releases/1791500000-8b8472731bba")));
        assert!(layout.is_release(Path::new("/var/www/app-releases/1791500000-initial")));
        assert!(!layout.is_release(Path::new("/var/www/app-releases/shared")));
        assert!(!layout.is_release(Path::new("/var/www/app-releases/releases.json")));
        assert!(!layout.is_release(Path::new("/var/www/other/1791500000-8b8472731bba")));
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

    fn spec(app: &Path, upstream: &Path, commit: &str, build: &str) -> ReleaseSpec {
        ReleaseSpec {
            service: "systemd:app.service".into(),
            path: app.display().to_string(),
            user: "test".into(),
            repo: format!("file://{}", upstream.display()),
            commit: commit.into(),
            steps: vec![daemon_protocol::ReleaseStep {
                name: "build".into(),
                run: build.into(),
                on_rollback: true,
                timeout_secs: 30,
            }],
            reload: vec![daemon_protocol::ReleaseReload {
                service: "systemd:php.service".into(),
                action: daemon_protocol::ServiceAction::Reload,
            }],
            health_url: None,
            discard_changes: false,
            repo_token: None,
            mode: daemon_protocol::ReleaseMode::Atomic,
            shared: vec![".env".into(), "storage".into()],
            keep: 2,
            trim: vec!["node_modules".into()],
        }
    }

    fn read(path: PathBuf) -> String {
        std::fs::read_to_string(path).unwrap().trim().to_string()
    }

    #[tokio::test]
    async fn builds_beside_the_live_release_and_switches_in_one_step() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let upstream = root.join("upstream");
        let app = root.join("app");
        std::fs::create_dir_all(upstream.join("storage")).unwrap();
        sh(&upstream, "git init -q -b main && echo one > version && printf '.env\nnode_modules\n' > .gitignore && echo keep > storage/.gitignore && git add -A && git commit -qm one");
        sh(&root, "git clone -q upstream app");
        // Live state the app made: its .env and something in storage.
        std::fs::write(app.join(".env"), "SECRET=1\n").unwrap();
        std::fs::write(app.join("storage/log"), "line\n").unwrap();
        let one = sh(&upstream, "git rev-parse HEAD");
        sh(&upstream, "echo two > version && git commit -qam two");
        let two = sh(&upstream, "git rev-parse HEAD");
        sh(&upstream, "echo three > version && git commit -qam three");
        let three = sh(&upstream, "git rev-parse HEAD");

        let state = Arc::new(daemon_state::State::in_memory().unwrap());
        let (tx, _rx) = tokio::sync::mpsc::channel(4096);
        let progress = Progress::new(uuid::Uuid::new_v4(), state, tx, vec![]);
        let cancel = watch::channel(false).1;
        let user = AppUser {
            name: "test".into(),
            ids: None,
            home: root.clone(),
        };
        let reloads = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(false));
        let (counted, failing) = (reloads.clone(), fail.clone());
        let reload = move |_: daemon_protocol::ReleaseReload| -> crate::native::ReloadFuture {
            counted.fetch_add(1, Ordering::SeqCst);
            let fail = failing.swap(false, Ordering::SeqCst);
            Box::pin(async move {
                if fail {
                    Err(Failure::new("reload", "php won't reload"))
                } else {
                    Ok(())
                }
            })
        };
        let build = "cp version built && mkdir -p node_modules && cat .env >> seen";
        let releases = root.join("app-releases");
        let go = |s: ReleaseSpec| {
            let (progress, cancel, user, reload) = (&progress, cancel.clone(), &user, &reload);
            async move { release(progress, cancel, &s, user, reload).await }
        };

        // First release: the folder becomes the first kept release and a link.
        let done = go(spec(&app, &upstream, &two, build)).await.unwrap();
        assert!(std::fs::symlink_metadata(&app)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(done.previous.as_deref(), Some(one.as_str()));
        assert_eq!(read(app.join("built")), "two");
        assert_eq!(
            read(app.join("seen")),
            "SECRET=1",
            "the release sees the shared .env"
        );
        assert_eq!(
            read(app.join("storage/log")),
            "line",
            "storage carried over"
        );
        assert_eq!(read(releases.join("shared/.env")), "SECRET=1");
        let live_two = std::fs::read_link(&app).unwrap();
        assert_eq!(Some(live_two.display().to_string()), done.release);

        // A build that fails changes nothing.
        let failure = go(spec(&app, &upstream, &three, "exit 4"))
            .await
            .unwrap_err();
        assert!(failure.next_step.unwrap().starts_with("Nothing changed"));
        assert_eq!(std::fs::read_link(&app).unwrap(), live_two);
        assert_eq!(read(app.join("built")), "two");

        // A reload that fails after the switch switches straight back.
        fail.store(true, Ordering::SeqCst);
        let failure = go(spec(&app, &upstream, &three, build)).await.unwrap_err();
        assert_eq!(failure.phase, "reload");
        assert!(failure.next_step.unwrap().contains("is back on"));
        assert_eq!(std::fs::read_link(&app).unwrap(), live_two);

        // Three goes live; the release before it loses its node_modules.
        let done = go(spec(&app, &upstream, &three, build)).await.unwrap();
        assert!(!done.reused);
        assert_eq!(read(app.join("built")), "three");
        assert!(!live_two.join("node_modules").exists());

        // Going back to two is a switch, not a build.
        let before = reloads.load(Ordering::SeqCst);
        let back = go(spec(&app, &upstream, &two, "exit 9")).await.unwrap();
        assert!(back.reused && back.steps.is_empty());
        assert_eq!(std::fs::read_link(&app).unwrap(), live_two);
        assert_eq!(read(app.join("built")), "two");
        assert_eq!(reloads.load(Ordering::SeqCst), before + 1);

        // Only two releases are kept, plus what's shared.
        let mut left: Vec<String> = std::fs::read_dir(&releases)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left.len(), 4, "{left:?}");
        assert!(
            left.contains(&"shared".to_string()) && left.contains(&"releases.json".to_string())
        );
        assert!(!left.iter().any(|n| n.ends_with(&one[..12])), "{left:?}");
    }
}
