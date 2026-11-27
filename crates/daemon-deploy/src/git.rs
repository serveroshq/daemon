use std::path::{Path, PathBuf};
use std::time::Duration;

use daemon_jobs::{capture_child, run_child, Captured, ChildOutcome, Failure, Progress};
use serde::Serialize;
use tokio::sync::watch;

pub fn key_paths(keys_dir: &Path, service: &str) -> (PathBuf, PathBuf) {
    let private = keys_dir.join(sanitise(service));
    let public = keys_dir.join(format!("{}.pub", sanitise(service)));
    (private, public)
}

pub fn sanitise(service: &str) -> String {
    service
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

pub async fn ensure_deploy_key(
    keys_dir: &Path,
    service: &str,
    progress: &Progress,
) -> Result<String, Failure> {
    std::fs::create_dir_all(keys_dir).map_err(|e| {
        Failure::new(
            "deploy-key",
            format!("could not create {}: {e}", keys_dir.display()),
        )
    })?;
    let (private, public) = key_paths(keys_dir, service);

    if !private.exists() {
        let (_tx, mut cancel) = watch::channel(false);
        let comment = format!("serveros-{}", sanitise(service));
        let outcome = run_child(
            "ssh-keygen",
            &[
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                &comment,
                "-f",
                &private.to_string_lossy(),
            ],
            None,
            &[],
            Duration::from_secs(30),
            &mut cancel,
            progress,
            None,
        )
        .await;

        if !outcome.success() {
            return Err(Failure::new("deploy-key", "ssh-keygen failed")
                .with_output(outcome.tail().to_vec())
                .with_next_step("Install openssh-client on the machine."));
        }
    }

    std::fs::read_to_string(&public)
        .map(|k| k.trim().to_string())
        .map_err(|e| {
            Failure::new(
                "deploy-key",
                format!("could not read {}: {e}", public.display()),
            )
        })
}

/// How to authenticate a fetch: the machine's deploy key for an SSH
/// repository, or a token for a private HTTPS one.
#[derive(Clone, Copy, Default)]
pub struct Auth<'a> {
    pub deploy_key: Option<&'a Path>,
    pub token: Option<&'a str>,
}

/// The environment that gives git an `Authorization` header for the
/// repository's host, as actions/checkout does.
pub fn token_env(repo: &str, token: &str) -> Vec<(&'static str, String)> {
    let (key, value) = token_header(repo, token);
    vec![
        ("GIT_CONFIG_COUNT", "1".to_string()),
        ("GIT_CONFIG_KEY_0", key),
        ("GIT_CONFIG_VALUE_0", value),
    ]
}

/// The git setting that sends a token to the repository's host, and only
/// there: submodules on the same host get it too, others don't.
fn token_header(repo: &str, token: &str) -> (String, String) {
    use base64::Engine;

    let origin = repo
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .map(|host| format!("https://{host}/"))
        .unwrap_or_else(|| "https://github.com/".to_string());
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
    (
        format!("http.{origin}.extraheader"),
        format!("AUTHORIZATION: basic {basic}"),
    )
}

/// Everything git is given for a fetch, through its environment so none of
/// it lands in `.git/config`, a remote URL or the job's output: how to
/// reach SSH hosts, never to ask anything, and the token for HTTPS ones.
/// A repository on this machine (`file://`, for tests) may have submodules
/// on it too, which git refuses by default for remote ones.
pub(crate) fn git_env(repo: &str, auth: Auth<'_>) -> Vec<(String, String)> {
    let mut env = vec![
        ("GIT_SSH_COMMAND".to_string(), ssh_command(auth.deploy_key)),
        ("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()),
        // LFS files are fetched on purpose, after the checkout, when the
        // build wants them; a machine-wide git-lfs mustn't do it before.
        ("GIT_LFS_SKIP_SMUDGE".to_string(), "1".to_string()),
    ];
    let mut config = Vec::new();
    if let Some(token) = auth.token.filter(|t| !t.is_empty()) {
        if repo.starts_with("https://") {
            config.push(token_header(repo, token));
        }
    }
    if repo.starts_with("file://") {
        config.push(("protocol.file.allow".to_string(), "always".to_string()));
    }
    if !config.is_empty() {
        env.push(("GIT_CONFIG_COUNT".to_string(), config.len().to_string()));
        for (i, (key, value)) in config.into_iter().enumerate() {
            env.push((format!("GIT_CONFIG_KEY_{i}"), key));
            env.push((format!("GIT_CONFIG_VALUE_{i}"), value));
        }
    }
    env
}

fn is_ssh(repo: &str) -> bool {
    repo.starts_with("git@") || repo.starts_with("ssh://")
}

pub fn valid_commit(sha: &str) -> bool {
    (7..=64).contains(&sha.len()) && sha.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn valid_repo(url: &str) -> bool {
    !url.contains(char::is_whitespace)
        && !url.starts_with('-')
        && (url.starts_with("https://")
            || url.starts_with("ssh://")
            || url.starts_with("git@")
            || url.starts_with("file://"))
}

/// How git reaches an SSH repository: with the service's deploy key when
/// it has one, never asking anything (there's no one to answer).
fn ssh_command(deploy_key: Option<&Path>) -> String {
    match deploy_key {
        Some(key) => format!(
            "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o BatchMode=yes",
            key.to_string_lossy()
        ),
        None => "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new".into(),
    }
}

/// What to do about git failing to reach a repository, from what it said
/// and how it was asked: a deploy key only opens SSH addresses, and a
/// token only HTTPS ones.
pub(crate) fn reach_hint(repo: &str, has_token: bool, output: &[String]) -> &'static str {
    const REFUSED: &[&str] = &[
        "Permission denied",
        "could not read Username",
        "could not read Password",
        "Authentication failed",
        "terminal prompts disabled",
        "Access denied",
        "Repository not found",
        "returned error: 401",
        "returned error: 403",
    ];
    let refused = output
        .iter()
        .any(|l| REFUSED.iter().any(|needle| l.contains(needle)));
    if refused && is_ssh(repo) {
        "Add the machine's deploy key to the repository (Settings → Deploy keys)."
    } else if refused && has_token {
        "The git host refused ServerOS's access to this repository. Reconnect the git host in ServerOS, then try again."
    } else if refused {
        "If the repository is private, connect its git host in ServerOS, or use its SSH address and add the machine's deploy key."
    } else if output
        .iter()
        .any(|l| l.contains("couldn't find remote ref") || l.contains("not our ref"))
    {
        "The commit is not in the repository; push it first."
    } else {
        "Check the repository URL and the machine's network access."
    }
}

/// A branch or tag name git ls-remote can be given without it being read
/// as an option or a pattern for something else.
pub fn valid_ref(name: &str) -> bool {
    (1..=200).contains(&name.len())
        && !name.starts_with(['-', '/', '.'])
        && !name.ends_with(['/', '.'])
        && !name.ends_with(".lock")
        && !name.contains("..")
        && !name.contains("//")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

/// A full commit SHA (SHA-1, or SHA-256 for repositories that use it).
pub(crate) fn full_sha(name: &str) -> bool {
    matches!(name.len(), 40 | 64) && name.chars().all(|c| c.is_ascii_hexdigit())
}

/// The commit a ref resolved to, and the full name of the ref it matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedRef {
    pub commit: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
}

/// Picks the commit for `wanted` from git ls-remote's output: the ref of
/// exactly that name, then the branch, then the commit an annotated tag
/// points at, then the tag. Without a name, the default branch (HEAD),
/// named by the branch it points to when git says.
pub(crate) fn pick_ref(output: &[String], wanted: Option<&str>) -> Option<ResolvedRef> {
    let refs: Vec<(&str, &str)> = output
        .iter()
        .filter_map(|line| line.split_once('\t'))
        .filter(|(sha, _)| full_sha(sha))
        .collect();
    let find = |name: &str| {
        refs.iter()
            .find(|(_, r)| *r == name)
            .map(|(sha, _)| sha.to_ascii_lowercase())
    };

    let Some(wanted) = wanted else {
        let commit = find("HEAD")?;
        let branch = output
            .iter()
            .filter_map(|line| line.strip_prefix("ref: "))
            .filter_map(|line| line.split_once('\t'))
            .find(|(_, r)| *r == "HEAD")
            .map(|(target, _)| target.to_string());
        return Some(ResolvedRef {
            commit,
            git_ref: branch.unwrap_or_else(|| "HEAD".into()),
        });
    };

    let tag = format!("refs/tags/{wanted}");
    [
        (wanted.to_string(), wanted.to_string()),
        (
            format!("refs/heads/{wanted}"),
            format!("refs/heads/{wanted}"),
        ),
        (format!("{tag}^{{}}"), tag.clone()),
        (tag.clone(), tag),
    ]
    .into_iter()
    .find_map(|(line, name)| {
        find(&line).map(|commit| ResolvedRef {
            commit,
            git_ref: name,
        })
    })
}

/// The commit a branch or tag points at in `repo`, or the default branch
/// when there's no name, asked with git ls-remote over the deploy key (SSH)
/// or the token (HTTPS). A full SHA is already a commit, so it's given back
/// without asking.
pub async fn resolve_ref(
    repo: &str,
    git_ref: Option<&str>,
    auth: Auth<'_>,
    cancel: &mut watch::Receiver<bool>,
) -> Result<ResolvedRef, Failure> {
    if !valid_repo(repo) {
        return Err(Failure::new(
            "resolve",
            format!("{repo:?} is not a repository URL ServerOS will fetch from"),
        ));
    }
    let wanted = git_ref.map(str::trim).filter(|r| !r.is_empty());
    if let Some(name) = wanted {
        if full_sha(name) {
            return Ok(ResolvedRef {
                commit: name.to_ascii_lowercase(),
                git_ref: name.to_ascii_lowercase(),
            });
        }
        if !valid_ref(name) {
            return Err(Failure::new(
                "resolve",
                format!("{name:?} is not a branch or tag name"),
            ));
        }
    }

    let env = git_env(repo, auth);
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    // `--` ends the options, so neither the URL nor the name can be one.
    // git only lists an annotated tag's commit (`v1^{}`) when asked for it
    // by that name too.
    let peeled = wanted.map(|name| format!("{name}^{{}}"));
    let args = match (wanted, &peeled) {
        (Some(name), Some(peeled)) => vec!["ls-remote", "--", repo, name, peeled],
        _ => vec!["ls-remote", "--symref", "--", repo, "HEAD"],
    };
    let captured = capture_child("git", &args, &env, Duration::from_secs(30), cancel, 10_000).await;

    match captured {
        Captured::Exited {
            code: 0, stdout, ..
        } => pick_ref(&stdout, wanted).ok_or_else(|| match wanted {
            Some(name) => Failure::new("resolve", format!("no branch or tag called {name}"))
                .with_next_step("Check the name, or push the branch first."),
            None => Failure::new("resolve", "the repository has no default branch")
                .with_next_step("Push a commit to the repository first."),
        }),
        Captured::Exited { code, stderr, .. } => {
            let hint = reach_hint(repo, auth.token.is_some_and(|t| !t.is_empty()), &stderr);
            Err(
                Failure::new("resolve", format!("git ls-remote exited {code}"))
                    .with_output(stderr)
                    .with_next_step(hint),
            )
        }
        Captured::TimedOut => Err(Failure::new("resolve", "git ls-remote timed out")
            .with_next_step("Check the repository is reachable from this machine.")),
        Captured::Cancelled => Err(Failure::new(
            "cancelled",
            "cancelled while asking the repository",
        )),
        Captured::Unstartable(e) => {
            Err(Failure::new("resolve", e).with_next_step("Install git on the machine."))
        }
    }
}

/// What a fetch brings besides the commit's own files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchOptions {
    /// The repository's submodules, recursively, each at the commit the
    /// repository records, shallow.
    pub submodules: bool,
    /// Git LFS files, when the repository's `.gitattributes` uses LFS.
    pub lfs: bool,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            submodules: true,
            lfs: true,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn fetch(
    repo: &str,
    commit: &str,
    workspace: &Path,
    auth: Auth<'_>,
    options: FetchOptions,
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    if !valid_commit(commit) {
        return Err(Failure::new(
            "fetch",
            format!("{commit:?} is not a commit SHA; deploys pin to a commit, not a branch"),
        ));
    }

    if !valid_repo(repo) {
        return Err(Failure::new(
            "fetch",
            format!("{repo:?} is not a repository URL ServerOS will fetch from"),
        ));
    }

    std::fs::create_dir_all(workspace)
        .map_err(|e| Failure::new("fetch", format!("could not create workspace: {e}")))?;

    // A token for a private HTTPS repository goes in as an auth header
    // through git's environment (git 2.31+), so it's never in the remote
    // URL, .git/config or the job's output. Submodules and LFS are fetched
    // by child gits that inherit it.
    let env = git_env(repo, auth);
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let has_token = auth.token.is_some_and(|t| !t.is_empty());
    let git = Git {
        repo,
        has_token,
        workspace,
        env: &env,
        timeout,
    };

    git.run("init", &["init", "-q"], cancel, progress).await?;
    git.run(
        "remote",
        &["remote", "add", "origin", repo],
        cancel,
        progress,
    )
    .await?;
    git.run(
        "fetch",
        &["fetch", "-q", "--depth", "1", "origin", commit],
        cancel,
        progress,
    )
    .await?;
    git.run(
        "checkout",
        &["checkout", "-q", "FETCH_HEAD"],
        cancel,
        progress,
    )
    .await?;

    if options.submodules && workspace.join(".gitmodules").is_file() {
        progress.line("fetching the repository's submodules").await;
        git.run(
            "submodule update",
            &[
                "submodule",
                "update",
                "--init",
                "--recursive",
                "--depth",
                "1",
            ],
            cancel,
            progress,
        )
        .await?;
    }

    if options.lfs && uses_lfs(workspace) {
        ensure_lfs(cancel, progress).await?;
        progress
            .line("fetching the repository's Git LFS files")
            .await;
        git.run(
            "lfs install",
            &["lfs", "install", "--local"],
            cancel,
            progress,
        )
        .await?;
        git.run("lfs pull", &["lfs", "pull"], cancel, progress)
            .await?;
    }

    progress
        .line(format!("fetched {commit} into {}", workspace.display()))
        .await;

    Ok(())
}

/// One fetch's git commands: same repository, folder and settings.
struct Git<'a> {
    repo: &'a str,
    has_token: bool,
    workspace: &'a Path,
    env: &'a [(&'a str, &'a str)],
    timeout: Duration,
}

impl Git<'_> {
    async fn run(
        &self,
        name: &str,
        args: &[&str],
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        let outcome = run_child(
            "git",
            args,
            Some(self.workspace),
            self.env,
            self.timeout,
            cancel,
            progress,
            None,
        )
        .await;

        match outcome {
            ChildOutcome::Exited { code: 0, .. } => Ok(()),
            ChildOutcome::Cancelled { tail } => {
                Err(Failure::new("cancelled", "deploy cancelled during fetch").with_output(tail))
            }
            ChildOutcome::TimedOut { tail } => {
                Err(Failure::new("fetch", format!("git {name} timed out"))
                    .with_output(tail)
                    .with_next_step("Check the repository is reachable from this machine."))
            }
            ChildOutcome::Unstartable(e) => {
                Err(Failure::new("fetch", e).with_next_step("Install git on the machine."))
            }
            ChildOutcome::Exited { code, tail } => {
                let hint = reach_hint(self.repo, self.has_token, &tail);
                Err(Failure::new("fetch", format!("git {name} exited {code}"))
                    .with_output(tail)
                    .with_next_step(hint))
            }
        }
    }
}

/// How far down a checkout `.gitattributes` files are looked for, and how
/// many entries are read at most, so a huge repository can't stall it.
const ATTRIBUTES_DEPTH: usize = 6;
const ATTRIBUTES_ENTRIES: usize = 20_000;

/// Whether any `.gitattributes` in the checkout hands files to Git LFS.
pub fn uses_lfs(workspace: &Path) -> bool {
    let mut dirs = vec![(workspace.to_path_buf(), 0usize)];
    let mut seen = 0usize;
    while let Some((dir, depth)) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > ATTRIBUTES_ENTRIES {
                return false;
            }
            let name = entry.file_name();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                if depth < ATTRIBUTES_DEPTH && name != ".git" && name != "node_modules" {
                    dirs.push((entry.path(), depth + 1));
                }
            } else if kind.is_file()
                && name == ".gitattributes"
                && std::fs::read_to_string(entry.path()).is_ok_and(|text| attributes_use_lfs(&text))
            {
                return true;
            }
        }
    }
    false
}

fn attributes_use_lfs(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .any(|l| l.split_whitespace().skip(1).any(|a| a == "filter=lfs"))
}

/// git-lfs from the machine's own package manager, as the proxies are
/// installed, when it isn't there.
const LFS_INSTALL_SCRIPT: &str = r#"set -eu
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 update -q
  apt-get -o DPkg::Lock::Timeout=300 install -y -q git-lfs
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y git-lfs
elif command -v yum >/dev/null 2>&1; then
  yum install -y git-lfs
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache git-lfs
else
  echo "installing git-lfs needs apt, dnf, yum or apk" >&2
  exit 3
fi
"#;

static LFS_INSTALL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn ensure_lfs(
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    let _one_at_a_time = LFS_INSTALL.lock().await;
    let has_lfs = |cancel: &mut watch::Receiver<bool>| {
        let mut cancel = cancel.clone();
        async move {
            capture_child(
                "git",
                &["lfs", "version"],
                &[],
                Duration::from_secs(15),
                &mut cancel,
                5,
            )
            .await
            .code()
                == Some(0)
        }
    };
    if has_lfs(cancel).await {
        return Ok(());
    }

    progress
        .line("the repository uses Git LFS and git-lfs is not installed: installing it")
        .await;
    let outcome = run_child(
        "sh",
        &["-c", LFS_INSTALL_SCRIPT],
        None,
        &[],
        Duration::from_secs(600),
        cancel,
        progress,
        None,
    )
    .await;
    if outcome.success() && has_lfs(cancel).await {
        return Ok(());
    }
    Err(Failure::new(
        "fetch",
        "the repository uses Git LFS, and git-lfs couldn't be installed",
    )
    .with_output(outcome.tail().to_vec())
    .with_next_step(
        "Install git-lfs on the machine (git-lfs.com), or turn off Git LFS in the app's build settings, then deploy again.",
    ))
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_token_becomes_an_auth_header_for_the_repository_host_only() {
        let env = token_env("https://github.com/acme/private-app.git", "ghs_abc");
        assert_eq!(env[0], ("GIT_CONFIG_COUNT", "1".to_string()));
        assert_eq!(env[1].1, "http.https://github.com/.extraheader");
        // base64 of "x-access-token:ghs_abc"
        assert_eq!(
            env[2].1,
            "AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Z2hzX2FiYw=="
        );
        assert!(env.iter().all(|(_, v)| !v.contains("ghs_abc")));
    }

    #[test]
    fn a_repo_token_never_shows_in_debug_output() {
        let token = daemon_protocol::RepoToken("ghs_secret".into());
        assert_eq!(format!("{token:?}"), "RepoToken([redacted])");
    }

    use super::*;

    #[test]
    fn only_commit_shas_and_real_urls_are_accepted() {
        assert!(valid_commit("a1b2c3d"));
        assert!(valid_commit(&"f".repeat(40)));
        assert!(!valid_commit("main"));
        assert!(!valid_commit("HEAD~1"));

        assert!(valid_repo("git@github.com:serveroshq/app.git"));
        assert!(valid_repo("https://github.com/serveroshq/app.git"));
        assert!(!valid_repo("--upload-pack=evil"));
        assert!(!valid_repo("ftp://x"));
    }

    #[test]
    fn ref_names_cant_become_options() {
        for good in ["main", "release/2.1", "v1.0.0", "feature_x-y", "HEAD"] {
            assert!(valid_ref(good), "{good:?} was refused");
        }
        for bad in [
            "",
            "-u",
            "--upload-pack=evil",
            "main branch",
            "a..b",
            "/main",
            "main/",
            ".hidden",
            "x.lock",
            "a//b",
            "main\n",
            "ma*in",
            "v1^{}",
            "@{-1}",
            &"a".repeat(201),
        ] {
            assert!(!valid_ref(bad), "{bad:?} was accepted");
        }
    }

    #[test]
    fn picks_the_branch_then_the_peeled_tag_then_the_tag() {
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let c = "c".repeat(40);
        let d = "d".repeat(40);
        let lines = |rows: &[(&str, &str)]| -> Vec<String> {
            rows.iter().map(|(sha, r)| format!("{sha}\t{r}")).collect()
        };

        let out = lines(&[
            (&a, "refs/heads/feature/main"),
            (&b, "refs/heads/main"),
            (&c, "refs/tags/main"),
        ]);
        assert_eq!(
            pick_ref(&out, Some("main")),
            Some(ResolvedRef {
                commit: b.clone(),
                git_ref: "refs/heads/main".into()
            })
        );

        let out = lines(&[(&c, "refs/tags/v1.0"), (&d, "refs/tags/v1.0^{}")]);
        assert_eq!(
            pick_ref(&out, Some("v1.0")),
            Some(ResolvedRef {
                commit: d.clone(),
                git_ref: "refs/tags/v1.0".into()
            })
        );

        let out = lines(&[(&c, "refs/tags/v2")]);
        assert_eq!(pick_ref(&out, Some("v2")).unwrap().commit, c);

        // A partial match isn't a match.
        let out = lines(&[(&a, "refs/heads/feature/main")]);
        assert_eq!(pick_ref(&out, Some("main")), None);
        assert_eq!(pick_ref(&[], Some("main")), None);

        let out = vec![
            "ref: refs/heads/trunk\tHEAD".to_string(),
            format!("{a}\tHEAD"),
        ];
        assert_eq!(
            pick_ref(&out, None),
            Some(ResolvedRef {
                commit: a.clone(),
                git_ref: "refs/heads/trunk".into()
            })
        );
        assert_eq!(
            pick_ref(&lines(&[(&a, "HEAD")]), None).unwrap().git_ref,
            "HEAD"
        );
        assert_eq!(pick_ref(&lines(&[(&a, "refs/heads/main")]), None), None);
    }

    #[tokio::test]
    async fn a_full_sha_is_its_own_commit_and_bad_input_is_refused() {
        let (_tx, mut cancel) = watch::channel(false);
        let sha = "AB".repeat(20);
        let resolved = resolve_ref(
            "git@gitlab.com:a/b.git",
            Some(&sha),
            Auth::default(),
            &mut cancel,
        )
        .await
        .unwrap();
        assert_eq!(resolved.commit, "ab".repeat(20));

        let refused = resolve_ref(
            "git@gitlab.com:a/b.git",
            Some("--upload-pack=x"),
            Auth::default(),
            &mut cancel,
        )
        .await
        .unwrap_err();
        assert!(refused.message.contains("not a branch or tag"));
        assert!(
            resolve_ref("-oProxyCommand=x", None, Auth::default(), &mut cancel)
                .await
                .is_err()
        );

        assert_eq!(
            serde_json::to_value(&resolved).unwrap(),
            serde_json::json!({"commit": "ab".repeat(20), "ref": "ab".repeat(20)})
        );
    }

    #[tokio::test]
    async fn resolves_branches_and_tags_of_a_real_repository() {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.com")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.com")
                .output()
        };
        if git(&["init", "-q", "-b", "trunk"]).is_err() {
            return; // no git here
        }
        git(&["commit", "-q", "--allow-empty", "-m", "one"]).unwrap();
        git(&["tag", "-a", "v1", "-m", "v1"]).unwrap();
        let head = String::from_utf8(git(&["rev-parse", "HEAD"]).unwrap().stdout).unwrap();
        let head = head.trim();

        let repo = format!("file://{}", dir.path().display());
        let (_tx, mut cancel) = watch::channel(false);
        let branch = resolve_ref(&repo, Some("trunk"), Auth::default(), &mut cancel)
            .await
            .unwrap();
        assert_eq!(
            (branch.commit.as_str(), branch.git_ref.as_str()),
            (head, "refs/heads/trunk")
        );
        let tag = resolve_ref(&repo, Some("v1"), Auth::default(), &mut cancel)
            .await
            .unwrap();
        assert_eq!(
            (tag.commit.as_str(), tag.git_ref.as_str()),
            (head, "refs/tags/v1")
        );
        let default = resolve_ref(&repo, None, Auth::default(), &mut cancel)
            .await
            .unwrap();
        assert_eq!(default.commit, head);
        let missing = resolve_ref(&repo, Some("nope"), Auth::default(), &mut cancel)
            .await
            .unwrap_err();
        assert_eq!(missing.message, "no branch or tag called nope");
    }

    fn sh(dir: &Path, script: &str) -> String {
        let out = std::process::Command::new("sh")
            .args(["-c", script])
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "protocol.file.allow")
            .env("GIT_CONFIG_VALUE_0", "always")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn progress() -> Progress {
        let state = std::sync::Arc::new(daemon_state::State::in_memory().unwrap());
        let (tx, _rx) = tokio::sync::mpsc::channel(1024);
        Progress::new(uuid::Uuid::new_v4(), state, tx, vec![])
    }

    #[tokio::test]
    async fn fetches_submodules_recursively_unless_told_not_to() {
        if std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("lib")).unwrap();
        std::fs::create_dir_all(root.join("app")).unwrap();
        sh(
            &root.join("lib"),
            "git init -q -b main && echo lib > lib.txt && git add . && git commit -qm lib",
        );
        sh(
            &root.join("app"),
            "git init -q -b main && echo app > app.txt && git add app.txt && git submodule -q add ../lib vendor/lib && git commit -qm app",
        );
        let commit = sh(&root.join("app"), "git rev-parse HEAD");
        let repo = format!("file://{}", root.join("app").display());
        let (_tx, mut cancel) = watch::channel(false);

        let with = root.join("with");
        fetch(
            &repo,
            &commit,
            &with,
            Auth::default(),
            FetchOptions::default(),
            Duration::from_secs(60),
            &mut cancel,
            &progress(),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(with.join("app.txt")).unwrap(),
            "app\n"
        );
        assert_eq!(
            std::fs::read_to_string(with.join("vendor/lib/lib.txt")).unwrap(),
            "lib\n"
        );
        // Nothing of how it was fetched is kept in the checkout's config.
        let config = std::fs::read_to_string(with.join(".git/config")).unwrap();
        assert!(!config.contains("extraheader") && !config.contains("protocol"));

        let without = root.join("without");
        fetch(
            &repo,
            &commit,
            &without,
            Auth::default(),
            FetchOptions {
                submodules: false,
                lfs: false,
            },
            Duration::from_secs(60),
            &mut cancel,
            &progress(),
        )
        .await
        .unwrap();
        assert!(without.join("app.txt").is_file());
        assert!(!without.join("vendor/lib/lib.txt").exists());
    }

    #[test]
    fn lfs_is_only_fetched_for_repositories_that_use_it() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!uses_lfs(dir.path()));
        std::fs::write(dir.path().join(".gitattributes"), "*.sh text eol=lf\n").unwrap();
        assert!(!uses_lfs(dir.path()));
        std::fs::create_dir_all(dir.path().join("assets/models")).unwrap();
        std::fs::write(
            dir.path().join("assets/models/.gitattributes"),
            "# big files\n*.bin filter=lfs diff=lfs merge=lfs -text\n",
        )
        .unwrap();
        assert!(uses_lfs(dir.path()));
        // Not in git's own folder, though.
        let other = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(other.path().join(".git")).unwrap();
        std::fs::write(
            other.path().join(".git/.gitattributes"),
            "*.bin filter=lfs\n",
        )
        .unwrap();
        assert!(!uses_lfs(other.path()));
        assert!(!attributes_use_lfs("# *.bin filter=lfs\n"));
    }

    #[test]
    fn a_failed_reach_says_what_opens_that_kind_of_address() {
        let denied = vec!["git@github.com: Permission denied (publickey).".to_string()];
        assert!(reach_hint("git@github.com:acme/app.git", false, &denied).contains("deploy key"));

        let https = vec![
            "fatal: could not read Username for 'https://github.com': terminal prompts disabled"
                .to_string(),
        ];
        let hint = reach_hint("https://github.com/acme/app.git", false, &https);
        assert!(hint.contains("connect its git host"), "{hint}");
        assert!(hint.contains("SSH address"));
        let hint = reach_hint("https://github.com/acme/app.git", true, &https);
        assert!(hint.contains("Reconnect the git host"), "{hint}");

        let missing = vec!["fatal: couldn't find remote ref deadbeef".to_string()];
        assert!(reach_hint("https://x/y.git", false, &missing).contains("push it first"));
        for hint in [
            reach_hint("git@x:y.git", false, &denied),
            reach_hint("https://x/y.git", false, &https),
            reach_hint("https://x/y.git", true, &https),
        ] {
            assert!(!hint.contains('\u{2014}'));
        }
    }

    #[test]
    fn fetch_settings_go_through_the_environment_only() {
        let env = git_env(
            "https://gitlab.com/acme/app.git",
            Auth {
                deploy_key: None,
                token: Some("glpat-secret"),
            },
        );
        let get = |k: &str| {
            env.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("GIT_CONFIG_COUNT"), Some("1"));
        assert_eq!(
            get("GIT_CONFIG_KEY_0"),
            Some("http.https://gitlab.com/.extraheader")
        );
        assert!(env.iter().all(|(_, v)| !v.contains("glpat-secret")));
        assert_eq!(get("GIT_LFS_SKIP_SMUDGE"), Some("1"));
        assert_eq!(get("GIT_TERMINAL_PROMPT"), Some("0"));

        // A token is for HTTPS hosts; an SSH address doesn't get it.
        let ssh = git_env(
            "git@github.com:acme/app.git",
            Auth {
                deploy_key: Some(Path::new("/var/lib/serveros/keys/web")),
                token: Some("ghs_x"),
            },
        );
        assert!(ssh.iter().all(|(k, _)| k != "GIT_CONFIG_COUNT"));
        assert!(ssh
            .iter()
            .any(|(k, v)| k == "GIT_SSH_COMMAND" && v.contains("/var/lib/serveros/keys/web")));
    }

    #[test]
    fn key_paths_are_sanitised() {
        let (private, public) = key_paths(Path::new("/var/lib/serveros/keys"), "shop/web");

        assert_eq!(private, PathBuf::from("/var/lib/serveros/keys/shop-web"));
        assert_eq!(public, PathBuf::from("/var/lib/serveros/keys/shop-web.pub"));
    }
}
