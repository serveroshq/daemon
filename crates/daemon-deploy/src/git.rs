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
    use base64::Engine;

    let origin = repo
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .map(|host| format!("https://{host}/"))
        .unwrap_or_else(|| "https://github.com/".to_string());
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));

    vec![
        ("GIT_CONFIG_COUNT", "1".to_string()),
        ("GIT_CONFIG_KEY_0", format!("http.{origin}.extraheader")),
        (
            "GIT_CONFIG_VALUE_0",
            format!("AUTHORIZATION: basic {basic}"),
        ),
    ]
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

/// What to do about git failing to reach a repository, from what it said.
fn reach_hint(output: &[String]) -> &'static str {
    if output
        .iter()
        .any(|l| l.contains("Permission denied") || l.contains("could not read Username"))
    {
        "Add the machine's deploy key to the repository (Settings → Deploy keys)."
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
fn full_sha(name: &str) -> bool {
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
fn pick_ref(output: &[String], wanted: Option<&str>) -> Option<ResolvedRef> {
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
/// when there's no name, asked with git ls-remote over the deploy key. A
/// full SHA is already a commit, so it's given back without asking.
pub async fn resolve_ref(
    repo: &str,
    git_ref: Option<&str>,
    deploy_key: Option<&Path>,
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

    let ssh = ssh_command(deploy_key);
    let env = [
        ("GIT_SSH_COMMAND", ssh.as_str()),
        ("GIT_TERMINAL_PROMPT", "0"),
    ];
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
            let hint = reach_hint(&stderr);
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

pub async fn fetch(
    repo: &str,
    commit: &str,
    workspace: &Path,
    auth: Auth<'_>,
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

    let mut env = vec![
        ("GIT_SSH_COMMAND", ssh_command(auth.deploy_key)),
        ("GIT_TERMINAL_PROMPT", "0".to_string()),
    ];
    // A token for a private HTTPS repository goes in as an auth header
    // through git's environment (git 2.31+), so it's never in the remote
    // URL, .git/config or the job's output.
    if let Some(token) = auth.token.filter(|t| !t.is_empty()) {
        env.extend(token_env(repo, token));
    }
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let steps: [(&str, Vec<&str>); 4] = [
        ("init", vec!["init", "-q"]),
        ("remote", vec!["remote", "add", "origin", repo]),
        (
            "fetch",
            vec!["fetch", "-q", "--depth", "1", "origin", commit],
        ),
        ("checkout", vec!["checkout", "-q", "FETCH_HEAD"]),
    ];

    for (name, args) in steps {
        let outcome = run_child(
            "git",
            &args,
            Some(workspace),
            &env,
            timeout,
            cancel,
            progress,
            None,
        )
        .await;

        match outcome {
            ChildOutcome::Exited { code: 0, .. } => {}
            ChildOutcome::Cancelled { tail } => {
                return Err(
                    Failure::new("cancelled", "deploy cancelled during fetch").with_output(tail)
                )
            }
            ChildOutcome::TimedOut { tail } => {
                return Err(Failure::new("fetch", format!("git {name} timed out"))
                    .with_output(tail)
                    .with_next_step("Check the repository is reachable from this machine."))
            }
            ChildOutcome::Unstartable(e) => {
                return Err(Failure::new("fetch", e).with_next_step("Install git on the machine."))
            }
            ChildOutcome::Exited { code, tail } => {
                let hint = reach_hint(&tail);
                return Err(Failure::new("fetch", format!("git {name} exited {code}"))
                    .with_output(tail)
                    .with_next_step(hint));
            }
        }
    }

    progress
        .line(format!("fetched {commit} into {}", workspace.display()))
        .await;

    Ok(())
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
        let resolved = resolve_ref("git@gitlab.com:a/b.git", Some(&sha), None, &mut cancel)
            .await
            .unwrap();
        assert_eq!(resolved.commit, "ab".repeat(20));

        let refused = resolve_ref(
            "git@gitlab.com:a/b.git",
            Some("--upload-pack=x"),
            None,
            &mut cancel,
        )
        .await
        .unwrap_err();
        assert!(refused.message.contains("not a branch or tag"));
        assert!(resolve_ref("-oProxyCommand=x", None, None, &mut cancel)
            .await
            .is_err());

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
        let branch = resolve_ref(&repo, Some("trunk"), None, &mut cancel)
            .await
            .unwrap();
        assert_eq!(
            (branch.commit.as_str(), branch.git_ref.as_str()),
            (head, "refs/heads/trunk")
        );
        let tag = resolve_ref(&repo, Some("v1"), None, &mut cancel)
            .await
            .unwrap();
        assert_eq!(
            (tag.commit.as_str(), tag.git_ref.as_str()),
            (head, "refs/tags/v1")
        );
        let default = resolve_ref(&repo, None, None, &mut cancel).await.unwrap();
        assert_eq!(default.commit, head);
        let missing = resolve_ref(&repo, Some("nope"), None, &mut cancel)
            .await
            .unwrap_err();
        assert_eq!(missing.message, "no branch or tag called nope");
    }

    #[test]
    fn key_paths_are_sanitised() {
        let (private, public) = key_paths(Path::new("/var/lib/serveros/keys"), "shop/web");

        assert_eq!(private, PathBuf::from("/var/lib/serveros/keys/shop-web"));
        assert_eq!(public, PathBuf::from("/var/lib/serveros/keys/shop-web.pub"));
    }
}
