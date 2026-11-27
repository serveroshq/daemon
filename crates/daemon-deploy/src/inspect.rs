//! A repository's files at a commit, read without building anything, so the
//! panel can tell what kind of app it is on any git host (one it has no API
//! for, or a private one only this machine's deploy key opens).
//!
//! It's a shallow fetch of one commit into a throwaway folder, without a
//! checkout: a partial clone that leaves out files over 64 KB where the
//! server allows it, a plain shallow fetch where it doesn't. The file list
//! comes from git's tree, and the few small files that say how an app is
//! built are read from git's objects. The folder is always removed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use daemon_jobs::Failure;
use serde::Serialize;
use tokio::sync::watch;

use crate::git::{self, Auth};

/// How long an inspection may take in all.
pub const TIMEOUT: Duration = Duration::from_secs(60);
/// How deep the file list goes: `apps/web/package.json` is three.
pub const MAX_DEPTH: usize = 3;
pub const MAX_FILES: usize = 2000;
pub const MAX_CONTENTS: usize = 40;
pub const MAX_CONTENT_BYTES: u64 = 64 * 1024;
/// The most a git command's output is read, so a huge tree can't fill
/// memory.
const MAX_OUTPUT: usize = 32 * 1024 * 1024;

/// What an inspection found, as the `repo_inspect` job's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepoFiles {
    pub commit: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub default_branch: Option<String>,
    pub files: Vec<String>,
    pub contents: BTreeMap<String, String>,
    pub truncated: bool,
}

/// What to inspect. No Debug: it holds the token.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub repo: &'a str,
    pub git_ref: Option<&'a str>,
    pub base_dir: Option<&'a str>,
    pub auth: Auth<'a>,
}

/// The files that say how an app is built, read when they're in the app's
/// folder (the repository's root, or `base_dir`).
const CONTENT_NAMES: &[&str] = &[
    "package.json",
    "composer.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Gemfile",
    "go.mod",
    "Cargo.toml",
    "mix.exs",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "deno.json",
    "deno.jsonc",
    "Procfile",
    "Dockerfile",
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    "railpack.json",
    "nixpacks.toml",
    ".nvmrc",
    ".node-version",
    ".python-version",
    "runtime.txt",
    ".tool-versions",
    "index.html",
];

/// Name prefixes and suffixes of the other files read: `Dockerfile.dev`,
/// `api.Dockerfile`, `next.config.mjs`, `vite.config.ts`…
const CONTENT_PREFIXES: &[&str] = &[
    "Dockerfile.",
    "next.config.",
    "vite.config.",
    "nuxt.config.",
    "astro.config.",
    "svelte.config.",
];
const CONTENT_SUFFIXES: &[&str] = &[".Dockerfile"];

/// Where a file comes in reading order, if it's read at all: the named
/// files first, in the order above, then the patterns.
pub fn content_rank(name: &str) -> Option<usize> {
    if let Some(i) = CONTENT_NAMES.iter().position(|n| *n == name) {
        return Some(i);
    }
    let patterned = CONTENT_PREFIXES
        .iter()
        .any(|p| name.len() > p.len() && name.starts_with(p))
        || CONTENT_SUFFIXES
            .iter()
            .any(|s| name.len() > s.len() && name.ends_with(s));
    patterned.then_some(CONTENT_NAMES.len())
}

/// One entry of `git ls-tree -r -z`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub mode: String,
    pub kind: String,
    pub object: String,
    pub path: String,
}

pub(crate) fn parse_tree(output: &[u8]) -> Vec<Entry> {
    output
        .split(|b| *b == 0)
        .filter(|e| !e.is_empty())
        .filter_map(|entry| {
            let entry = String::from_utf8_lossy(entry);
            let (meta, path) = entry.split_once('\t')?;
            let mut meta = meta.split(' ');
            Some(Entry {
                mode: meta.next()?.to_string(),
                kind: meta.next()?.to_string(),
                object: meta.next()?.to_string(),
                path: path.to_string(),
            })
        })
        .collect()
}

/// The files to list (up to three folders deep, at most 2000) and whether
/// there were more.
pub(crate) fn listed(entries: &[Entry]) -> (Vec<String>, bool) {
    let mut files = Vec::new();
    let mut truncated = false;
    for entry in entries.iter().filter(|e| e.kind == "blob") {
        if entry.path.split('/').count() > MAX_DEPTH {
            continue;
        }
        if files.len() == MAX_FILES {
            truncated = true;
            break;
        }
        files.push(entry.path.clone());
    }
    (files, truncated)
}

/// The top-level files whose contents are read, in reading order, at most
/// 40. Links aren't read: their content is where they point.
pub(crate) fn to_read(entries: &[Entry]) -> Vec<&Entry> {
    let mut wanted: Vec<(usize, &Entry)> = entries
        .iter()
        .filter(|e| e.kind == "blob" && e.mode != "120000" && !e.path.contains('/'))
        .filter_map(|e| content_rank(&e.path).map(|rank| (rank, e)))
        .collect();
    wanted.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.path.cmp(&b.1.path)));
    wanted
        .into_iter()
        .take(MAX_CONTENTS)
        .map(|(_, e)| e)
        .collect()
}

/// `refs/heads/main` → `main`.
fn short_ref(name: &str) -> &str {
    name.strip_prefix("refs/heads/")
        .or_else(|| name.strip_prefix("refs/tags/"))
        .unwrap_or(name)
}

/// The default branch git ls-remote --symref named for HEAD.
pub(crate) fn default_branch(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .filter_map(|l| l.strip_prefix("ref: "))
        .filter_map(|l| l.split_once('\t'))
        .find(|(_, r)| *r == "HEAD")
        .map(|(target, _)| short_ref(target).to_string())
}

/// A git command's raw output, or what it said on failure.
struct Output {
    ok: bool,
    stdout: Vec<u8>,
    stderr: Vec<String>,
}

async fn git_raw(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Result<Output, Failure> {
    use tokio::io::AsyncReadExt;

    let mut command = tokio::process::Command::new("git");
    command
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LC_ALL", "C.UTF-8")
        .env("HOME", "/var/lib/serveros")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|e| {
        Failure::new("inspect", format!("could not start git: {e}"))
            .with_next_step("Install git on the machine.")
    })?;

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let read_out = async {
        let mut buf = Vec::new();
        if let Some(out) = stdout.as_mut() {
            let _ = out.take(MAX_OUTPUT as u64).read_to_end(&mut buf).await;
        }
        buf
    };
    let read_err = async {
        let mut buf = Vec::new();
        if let Some(err) = stderr.as_mut() {
            let _ = err.take(64 * 1024).read_to_end(&mut buf).await;
        }
        buf
    };
    let (out, err) = tokio::join!(read_out, read_err);
    // Past the cap, closing the pipe stops git rather than leaving it
    // waiting to write.
    drop(stdout);
    drop(stderr);
    let status = child
        .wait()
        .await
        .map_err(|e| Failure::new("inspect", e.to_string()))?;
    let stderr: Vec<String> = String::from_utf8_lossy(&err)
        .lines()
        .rev()
        .take(20)
        .map(str::to_string)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Ok(Output {
        ok: status.success(),
        stdout: out,
        stderr,
    })
}

/// Removes the inspection's folder however it ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Inspects `request` in `dir` (made for it and removed after), giving up
/// after a minute or when cancelled.
pub async fn inspect(
    dir: &Path,
    request: Request<'_>,
    cancel: &mut watch::Receiver<bool>,
) -> Result<RepoFiles, Failure> {
    let scratch = Scratch(dir.to_path_buf());
    let _ = std::fs::remove_dir_all(&scratch.0);
    std::fs::create_dir_all(&scratch.0)
        .map_err(|e| Failure::new("inspect", format!("could not create a folder for it: {e}")))?;

    let cancelled = async {
        loop {
            if *cancel.borrow() {
                return;
            }
            if cancel.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    };
    let result = tokio::select! {
        result = tokio::time::timeout(TIMEOUT, run(&scratch.0, request)) => match result {
            Ok(result) => result,
            Err(_) => Err(Failure::new("inspect", "reading the repository took over a minute")
                .with_next_step("Check the repository is reachable from this machine, then try again.")),
        },
        _ = cancelled => Err(Failure::new("cancelled", "cancelled while reading the repository")),
    };
    drop(scratch);
    result
}

async fn run(dir: &Path, request: Request<'_>) -> Result<RepoFiles, Failure> {
    let repo = request.repo;
    if !git::valid_repo(repo) {
        return Err(Failure::new(
            "inspect",
            format!("{repo:?} is not a repository URL ServerOS will fetch from"),
        ));
    }
    let wanted = request.git_ref.map(str::trim).filter(|r| !r.is_empty());
    if let Some(name) = wanted {
        if !git::full_sha(name) && !git::valid_ref(name) {
            return Err(Failure::new(
                "inspect",
                format!("{name:?} is not a branch or tag name"),
            ));
        }
    }
    let base_dir = match request.base_dir.map(str::trim).filter(|d| !d.is_empty()) {
        Some(dir) => Some(
            crate::deployer::base_dir_path(dir.trim_end_matches('/'))?
                .to_string_lossy()
                .into_owned(),
        ),
        None => None,
    };

    let env = git::git_env(repo, request.auth);
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let has_token = request.auth.token.is_some_and(|t| !t.is_empty());
    let refused = |what: &str, output: Output| {
        let hint = git::reach_hint(repo, has_token, &output.stderr);
        Failure::new("inspect", format!("git {what} failed"))
            .with_output(output.stderr)
            .with_next_step(hint)
    };

    // The commit, and the default branch, in one ask.
    let peeled = wanted.map(|name| format!("{name}^{{}}"));
    let mut args = vec!["ls-remote", "--symref", "--", repo, "HEAD"];
    if let (Some(name), Some(peeled)) = (wanted, &peeled) {
        if !git::full_sha(name) {
            args.extend([name, peeled.as_str()]);
        }
    }
    let listed_refs = git_raw(dir, &args, &env).await?;
    if !listed_refs.ok {
        return Err(refused("ls-remote", listed_refs));
    }
    let lines: Vec<String> = String::from_utf8_lossy(&listed_refs.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    let default_branch = default_branch(&lines);
    let (commit, git_ref) = match wanted {
        Some(sha) if git::full_sha(sha) => (sha.to_ascii_lowercase(), sha.to_ascii_lowercase()),
        _ => {
            let resolved = git::pick_ref(&lines, wanted).ok_or_else(|| match wanted {
                Some(name) => Failure::new("inspect", format!("no branch or tag called {name}"))
                    .with_next_step("Check the name, or push the branch first."),
                None => Failure::new("inspect", "the repository has no commits yet")
                    .with_next_step("Push a commit to the repository first."),
            })?;
            let name = match wanted {
                Some(_) => short_ref(&resolved.git_ref).to_string(),
                None => default_branch.clone().unwrap_or_else(|| "HEAD".into()),
            };
            (resolved.commit, name)
        }
    };

    // Just the one commit, and only its small files where the server will
    // leave the rest out.
    for (step, args) in [
        ("init", vec!["init", "-q"]),
        ("remote", vec!["remote", "add", "origin", repo]),
    ] {
        let out = git_raw(dir, &args, &env).await?;
        if !out.ok {
            return Err(refused(step, out));
        }
    }
    let filtered = git_raw(
        dir,
        &[
            "fetch",
            "-q",
            "--depth",
            "1",
            "--filter=blob:limit=64k",
            "origin",
            &commit,
        ],
        &env,
    )
    .await?;
    if !filtered.ok {
        let plain = git_raw(
            dir,
            &["fetch", "-q", "--depth", "1", "origin", &commit],
            &env,
        )
        .await?;
        if !plain.ok {
            return Err(refused("fetch", plain));
        }
    }
    // Without its remote, git won't go back for a file the fetch left out;
    // asking for one just fails.
    let _ = git_raw(dir, &["remote", "remove", "origin"], &env).await?;

    let tree = match &base_dir {
        Some(base) => format!("{commit}:{base}"),
        None => commit.clone(),
    };
    let listing = git_raw(dir, &["ls-tree", "-r", "-z", &tree], &env).await?;
    if !listing.ok {
        return Err(match &base_dir {
            Some(base) => Failure::new(
                "inspect",
                format!(
                    "{base} isn't a folder in the repository at {}",
                    &commit[..7.min(commit.len())]
                ),
            )
            .with_next_step("Check the app's folder, or push the commit that adds it."),
            None => refused("ls-tree", listing),
        });
    }
    let entries = parse_tree(&listing.stdout);
    let (files, mut truncated) = listed(&entries);
    if listing.stdout.len() >= MAX_OUTPUT {
        truncated = true;
    }

    let mut contents = BTreeMap::new();
    for entry in to_read(&entries) {
        let size = git_raw(dir, &["cat-file", "-s", &entry.object], &env).await?;
        let size: Option<u64> = size
            .ok
            .then(|| String::from_utf8_lossy(&size.stdout).trim().parse().ok())
            .flatten();
        if !size.is_some_and(|s| s <= MAX_CONTENT_BYTES) {
            continue;
        }
        let blob = git_raw(dir, &["cat-file", "blob", &entry.object], &env).await?;
        if !blob.ok {
            continue;
        }
        if let Ok(text) = String::from_utf8(blob.stdout) {
            contents.insert(entry.path.clone(), text);
        }
    }

    Ok(RepoFiles {
        commit,
        git_ref,
        default_branch,
        files,
        contents,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_files_that_say_how_an_app_is_built() {
        for name in [
            "package.json",
            "Dockerfile",
            "Dockerfile.dev",
            "api.Dockerfile",
            "compose.yaml",
            "docker-compose.yml",
            ".env.example",
            "next.config.mjs",
            "vite.config.ts",
            "svelte.config.js",
            "index.html",
            "build.gradle.kts",
            ".tool-versions",
        ] {
            assert!(content_rank(name).is_some(), "{name}");
        }
        for name in [
            "README.md",
            "package-lock.json",
            ".env",
            "Dockerfile.",
            "next.config",
            "src",
        ] {
            assert!(content_rank(name).is_none(), "{name}");
        }
    }

    #[test]
    fn lists_files_three_folders_deep_and_reads_only_top_level_ones() {
        let raw = b"100644 blob aaa\tpackage.json\x00100644 blob bbb\tsrc/index.ts\x00100644 blob ccc\tapps/web/package.json\x00100644 blob ddd\tapps/web/src/main.ts\x00160000 commit eee\tvendor/lib\x00120000 blob fff\tDockerfile\x00100644 blob ggg\tvite.config.ts\x00";
        let entries = parse_tree(raw);
        assert_eq!(entries.len(), 7);
        assert_eq!(entries[1].path, "src/index.ts");
        let (files, truncated) = listed(&entries);
        assert_eq!(
            files,
            [
                "package.json",
                "src/index.ts",
                "apps/web/package.json",
                "Dockerfile",
                "vite.config.ts"
            ]
        );
        assert!(!truncated);
        let read: Vec<&str> = to_read(&entries).iter().map(|e| e.path.as_str()).collect();
        assert_eq!(read, ["package.json", "vite.config.ts"]);

        let many: Vec<Entry> = (0..MAX_FILES + 5)
            .map(|i| Entry {
                mode: "100644".into(),
                kind: "blob".into(),
                object: "x".into(),
                path: format!("f{i}"),
            })
            .collect();
        let (files, truncated) = listed(&many);
        assert_eq!(files.len(), MAX_FILES);
        assert!(truncated);
    }

    #[test]
    fn names_the_default_branch() {
        let lines = vec![
            "ref: refs/heads/trunk\tHEAD".to_string(),
            format!("{}\tHEAD", "a".repeat(40)),
        ];
        assert_eq!(default_branch(&lines).as_deref(), Some("trunk"));
        assert_eq!(default_branch(&[]), None);
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

    #[tokio::test]
    async fn inspects_a_real_repository_with_and_without_partial_clones() {
        if std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let upstream = dir.path().join("upstream");
        std::fs::create_dir_all(&upstream).unwrap();
        sh(
            &upstream,
            r#"git init -q -b main
               echo '{"name":"shop","scripts":{"start":"node index.js"}}' > package.json
               echo 'console.log(1)' > index.js
               mkdir -p apps/web/src
               echo '{"name":"web"}' > apps/web/package.json
               echo x > apps/web/src/deep.ts
               head -c 100000 /dev/zero | tr '\0' 'a' > index.html
               printf 'FROM node:22\n' > Dockerfile.dev
               git add -A && git commit -qm one && git tag v1"#,
        );
        let head = sh(&upstream, "git rev-parse HEAD");
        let repo = format!("file://{}", upstream.display());
        let (_tx, mut cancel) = watch::channel(false);

        for filter in ["false", "true"] {
            sh(
                &upstream,
                &format!("git config uploadpack.allowFilter {filter}"),
            );
            let scratch = dir.path().join(format!("inspect-{filter}"));
            let found = inspect(
                &scratch,
                Request {
                    repo: &repo,
                    git_ref: None,
                    base_dir: None,
                    auth: Auth::default(),
                },
                &mut cancel,
            )
            .await
            .unwrap();
            assert!(!scratch.exists(), "the folder is removed");
            assert_eq!(found.commit, head);
            assert_eq!(found.git_ref, "main");
            assert_eq!(found.default_branch.as_deref(), Some("main"));
            assert!(found.files.contains(&"apps/web/package.json".to_string()));
            assert!(!found.files.contains(&"apps/web/src/deep.ts".to_string()));
            assert!(found.contents["package.json"].contains("node index.js"));
            assert_eq!(found.contents["Dockerfile.dev"], "FROM node:22\n");
            // Over 64 KB: listed, not read.
            assert!(found.files.contains(&"index.html".to_string()));
            assert!(!found.contents.contains_key("index.html"));
            assert!(!found.truncated);
        }

        let tagged = inspect(
            &dir.path().join("tagged"),
            Request {
                repo: &repo,
                git_ref: Some("v1"),
                base_dir: Some("apps/web"),
                auth: Auth::default(),
            },
            &mut cancel,
        )
        .await
        .unwrap();
        assert_eq!(tagged.commit, head);
        assert_eq!(tagged.git_ref, "v1");
        assert_eq!(tagged.files, ["package.json", "src/deep.ts"]);
        assert_eq!(tagged.contents["package.json"].trim(), r#"{"name":"web"}"#);

        let missing = inspect(
            &dir.path().join("missing"),
            Request {
                repo: &repo,
                git_ref: None,
                base_dir: Some("apps/api"),
                auth: Auth::default(),
            },
            &mut cancel,
        )
        .await
        .unwrap_err();
        assert!(missing.message.contains("apps/api isn't a folder"));
        assert!(!dir.path().join("missing").exists());

        let nope = inspect(
            &dir.path().join("nope"),
            Request {
                repo: &repo,
                git_ref: Some("nope"),
                base_dir: None,
                auth: Auth::default(),
            },
            &mut cancel,
        )
        .await
        .unwrap_err();
        assert_eq!(nope.message, "no branch or tag called nope");

        for bad in [
            Request {
                repo: "--upload-pack=x",
                git_ref: None,
                base_dir: None,
                auth: Auth::default(),
            },
            Request {
                repo: &repo,
                git_ref: Some("-x"),
                base_dir: None,
                auth: Auth::default(),
            },
            Request {
                repo: &repo,
                git_ref: None,
                base_dir: Some("../etc"),
                auth: Auth::default(),
            },
        ] {
            assert!(inspect(&dir.path().join("bad"), bad, &mut cancel)
                .await
                .is_err());
        }

        let json = serde_json::to_value(&tagged).unwrap();
        assert_eq!(json["ref"], "v1");
        assert_eq!(json["default_branch"], "main");
        assert!(json["contents"].is_object() && json["files"].is_array());
    }
}
