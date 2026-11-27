//! Reading why a build or pull failed from what Docker printed, so the
//! failure says which step broke and what it said, in plain words, instead
//! of "docker build exited 1".

use daemon_jobs::{ChildOutcome, Failure};

/// What a failed build printed that says why.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BuildError {
    /// The step that failed: `[3/4] RUN npm ci`, or `Step 7/12 : RUN npm ci`
    /// from Docker's classic builder.
    pub step: Option<String>,
    /// The error Docker ends with, without its `ERROR: failed to solve:`
    /// wrapping.
    pub error: Option<String>,
    /// The failing step's last lines of output that look like errors.
    pub lines: Vec<String>,
}

/// How many of the step's own lines a failure repeats.
const KEPT_LINES: usize = 3;
const MAX_LINE: usize = 200;

/// Reads BuildKit's plain progress output (`#6 [2/3] RUN npm ci`, then
/// `#6 ERROR: …` and a `------` block of the step's output), or the
/// classic builder's (`Step 2/3 : RUN npm ci` … `returned a non-zero code`).
pub fn parse(output: &[String]) -> BuildError {
    // The last top-level ERROR line is what the build died of.
    let error = output
        .iter()
        .rev()
        .find_map(|l| l.trim().strip_prefix("ERROR: "))
        .map(unwrap_error)
        .or_else(|| {
            output.iter().rev().find_map(|l| {
                let l = l.trim();
                (l.starts_with("The command '") && l.contains("returned a non-zero code"))
                    .then(|| l.to_string())
            })
        });
    let mut found = BuildError {
        error,
        ..BuildError::default()
    };

    // BuildKit: `#N ERROR: …` names the vertex that failed; its first line
    // `#N <name>` says what it was.
    let failed_vertex = output.iter().rev().find_map(|l| {
        let rest = l.trim().strip_prefix('#')?;
        let (id, rest) = rest.split_once(' ')?;
        (id.chars().all(|c| c.is_ascii_digit()) && rest.starts_with("ERROR"))
            .then(|| id.to_string())
    });
    if let Some(id) = &failed_vertex {
        let prefix = format!("#{id} ");
        found.step = output.iter().find_map(|l| {
            let rest = l.trim().strip_prefix(&prefix)?;
            is_vertex_name(rest).then(|| rest.trim().to_string())
        });
    }

    // The summary block BuildKit prints after a failure:
    //   ------
    //    > [2/3] RUN npm ci:
    //   0.345 npm error code ENOENT
    //   ------
    let mut block: Option<(String, Vec<String>)> = None;
    let mut blocks = Vec::new();
    for line in output {
        let trimmed = line.trim_end();
        if let Some((name, lines)) = block.as_mut() {
            if trimmed.trim() == "------" {
                blocks.push((std::mem::take(name), std::mem::take(lines)));
                block = None;
            } else {
                lines.push(strip_timestamp(trimmed.trim()).to_string());
            }
            continue;
        }
        if let Some(name) = trimmed.trim_start().strip_prefix("> ") {
            if let Some(name) = name.strip_suffix(':') {
                block = Some((name.trim().to_string(), Vec::new()));
            }
        }
    }
    if let Some((name, lines)) = block {
        blocks.push((name, lines));
    }
    if let Some((name, lines)) = blocks.pop() {
        if found.step.is_none() && !name.is_empty() {
            found.step = Some(name);
        }
        found.lines = error_lines(&lines);
    }

    // The classic builder.
    if found.step.is_none() {
        found.step = output.iter().rev().find_map(|l| {
            l.trim()
                .strip_prefix("Step ")
                .map(|s| format!("Step {}", s.trim()))
        });
    }
    if found.lines.is_empty() && failed_vertex.is_some() {
        let prefix = format!("#{} ", failed_vertex.unwrap_or_default());
        let lines: Vec<String> = output
            .iter()
            .filter_map(|l| l.trim().strip_prefix(&prefix))
            .filter(|rest| !rest.starts_with("ERROR") && !is_vertex_name(rest))
            .map(|rest| strip_timestamp(rest).to_string())
            .collect();
        found.lines = error_lines(&lines);
    }

    found
}

/// A vertex's own name line, rather than its output (`#6 0.345 …`) or its
/// status (`#6 DONE 0.1s`, `#6 CACHED`).
fn is_vertex_name(rest: &str) -> bool {
    let rest = rest.trim();
    let first = rest.split_whitespace().next().unwrap_or("");
    !rest.is_empty()
        && !matches!(first, "DONE" | "CACHED" | "ERROR" | "ERROR:" | "CANCELED")
        && !first.chars().next().is_some_and(|c| c.is_ascii_digit())
        && !rest.starts_with("sha256:")
        && !rest.starts_with("transferring")
        && !rest.starts_with("resolve ")
        && !rest.starts_with("extracting ")
        && !rest.starts_with("naming to")
        && !rest.starts_with("writing image")
        && !rest.starts_with("exporting ")
}

/// `0.345 npm error …` → `npm error …`.
fn strip_timestamp(line: &str) -> &str {
    match line.split_once(' ') {
        Some((stamp, rest))
            if !stamp.is_empty()
                && stamp.contains('.')
                && stamp.chars().all(|c| c.is_ascii_digit() || c == '.') =>
        {
            rest
        }
        _ => line,
    }
}

/// `failed to build: failed to solve: process "/bin/sh -c npm ci" did not
/// complete successfully: exit code: 254` → `process "/bin/sh -c npm ci"
/// did not complete successfully: exit code: 254`.
fn unwrap_error(error: &str) -> String {
    let mut error = error.trim();
    loop {
        let before = error;
        for wrapper in ["failed to build: ", "failed to solve: ", "error: "] {
            if let Some(rest) = error.strip_prefix(wrapper) {
                error = rest;
            }
        }
        if error == before {
            break;
        }
    }
    error.to_string()
}

/// The lines of a step's output worth repeating: those that mention an
/// error, else its last ones.
fn error_lines(lines: &[String]) -> Vec<String> {
    let lines: Vec<&str> = lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    let errors: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| {
            let lower = l.to_ascii_lowercase();
            lower.contains("error") || lower.contains("not found") || lower.contains("cannot")
        })
        .collect();
    let chosen = if errors.is_empty() { lines } else { errors };
    let skip = chosen.len().saturating_sub(KEPT_LINES);
    chosen
        .into_iter()
        .skip(skip)
        .map(|l| shorten(l, MAX_LINE))
        .collect()
}

fn shorten(line: &str, max: usize) -> String {
    if line.chars().count() <= max {
        return line.to_string();
    }
    let mut cut: String = line.chars().take(max).collect();
    cut.push_str("...");
    cut
}

/// The exit code in BuildKit's `did not complete successfully: exit code: 1`.
fn exit_code_of(error: &str) -> Option<&str> {
    error
        .rsplit_once("exit code: ")
        .map(|(_, code)| code.trim())
        .filter(|code| code.chars().all(|c| c.is_ascii_digit()) && !code.is_empty())
}

/// Whether Docker Hub refused a pull for going over its limit.
pub fn rate_limited(output: &[String]) -> bool {
    output.iter().any(|l| {
        l.contains("toomanyrequests")
            || l.contains("You have reached your pull rate limit")
            || l.contains("429 Too Many Requests")
    })
}

fn out_of_space(output: &[String]) -> bool {
    output.iter().any(|l| l.contains("no space left on device"))
}

pub fn rate_limit_failure(phase: &str, tail: Vec<String>) -> Failure {
    Failure::new(phase, "Docker Hub's pull limit was reached")
        .with_output(tail)
        .with_next_step(
            "Docker Hub limits how many images a machine can pull without signing in. Add a Docker Hub login to the app's registry settings in ServerOS, or wait a few hours and deploy again.",
        )
}

pub fn out_of_space_failure(phase: &str, tail: Vec<String>) -> Failure {
    Failure::new(phase, "the machine ran out of disk space")
        .with_output(tail)
        .with_next_step(
            "Free some space: remove images nothing uses from the machine's Docker page in ServerOS, or resize the disk. Then deploy again.",
        )
}

/// A failed build as a failure that names the step that broke and what it
/// said. `what` is the command, like "docker build".
pub fn build_failure(phase: &str, outcome: ChildOutcome, what: &str) -> Failure {
    match outcome {
        ChildOutcome::Exited { code, tail } => {
            if rate_limited(&tail) {
                return rate_limit_failure(phase, tail);
            }
            if out_of_space(&tail) {
                return out_of_space_failure(phase, tail);
            }
            let parsed = parse(&tail);
            let message = match (&parsed.step, &parsed.error) {
                (Some(step), Some(error)) => match exit_code_of(error) {
                    Some(code) => format!("{what} failed at {step} (exit code {code})"),
                    None => format!("{what} failed at {step}: {}", shorten(error, MAX_LINE)),
                },
                (Some(step), None) => format!("{what} failed at {step}, exited {code}"),
                (None, Some(error)) => format!("{what} failed: {}", shorten(error, MAX_LINE)),
                (None, None) => format!("{what} exited {code}"),
            };
            let next = if parsed.lines.is_empty() {
                "Fix the build locally, push, and redeploy.".to_string()
            } else {
                format!(
                    "It printed: {}. Fix the build locally, push, and redeploy.",
                    parsed.lines.join(" / ").trim_end_matches('.')
                )
            };
            Failure::new(phase, message)
                .with_output(tail)
                .with_next_step(next)
        }
        ChildOutcome::TimedOut { tail } => Failure::new(phase, format!("{what} timed out"))
            .with_output(tail)
            .with_next_step("Raise the job timeout or reduce the build."),
        ChildOutcome::Cancelled { tail } => {
            Failure::new("cancelled", format!("{what} cancelled")).with_output(tail)
        }
        ChildOutcome::Unstartable(e) => Failure::new(phase, e)
            .with_next_step("Install Docker from the machine's page in ServerOS."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_string).collect()
    }

    const BUILDKIT_RUN: &str = r#"#5 [1/3] FROM docker.io/library/node:22@sha256:abc
#5 CACHED

#6 [2/3] COPY . .
#6 DONE 0.1s

#7 [3/3] RUN npm ci
#7 0.512 npm error code ENOENT
#7 0.513 npm error syscall open
#7 0.513 npm error path /app/package.json
#7 0.520 npm error A complete log of this run can be found in: /root/.npm/_logs/x.log
#7 ERROR: process "/bin/sh -c npm ci" did not complete successfully: exit code: 254
------
 > [3/3] RUN npm ci:
0.512 npm error code ENOENT
0.513 npm error syscall open
0.513 npm error path /app/package.json
0.520 npm error A complete log of this run can be found in: /root/.npm/_logs/x.log
------
Dockerfile:3
--------------------
   1 |     FROM node:22
   2 |     COPY . .
   3 | >>> RUN npm ci
   4 |
--------------------
ERROR: failed to build: failed to solve: process "/bin/sh -c npm ci" did not complete successfully: exit code: 254"#;

    #[test]
    fn finds_the_failing_step_and_what_it_said_in_buildkit_output() {
        let parsed = parse(&lines(BUILDKIT_RUN));
        assert_eq!(parsed.step.as_deref(), Some("[3/3] RUN npm ci"));
        assert_eq!(
            parsed.error.as_deref(),
            Some(r#"process "/bin/sh -c npm ci" did not complete successfully: exit code: 254"#)
        );
        assert_eq!(
            parsed.lines,
            [
                "npm error syscall open",
                "npm error path /app/package.json",
                "npm error A complete log of this run can be found in: /root/.npm/_logs/x.log"
            ]
        );

        let failure = build_failure(
            "build",
            ChildOutcome::Exited {
                code: 1,
                tail: lines(BUILDKIT_RUN),
            },
            "docker build",
        );
        assert_eq!(
            failure.message,
            "docker build failed at [3/3] RUN npm ci (exit code 254)"
        );
        let next = failure.next_step.unwrap();
        assert!(next.starts_with("It printed: npm error syscall open / "));
        assert!(next.ends_with("Fix the build locally, push, and redeploy."));
        assert!(!next.contains('\u{2014}'));
    }

    #[test]
    fn a_missing_base_image_names_the_lookup_that_failed() {
        let out = lines(
            r#"#2 [internal] load metadata for docker.io/library/node:99
#2 ERROR: docker.io/library/node:99: not found
------
 > [internal] load metadata for docker.io/library/node:99:
------
Dockerfile:1
ERROR: failed to solve: node:99: failed to resolve source metadata for docker.io/library/node:99: docker.io/library/node:99: not found"#,
        );
        let failure = build_failure(
            "build",
            ChildOutcome::Exited { code: 1, tail: out },
            "docker build",
        );
        assert_eq!(
            failure.message,
            "docker build failed at [internal] load metadata for docker.io/library/node:99: node:99: failed to resolve source metadata for docker.io/library/node:99: docker.io/library/node:99: not found"
        );
    }

    #[test]
    fn the_step_is_found_from_the_summary_when_its_first_line_scrolled_away() {
        let out = lines(
            r#"#12 41.2 Traceback (most recent call last):
#12 41.3 ModuleNotFoundError: No module named 'flask'
#12 ERROR: process "/bin/sh -c python -m compileall ." did not complete successfully: exit code: 1
------
 > [build 4/4] RUN python -m compileall .:
41.3 ModuleNotFoundError: No module named 'flask'
------
ERROR: failed to solve: process "/bin/sh -c python -m compileall ." did not complete successfully: exit code: 1"#,
        );
        let parsed = parse(&out);
        assert_eq!(
            parsed.step.as_deref(),
            Some("[build 4/4] RUN python -m compileall .")
        );
        assert_eq!(
            parsed.lines,
            ["ModuleNotFoundError: No module named 'flask'"]
        );
    }

    #[test]
    fn railpack_steps_are_named_by_their_command() {
        let out = lines(
            r#"#9 [railpack] secrets hash
#9 DONE 0.0s

#10 npm run build
#10 1.204 > web@1.0.0 build
#10 1.877 Error: Cannot find module 'vite'
#10 ERROR: process "/bin/bash --login -c npm run build" did not complete successfully: exit code: 1
ERROR: failed to build: failed to solve: process "/bin/bash --login -c npm run build" did not complete successfully: exit code: 1"#,
        );
        let parsed = parse(&out);
        assert_eq!(parsed.step.as_deref(), Some("npm run build"));
        assert_eq!(parsed.lines, ["Error: Cannot find module 'vite'"]);
    }

    #[test]
    fn the_classic_builder_still_names_its_step() {
        let out = lines(
            "Step 7/12 : RUN npm ci\n ---> Running in 1a2b\nnpm ERR! code 1\nThe command '/bin/sh -c npm ci' returned a non-zero code: 1",
        );
        let failure = build_failure(
            "build",
            ChildOutcome::Exited { code: 1, tail: out },
            "docker build",
        );
        assert!(failure.message.contains("Step 7/12 : RUN npm ci"));
        assert!(failure.next_step.is_some());

        let bare = build_failure(
            "build",
            ChildOutcome::Exited {
                code: 3,
                tail: vec!["something odd".into()],
            },
            "docker build",
        );
        assert_eq!(bare.message, "docker build exited 3");
    }

    #[test]
    fn docker_hub_limits_and_full_disks_are_explained() {
        let out = lines(
            "#3 ERROR: failed to copy: httpReadSeeker: failed open: unexpected status code https://registry-1.docker.io/v2/library/node/manifests/sha256:x: 429 Too Many Requests - Server message: toomanyrequests: You have reached your pull rate limit.",
        );
        assert!(rate_limited(&out));
        let failure = build_failure(
            "build",
            ChildOutcome::Exited { code: 1, tail: out },
            "docker build",
        );
        assert_eq!(failure.message, "Docker Hub's pull limit was reached");
        assert!(failure.next_step.unwrap().contains("Docker Hub login"));

        let full = build_failure(
            "build",
            ChildOutcome::Exited {
                code: 1,
                tail: vec!["write /var/lib/docker/tmp/x: no space left on device".into()],
            },
            "docker build",
        );
        assert_eq!(full.message, "the machine ran out of disk space");

        assert!(!rate_limited(&lines(BUILDKIT_RUN)));
    }

    #[test]
    fn docker_not_being_there_says_to_install_it() {
        let failure = build_failure(
            "build",
            ChildOutcome::Unstartable("could not start docker: No such file".into()),
            "docker build",
        );
        assert_eq!(
            failure.next_step.as_deref(),
            Some("Install Docker from the machine's page in ServerOS.")
        );
    }
}
