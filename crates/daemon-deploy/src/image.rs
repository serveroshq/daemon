//! Deploying a prebuilt image: pull it with the job's registry logins and
//! tag it as the release's own image, `serveros/<app>:<commit>`, so starting,
//! health checks, releases and rollback work as they do for a build.

use std::time::Duration;

use daemon_jobs::{capture_child, run_child, ChildOutcome, Failure, Progress};
use tokio::sync::watch;

use crate::buildlog;

/// An image reference docker pull can be given without it being read as an
/// option: `nginx:alpine`, `ghcr.io/acme/api:1.4`, `name@sha256:…`.
pub fn valid_image(image: &str) -> bool {
    (1..=512).contains(&image.len())
        && !image.starts_with(['-', '/', '.', ':', '@'])
        && image
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '@'))
}

/// The first `name@sha256:…` docker image inspect lists.
fn parse_digest(json: &str) -> Option<String> {
    serde_json::from_str::<Option<Vec<String>>>(json.trim())
        .ok()
        .flatten()?
        .into_iter()
        .find(|d| d.contains("@sha256:"))
}

fn pull_failure(image: &str, outcome: ChildOutcome) -> Failure {
    match outcome {
        ChildOutcome::Exited { code, tail } => {
            if buildlog::rate_limited(&tail) {
                return buildlog::rate_limit_failure("pull", tail);
            }
            let said = |needles: &[&str]| {
                tail.iter()
                    .any(|l| needles.iter().any(|n| l.to_ascii_lowercase().contains(n)))
            };
            if said(&["unauthorized", "denied", "authentication required"]) {
                Failure::new("pull", format!("the registry wouldn't let this machine pull {image}"))
                    .with_output(tail)
                    .with_next_step(
                        "Check the image name, and add a login for its registry in the app's registry settings in ServerOS.",
                    )
            } else if said(&["manifest unknown", "not found", "no such image"]) {
                Failure::new("pull", format!("{image} isn't in its registry"))
                    .with_output(tail)
                    .with_next_step("Check the image's name and tag.")
            } else if said(&["no matching manifest"]) {
                Failure::new(
                    "pull",
                    format!("{image} has no build for this machine's processor"),
                )
                .with_output(tail)
                .with_next_step("Use an image built for this machine's architecture.")
            } else {
                Failure::new("pull", format!("docker pull exited {code}"))
                    .with_output(tail)
                    .with_next_step("Check the image name and the machine's network access.")
            }
        }
        other => buildlog::build_failure("pull", other, "docker pull"),
    }
}

/// Pulls `image` (with DOCKER_CONFIG in `docker_env` for private
/// registries) and tags it `tag`.
pub async fn pull(
    image: &str,
    tag: &str,
    docker_env: &[(&str, &str)],
    timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    if !valid_image(image) {
        return Err(
            Failure::new("pull", format!("{image:?} is not an image name"))
                .with_next_step("Use a name like nginx:alpine or ghcr.io/acme/api:1.4."),
        );
    }

    progress.line(format!("pulling {image}")).await;
    let outcome = run_child(
        "docker",
        &["pull", image],
        None,
        docker_env,
        timeout,
        cancel,
        progress,
        None,
    )
    .await;
    if !outcome.success() {
        return Err(pull_failure(image, outcome));
    }

    let digest = capture_child(
        "docker",
        &[
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            image,
        ],
        &[],
        Duration::from_secs(30),
        cancel,
        5,
    )
    .await;
    if let Some(digest) = digest.stdout().first().and_then(|line| parse_digest(line)) {
        progress.line(format!("{image} is {digest}")).await;
    }

    let outcome = run_child(
        "docker",
        &["tag", image, tag],
        None,
        &[],
        Duration::from_secs(60),
        cancel,
        progress,
        None,
    )
    .await;
    if !outcome.success() {
        return Err(
            Failure::new("pull", format!("could not tag {image} as {tag}"))
                .with_output(outcome.tail().to_vec()),
        );
    }
    progress
        .line(format!("{image} is this release's image, as {tag}"))
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_names_cant_become_options() {
        for good in [
            "nginx:alpine",
            "ghcr.io/acme/api:1.4",
            "registry.example.com:5000/team/app",
            "nginx@sha256:0123abcd",
            "library/redis",
        ] {
            assert!(valid_image(good), "{good:?} was refused");
        }
        for bad in [
            "",
            "-q",
            "--help",
            "nginx alpine",
            "nginx;rm",
            "a$(b)",
            "/abs",
            &"a".repeat(513),
        ] {
            assert!(!valid_image(bad), "{bad:?} was accepted");
        }
    }

    #[test]
    fn reads_the_digest_docker_pulled() {
        assert_eq!(
            parse_digest(r#"["nginx@sha256:aaa","docker.io/library/nginx@sha256:bbb"]"#).as_deref(),
            Some("nginx@sha256:aaa")
        );
        assert_eq!(parse_digest("[]"), None);
        assert_eq!(parse_digest("null"), None);
    }

    #[test]
    fn pull_failures_say_what_went_wrong() {
        let exited = |line: &str| ChildOutcome::Exited {
            code: 1,
            tail: vec![line.to_string()],
        };
        let f = pull_failure(
            "ghcr.io/acme/api:1.4",
            exited("Error response from daemon: Head \"https://ghcr.io/v2/acme/api/manifests/1.4\": unauthorized"),
        );
        assert!(f.message.contains("wouldn't let this machine pull"));
        let f = pull_failure(
            "nginx:nope",
            exited(
                "Error response from daemon: manifest for nginx:nope not found: manifest unknown",
            ),
        );
        assert_eq!(f.message, "nginx:nope isn't in its registry");
        let f = pull_failure(
            "nginx:alpine",
            exited("toomanyrequests: You have reached your pull rate limit."),
        );
        assert_eq!(f.message, "Docker Hub's pull limit was reached");
        let f = pull_failure("x", ChildOutcome::Unstartable("no docker".into()));
        assert!(f.next_step.unwrap().contains("Install Docker"));
    }
}
