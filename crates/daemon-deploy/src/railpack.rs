//! Building an app that has no Dockerfile, with Railpack: it reads the
//! app's files (package.json, requirements.txt, go.mod, index.html…), works
//! out how to install, build and start it, and writes a build plan that
//! BuildKit builds through Railpack's frontend image.
//!
//! The Railpack binary is a pinned release, downloaded on first use into
//! the daemon's own `bin` folder and checked against its sha256 before it
//! runs. Build settings reach Railpack and BuildKit by name only, with
//! their values in the child's environment: `railpack prepare --env NAME`
//! and `docker buildx build --secret id=NAME,env=NAME`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use daemon_jobs::{capture_child, run_child, ChildOutcome, Failure, Progress};
use daemon_protocol::BuildSpec;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::buildlog;
use crate::container::{self, BuildLimits, BuildSettings};

/// The Railpack release ServerOS builds with.
pub const VERSION: &str = "0.44.0";

/// Railpack's BuildKit frontend at the same release, pinned by digest.
pub const FRONTEND: &str = "ghcr.io/railwayapp/railpack-frontend:v0.44.0@sha256:ca7b4f62a572e1910cf51dc181bd5b51111a07efe6604f80536e16a9923ffae2";

const RELEASES: &str = "https://github.com/railwayapp/railpack/releases/download";

/// The release archive for each processor, and its sha256 (from the
/// release's checksums.txt).
const ASSETS: &[(&str, &str, &str)] = &[
    (
        "x86_64",
        "x86_64-unknown-linux-musl",
        "50b55b6762321c4eb2a2b8850ea0ffcb70b3250f1a2b15519b4901b17ce09411",
    ),
    (
        "aarch64",
        "arm64-unknown-linux-musl",
        "8f0d88077cf903faeaa463db192221900609f5d7c89d9430d9c3a0800479d18f",
    ),
];

/// The BuildKit builder Railpack builds in when Docker's own can't (Docker
/// keeping images the classic way can't run Railpack's merge steps).
pub const BUILDER: &str = "serveros-railpack";

/// The archive name and sha256 for this processor.
fn asset_for(arch: &str) -> Option<(String, &'static str)> {
    ASSETS
        .iter()
        .find(|(a, _, _)| *a == arch)
        .map(|(_, target, sha)| (format!("railpack-v{VERSION}-{target}.tar.gz"), *sha))
}

pub fn binary_path(state_dir: &Path) -> PathBuf {
    state_dir.join("bin").join(format!("railpack-{VERSION}"))
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}

static INSTALL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The Railpack binary, downloaded and checked the first time it's needed.
pub async fn ensure_installed(
    state_dir: &Path,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<PathBuf, Failure> {
    let _one_at_a_time = INSTALL.lock().await;
    let binary = binary_path(state_dir);
    if binary.is_file() {
        return Ok(binary);
    }

    let arch = std::env::consts::ARCH;
    let (archive, sha256) = asset_for(arch).ok_or_else(|| {
        Failure::new("build", format!("Railpack doesn't run on {arch} machines"))
            .with_next_step("Add a Dockerfile to the repository and build with it instead.")
    })?;
    let url = format!("{RELEASES}/v{VERSION}/{archive}");

    let bin_dir = binary.parent().unwrap_or(state_dir).to_path_buf();
    std::fs::create_dir_all(&bin_dir).map_err(|e| {
        Failure::new(
            "build",
            format!("could not create {}: {e}", bin_dir.display()),
        )
    })?;
    let scratch = bin_dir.join(format!(".railpack-{VERSION}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).map_err(|e| {
        Failure::new(
            "build",
            format!("could not create {}: {e}", scratch.display()),
        )
    })?;
    let result = download(&url, sha256, &scratch, &binary, cancel, progress).await;
    let _ = std::fs::remove_dir_all(&scratch);
    result.map(|_| binary)
}

async fn download(
    url: &str,
    sha256: &str,
    scratch: &Path,
    binary: &Path,
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    progress
        .line(format!(
            "downloading Railpack {VERSION} (first build without a Dockerfile on this machine)"
        ))
        .await;
    let archive = scratch.join("railpack.tar.gz");
    let archive_arg = archive.to_string_lossy().into_owned();
    let mut outcome = run_child(
        "curl",
        &[
            "-fsSL",
            "--retry",
            "3",
            "--max-time",
            "300",
            "-o",
            &archive_arg,
            url,
        ],
        None,
        &[],
        Duration::from_secs(330),
        cancel,
        progress,
        None,
    )
    .await;
    if matches!(outcome, ChildOutcome::Unstartable(_)) {
        outcome = run_child(
            "wget",
            &["-q", "-T", "60", "-O", &archive_arg, url],
            None,
            &[],
            Duration::from_secs(330),
            cancel,
            progress,
            None,
        )
        .await;
    }
    match outcome {
        ChildOutcome::Exited { code: 0, .. } => {}
        ChildOutcome::Cancelled { tail } => {
            return Err(Failure::new("cancelled", "deploy cancelled").with_output(tail))
        }
        ChildOutcome::Unstartable(_) => {
            return Err(Failure::new(
                "build",
                "downloading Railpack needs curl or wget, and neither is installed",
            )
            .with_next_step("Install curl on the machine, then deploy again."))
        }
        other => {
            return Err(Failure::new("build", "could not download Railpack")
                .with_output(other.tail().to_vec())
                .with_next_step("Check the machine can reach github.com, then deploy again."))
        }
    }

    let got = sha256_file(&archive).map_err(|e| {
        Failure::new(
            "build",
            format!("could not read the Railpack download: {e}"),
        )
    })?;
    if got != sha256 {
        return Err(Failure::new(
            "build",
            "the Railpack download didn't match its checksum, so it wasn't used",
        )
        .with_next_step("Deploy again. If it keeps happening, tell ServerOS support."));
    }

    let scratch_arg = scratch.to_string_lossy().into_owned();
    let outcome = run_child(
        "tar",
        &["-xzf", &archive_arg, "-C", &scratch_arg, "railpack"],
        None,
        &[],
        Duration::from_secs(120),
        cancel,
        progress,
        None,
    )
    .await;
    if !outcome.success() {
        return Err(
            Failure::new("build", "could not unpack Railpack").with_output(outcome.tail().to_vec())
        );
    }

    use std::os::unix::fs::PermissionsExt;
    let unpacked = scratch.join("railpack");
    std::fs::set_permissions(&unpacked, std::fs::Permissions::from_mode(0o755))
        .and_then(|_| std::fs::rename(&unpacked, binary))
        .map_err(|e| Failure::new("build", format!("could not install Railpack: {e}")))?;
    progress
        .line(format!("Railpack {VERSION} is in {}", binary.display()))
        .await;
    Ok(())
}

/// What `railpack prepare --info-out` writes.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct Info {
    #[serde(rename = "railpackVersion", default)]
    pub version: String,
    #[serde(rename = "detectedProviders", default)]
    pub providers: Vec<String>,
    #[serde(rename = "resolvedPackages", default)]
    pub packages: BTreeMap<String, Package>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub logs: Vec<LogLine>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Package {
    #[serde(rename = "resolvedVersion", default)]
    pub resolved: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct LogLine {
    #[serde(rename = "Level", default)]
    pub level: String,
    #[serde(rename = "Msg", default)]
    pub msg: String,
}

/// The parts of a build plan the build needs to know.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct Plan {
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub deploy: PlanDeploy,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PlanDeploy {
    #[serde(rename = "startCommand", default)]
    pub start: Option<String>,
}

/// What the build log says Railpack found: the kind of app, the versions
/// it picked and how it starts, then what it warned about.
pub(crate) fn summary(info: &Info, plan: &Plan) -> Vec<String> {
    let mut lines = Vec::new();
    let kind = if info.providers.is_empty() {
        "an app".to_string()
    } else {
        format!("a {} app", info.providers.join(" + "))
    };
    let version = if info.version.is_empty() {
        VERSION
    } else {
        info.version.as_str()
    };
    lines.push(format!("Railpack {version} found {kind}"));

    let mut packages: Vec<String> = info
        .packages
        .iter()
        .filter_map(|(name, p)| p.resolved.as_ref().map(|v| format!("{name} {v}")))
        .collect();
    if let Some(manager) = info.metadata.get("nodePackageManager") {
        if !info.packages.contains_key(manager) {
            packages.push(manager.clone());
        }
    }
    if !packages.is_empty() {
        lines.push(format!("using {}", packages.join(", ")));
    }
    if let Some(dir) = info
        .metadata
        .get("staticOutputDir")
        .filter(|d| !d.is_empty())
    {
        lines.push(format!("a static site: Caddy serves the files in {dir}"));
    }
    match plan.deploy.start.as_deref().filter(|s| !s.is_empty()) {
        Some(start) => lines.push(format!("start command: {start}")),
        None => lines.push("no start command".into()),
    }
    for log in info.logs.iter().filter(|l| l.level == "warn") {
        if let Some(first) = log.msg.lines().next().filter(|l| !l.trim().is_empty()) {
            lines.push(format!("Railpack: {first}"));
        }
    }
    lines
}

/// A failed `railpack prepare`, from the errors it wrote.
pub(crate) fn prepare_failure(code: i32, info: Option<&Info>, tail: Vec<String>) -> Failure {
    let error = info.and_then(|i| {
        i.logs
            .iter()
            .rev()
            .find(|l| l.level == "error")
            .map(|l| l.msg.as_str())
    });
    let first = error
        .and_then(|e| e.lines().next())
        .unwrap_or_default()
        .trim();

    if first.starts_with("Railpack could not determine how to build the app") {
        Failure::new("build", "Railpack couldn't tell how to build this app")
            .with_output(tail)
            .with_next_step(
                "Add a Dockerfile to the repository, or set a start command in the app's build settings.",
            )
    } else if first.starts_with("No start command detected") {
        Failure::new("build", "Railpack couldn't tell how to start this app")
            .with_output(tail)
            .with_next_step(
                "Set a start command in the app's build settings, or add one to the app (a start script in package.json, or a Procfile).",
            )
    } else if code == 75 {
        Failure::new(
            "build",
            "Railpack couldn't download what it needs to plan the build",
        )
        .with_output(tail)
        .with_next_step("Check the machine's network access, then deploy again.")
    } else if !first.is_empty() {
        Failure::new(
            "build",
            format!("Railpack couldn't plan the build: {first}"),
        )
        .with_output(tail)
        .with_next_step(
            "Fix what it says, or add a Dockerfile to the repository, then deploy again.",
        )
    } else {
        Failure::new("build", format!("railpack prepare exited {code}"))
            .with_output(tail)
            .with_next_step(
                "Add a Dockerfile to the repository, or check the app's build settings.",
            )
    }
}

/// A hash of the settings' values, so a layer that read one is built again
/// when it changes (Railpack's `secrets-hash`).
fn secrets_hash(env: &[(String, String)]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"serveros.railpack.secrets/1");
    for (name, value) in env {
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    hex::encode(hash.finalize())
}

/// Where the build runs: Docker's own BuildKit when it keeps images in
/// containerd (Docker 29 and later, fresh), or a BuildKit container
/// otherwise, since only the first can run Railpack's merge steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Builder {
    Docker,
    Container,
}

pub(crate) fn uses_containerd(driver_status: &str) -> bool {
    driver_status.contains("io.containerd.snapshotter")
}

fn needs_container_builder(output: &[String]) -> bool {
    output
        .iter()
        .any(|l| l.contains("mergeop") || l.contains("containerd image store"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn buildx_args(
    builder: Builder,
    plan: &Path,
    context: &Path,
    tag: &str,
    cache_key: &str,
    secrets: &[String],
    secrets_hash: Option<&str>,
    no_cache: bool,
) -> Vec<String> {
    let mut args: Vec<String> = vec!["buildx".into(), "build".into()];
    if builder == Builder::Container {
        args.extend(["--builder".into(), BUILDER.into()]);
    }
    args.extend([
        "--load".into(),
        "--progress=plain".into(),
        "--build-arg".into(),
        format!("BUILDKIT_SYNTAX={FRONTEND}"),
        "--build-arg".into(),
        format!("cache-key={cache_key}"),
    ]);
    if let Some(hash) = secrets_hash {
        args.extend(["--build-arg".into(), format!("secrets-hash={hash}")]);
    }
    if no_cache {
        args.push("--no-cache".into());
    }
    for name in secrets {
        args.extend(["--secret".into(), format!("id={name},env={name}")]);
    }
    args.extend([
        "-f".into(),
        plan.to_string_lossy().into_owned(),
        "-t".into(),
        tag.into(),
        context.to_string_lossy().into_owned(),
    ]);
    args
}

/// One Railpack build.
pub struct RailpackBuild<'a> {
    pub state_dir: &'a Path,
    /// A folder of the job's own, outside the build context, for the plan.
    pub plan_dir: &'a Path,
    pub service: &'a str,
    pub context: &'a Path,
    pub tag: &'a str,
    pub build: &'a BuildSpec,
    pub settings: &'a BuildSettings,
    pub limits: &'a BuildLimits,
    pub docker_env: &'a [(&'a str, &'a str)],
    pub timeout: Duration,
}

/// Removes the plan's folder however the build ends.
struct PlanDir(PathBuf);

impl Drop for PlanDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl RailpackBuild<'_> {
    pub async fn run(
        &self,
        cancel: &mut watch::Receiver<bool>,
        progress: &Progress,
    ) -> Result<(), Failure> {
        let railpack = ensure_installed(self.state_dir, cancel, progress).await?;

        let plan_dir = PlanDir(self.plan_dir.to_path_buf());
        let _ = std::fs::remove_dir_all(&plan_dir.0);
        std::fs::create_dir_all(&plan_dir.0).map_err(|e| {
            Failure::new(
                "build",
                format!("could not create {}: {e}", plan_dir.0.display()),
            )
        })?;
        let plan_file = plan_dir.0.join("railpack-plan.json");
        let info_file = plan_dir.0.join("railpack-info.json");

        // Everything Railpack is told by name; the values ride in the
        // environment. An install command goes the same way, as Railpack's
        // RAILPACK_INSTALL_CMD.
        let mut env: Vec<(String, String)> = self
            .settings
            .env
            .iter()
            .filter(|(k, _)| !(self.build.install_command.is_some() && k == "RAILPACK_INSTALL_CMD"))
            .cloned()
            .collect();
        if let Some(install) = self
            .build
            .install_command
            .as_deref()
            .filter(|c| !c.is_empty())
        {
            env.push(("RAILPACK_INSTALL_CMD".into(), install.into()));
        }
        env.sort();

        self.settings.log(progress).await;
        progress
            .line("working out how to build the app with Railpack")
            .await;
        let context_arg = self.context.to_string_lossy().into_owned();
        let plan_arg = plan_file.to_string_lossy().into_owned();
        let info_arg = info_file.to_string_lossy().into_owned();
        let mut args: Vec<String> = vec![
            "prepare".into(),
            context_arg,
            "--plan-out".into(),
            plan_arg,
            "--info-out".into(),
            info_arg,
            "--hide-pretty-plan".into(),
            "--error-missing-start".into(),
        ];
        for (name, _) in &env {
            args.extend(["--env".into(), name.clone()]);
        }
        if let Some(cmd) = self
            .build
            .build_command
            .as_deref()
            .filter(|c| !c.is_empty())
        {
            args.extend(["--build-cmd".into(), cmd.into()]);
        }
        if let Some(cmd) = self
            .build
            .start_command
            .as_deref()
            .filter(|c| !c.is_empty())
        {
            args.extend(["--start-cmd".into(), cmd.into()]);
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut child_env: Vec<(&str, &str)> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        child_env.extend([("NO_COLOR", "1"), ("TERM", "dumb")]);
        let binary = railpack.to_string_lossy().into_owned();
        let outcome = run_child(
            &binary,
            &arg_refs,
            Some(self.context),
            &child_env,
            self.timeout,
            cancel,
            progress,
            None,
        )
        .await;

        let info: Option<Info> = std::fs::read(&info_file)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        match outcome {
            ChildOutcome::Exited { code: 0, .. } => {}
            ChildOutcome::Exited { code, tail } => {
                return Err(prepare_failure(code, info.as_ref(), tail));
            }
            ChildOutcome::Cancelled { tail } => {
                return Err(Failure::new("cancelled", "deploy cancelled").with_output(tail))
            }
            ChildOutcome::TimedOut { tail } => {
                return Err(Failure::new("build", "railpack prepare timed out").with_output(tail))
            }
            ChildOutcome::Unstartable(e) => {
                return Err(Failure::new("build", e)
                    .with_next_step("Deploy again to download Railpack afresh."))
            }
        }

        let plan: Plan = std::fs::read(&plan_file)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| Failure::new("build", "Railpack didn't write a build plan"))?;
        for line in summary(&info.unwrap_or_default(), &plan) {
            progress.line(line).await;
        }

        // Each secret the plan names, given by name from the environment.
        // One it names that this deploy doesn't have (a railpack.json's
        // own) is left for BuildKit to report.
        let secrets: Vec<String> = plan
            .secrets
            .iter()
            .filter(|s| env.iter().any(|(k, _)| k == *s))
            .cloned()
            .collect();
        let hash = (!env.is_empty()).then(|| secrets_hash(&env));

        let driver = capture_child(
            "docker",
            &["info", "--format", "{{json .DriverStatus}}"],
            &[],
            Duration::from_secs(20),
            cancel,
            5,
        )
        .await;
        let mut builder = if uses_containerd(&driver.stdout().join("")) {
            Builder::Docker
        } else {
            Builder::Container
        };

        let buildx_config = self.state_dir.join("buildx").to_string_lossy().into_owned();
        let mut build_env: Vec<(&str, &str)> = vec![
            ("DOCKER_BUILDKIT", "1"),
            // The daemon's own buildx state, so a builder someone picked
            // on the machine doesn't change where this one runs.
            ("BUILDX_CONFIG", buildx_config.as_str()),
        ];
        build_env.extend(self.docker_env.iter().copied());
        build_env.extend(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));

        let cache_key = format!("serveros-{}", crate::git::sanitise(self.service));
        let scoped = container::scopes_work(cancel).await;
        if self.build.no_cache {
            progress
                .line("building from scratch, without the layer cache")
                .await;
        }
        loop {
            if builder == Builder::Container {
                ensure_builder(&build_env, cancel, progress).await?;
            }
            let args = buildx_args(
                builder,
                &plan_file,
                self.context,
                self.tag,
                &cache_key,
                &secrets,
                hash.as_deref(),
                self.build.no_cache,
            );
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let outcome = container::run_scoped(
                "docker",
                &arg_refs,
                self.context,
                &build_env,
                self.limits,
                scoped,
                self.timeout,
                cancel,
                progress,
            )
            .await;
            if outcome.success() {
                return Ok(());
            }
            if builder == Builder::Docker && needs_container_builder(outcome.tail()) {
                progress
                    .line("Docker's own builder can't run this build here; building in a BuildKit container instead")
                    .await;
                builder = Builder::Container;
                continue;
            }
            return Err(buildlog::build_failure(
                "build",
                outcome,
                "the Railpack build",
            ));
        }
    }
}

/// The BuildKit container builder, made the first time it's needed.
async fn ensure_builder(
    env: &[(&str, &str)],
    cancel: &mut watch::Receiver<bool>,
    progress: &Progress,
) -> Result<(), Failure> {
    let exists = capture_child(
        "docker",
        &["buildx", "inspect", BUILDER],
        env,
        Duration::from_secs(30),
        cancel,
        50,
    )
    .await
    .code()
        == Some(0);
    if exists {
        return Ok(());
    }
    progress
        .line(format!("setting up the BuildKit builder {BUILDER}"))
        .await;
    let outcome = run_child(
        "docker",
        &[
            "buildx",
            "create",
            "--name",
            BUILDER,
            "--driver",
            "docker-container",
            "--bootstrap",
        ],
        None,
        env,
        Duration::from_secs(600),
        cancel,
        progress,
        None,
    )
    .await;
    if outcome.success() {
        Ok(())
    } else {
        Err(buildlog::build_failure(
            "build",
            outcome,
            "setting up the BuildKit builder",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_release_has_a_checksum_for_both_processors() {
        let (amd, amd_sha) = asset_for("x86_64").unwrap();
        assert_eq!(amd, "railpack-v0.44.0-x86_64-unknown-linux-musl.tar.gz");
        assert_eq!(amd_sha.len(), 64);
        let (arm, arm_sha) = asset_for("aarch64").unwrap();
        assert_eq!(arm, "railpack-v0.44.0-arm64-unknown-linux-musl.tar.gz");
        assert_ne!(amd_sha, arm_sha);
        assert!(asset_for("riscv64").is_none());
        assert!(FRONTEND.contains(&format!("v{VERSION}@sha256:")));
        assert_eq!(
            binary_path(Path::new("/var/lib/serveros")),
            Path::new("/var/lib/serveros/bin/railpack-0.44.0")
        );
    }

    #[test]
    fn checksums_are_of_the_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x");
        std::fs::write(&file, b"abc").unwrap();
        assert_eq!(
            sha256_file(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_build_log_says_what_railpack_found() {
        let info: Info = serde_json::from_str(
            r#"{"railpackVersion":"0.44.0",
                "resolvedPackages":{"node":{"name":"node","requestedVersion":"lts","resolvedVersion":"26.13.1","source":"railpack default"}},
                "metadata":{"nodePackageManager":"npm","providers":"node"},
                "detectedProviders":["node"],
                "logs":[{"Level":"warn","Msg":"No node package manager detected, using npm","DocsPath":""},
                        {"Level":"info","Msg":"Detected Node","DocsPath":""}],
                "success":true}"#,
        )
        .unwrap();
        let plan: Plan = serde_json::from_str(
            r#"{"secrets":["NPM_TOKEN"],"deploy":{"startCommand":"npm run start"}}"#,
        )
        .unwrap();
        assert_eq!(
            summary(&info, &plan),
            [
                "Railpack 0.44.0 found a node app",
                "using node 26.13.1, npm",
                "start command: npm run start",
                "Railpack: No node package manager detected, using npm",
            ]
        );
        assert_eq!(plan.secrets, ["NPM_TOKEN"]);
    }

    #[test]
    fn an_app_railpack_cant_read_gets_a_next_step() {
        let info: Info = serde_json::from_str(
            r#"{"logs":[{"Level":"error","Msg":"Railpack could not determine how to build the app.\n\nThe following languages are supported:\n- Node"}],"success":false}"#,
        )
        .unwrap();
        let failure = prepare_failure(1, Some(&info), vec![]);
        assert_eq!(
            failure.message,
            "Railpack couldn't tell how to build this app"
        );
        assert_eq!(
            failure.next_step.as_deref(),
            Some("Add a Dockerfile to the repository, or set a start command in the app's build settings.")
        );

        let info: Info = serde_json::from_str(
            r#"{"logs":[{"Level":"error","Msg":"No start command detected. Specify a start command: https://railpack.com/config/file#deploy\n\nmore"}]}"#,
        )
        .unwrap();
        let failure = prepare_failure(1, Some(&info), vec![]);
        assert_eq!(
            failure.message,
            "Railpack couldn't tell how to start this app"
        );
        assert!(failure.next_step.unwrap().contains("start command"));

        assert!(prepare_failure(75, None, vec![])
            .message
            .contains("couldn't download"));
        assert_eq!(
            prepare_failure(2, None, vec![]).message,
            "railpack prepare exited 2"
        );
        for f in [
            prepare_failure(1, Some(&info), vec![]),
            prepare_failure(2, None, vec![]),
        ] {
            assert!(!f.message.contains('\u{2014}'));
            assert!(!f.next_step.unwrap_or_default().contains('\u{2014}'));
        }
    }

    #[test]
    fn secrets_go_to_buildkit_by_name_and_values_stay_off_the_command_line() {
        let env = vec![
            ("API_KEY".to_string(), "fake_key_123".to_string()),
            ("NODE_ENV".to_string(), "production".to_string()),
        ];
        let hash = secrets_hash(&env);
        assert_eq!(hash.len(), 64);
        let mut changed = env.clone();
        changed[0].1 = "fake_key_124".into();
        assert_ne!(secrets_hash(&changed), hash);

        let args = buildx_args(
            Builder::Docker,
            Path::new("/var/lib/serveros/jobs/1-railpack/railpack-plan.json"),
            Path::new("/var/lib/serveros/jobs/1"),
            "serveros/web:abc",
            "serveros-web",
            &["API_KEY".into(), "NODE_ENV".into()],
            Some(&hash),
            true,
        );
        let joined = args.join(" ");
        assert!(!joined.contains("fake_key_123") && !joined.contains("production"));
        assert!(joined.starts_with("buildx build --load --progress=plain"));
        assert!(joined.contains(&format!("--build-arg BUILDKIT_SYNTAX={FRONTEND}")));
        assert!(joined.contains("--build-arg cache-key=serveros-web"));
        assert!(joined.contains(&format!("--build-arg secrets-hash={hash}")));
        assert!(joined.contains("--no-cache"));
        assert!(
            joined.contains("--secret id=API_KEY,env=API_KEY --secret id=NODE_ENV,env=NODE_ENV")
        );
        assert!(joined.ends_with(
            "-f /var/lib/serveros/jobs/1-railpack/railpack-plan.json -t serveros/web:abc /var/lib/serveros/jobs/1"
        ));
        assert!(!joined.contains("--builder"));

        let args = buildx_args(
            Builder::Container,
            Path::new("p"),
            Path::new("c"),
            "t",
            "k",
            &[],
            None,
            false,
        );
        assert!(args
            .join(" ")
            .starts_with(&format!("buildx build --builder {BUILDER} --load")));
        assert!(!args.contains(&"--no-cache".to_string()));
    }

    #[test]
    fn docker_keeping_images_in_containerd_builds_railpack_itself() {
        assert!(uses_containerd(
            r#"[["driver-type","io.containerd.snapshotter.v1"]]"#
        ));
        assert!(!uses_containerd(
            r#"[["Backing Filesystem","extfs"],["Supports d_type","true"]]"#
        ));
        assert!(needs_container_builder(&[
            "ERROR: failed to solve: requested experimental feature mergeop has been disabled on the build server: only enabled with containerd image store backend".to_string()
        ]));
        assert!(!needs_container_builder(&[
            "ERROR: exit code: 1".to_string()
        ]));
    }
}
