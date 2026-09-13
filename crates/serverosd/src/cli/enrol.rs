//! `serverosd enrol`: the nine steps from the spec, each printed before it
//! happens, each failure telling a person what to do.

use std::path::Path;

use daemon_core::{BuildInfo, Config, Paths};
use daemon_identity::{enrol, Identity, KeyMaterial};
use daemon_uninstall::{Artifact, Manifest};

use super::{require_root, runtime};

pub const UNIT_NAME: &str = "serverosd.service";

pub fn unit_file(binary: &Path) -> String {
    format!(
        "[Unit]\nDescription=ServerOS daemon\nDocumentation={}\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={} run\nRestart=always\nRestartSec=5\nTimeoutStopSec=90\nKillMode=mixed\nLimitNOFILE=65536\nEnvironment=SERVEROS_LOG=info\n\n[Install]\nWantedBy=multi-user.target\n",
        daemon_core::links::DOCS_URL,
        binary.display()
    )
}

pub fn run(paths: Paths, token: &str, panel: &str, dry_run: bool) -> anyhow::Result<()> {
    require_root("enrolment")?;

    println!("ServerOS daemon {} enrolment", BuildInfo::current().version);
    println!();
    println!("This will:");
    println!("  1. check this machine can run the daemon");
    println!(
        "  2. generate a private key in {} (it never leaves this machine)",
        paths.config_dir.display()
    );
    println!("  3. ask {panel} for a certificate using your one-time token");
    println!("  4. install and start {UNIT_NAME}");
    println!("  5. run a first read-only scan of what is running here");
    println!();

    // 1. Platform.
    let facts = daemon_telemetry::gather_facts();

    if !cfg!(target_os = "linux") {
        anyhow::bail!(
            "the daemon runs on Linux only (this is {})",
            std::env::consts::OS
        );
    }

    if facts.init_system != "systemd" {
        anyhow::bail!("systemd was not found (/run/systemd/system). The daemon needs systemd to stay running; other init systems are not supported yet.");
    }

    if Identity::exists(&paths) {
        anyhow::bail!("this machine is already enrolled ({}). Run `serverosd disconnect` first to enrol it somewhere else.", paths.config_file().display());
    }

    if let Some(free) = free_bytes(paths.state_dir.parent().unwrap_or(Path::new("/"))) {
        if free < 512 * 1024 * 1024 {
            anyhow::bail!("only {} MB free on the root filesystem; the daemon needs at least 512 MB for state, job workspaces, and backup staging.", free / (1024 * 1024));
        }
    }

    println!(
        "  machine: {} ({} {}, {}, {} cores, {} GB RAM)",
        facts.hostname,
        facts.os,
        facts.os_version,
        facts.arch,
        facts.cpu_cores,
        facts.memory_bytes / (1024 * 1024 * 1024)
    );

    if dry_run {
        println!("\nDry run: stopping here. Nothing was changed.");
        return Ok(());
    }

    // 2. Directories and key.
    for (dir, mode) in paths.owned_directories() {
        std::fs::create_dir_all(&dir)?;
        set_mode(&dir, mode);
    }

    let key = KeyMaterial::generate()?;
    println!("  generated keypair");

    // 3. Enrol.
    let rt = runtime()?;
    let (answer, identity) = rt.block_on(enrol(
        panel,
        token,
        &key,
        &facts.hostname,
        BuildInfo::current().version,
        &facts,
    ))?;
    identity.save(&paths)?;

    let host = answer.panel_host.clone().unwrap_or_else(|| {
        panel
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string()
    });
    let mut config = Config::new(host, answer.machine_id.clone());
    config.machine.label = answer.label.clone();
    config.save(&paths.config_file())?;
    println!("  enrolled as machine {}", answer.machine_id);

    // 4. systemd.
    let unit_path = paths.systemd_unit();
    std::fs::write(&unit_path, unit_file(&paths.binary))?;
    Manifest::record(
        &paths.manifest_file(),
        Artifact::SystemdUnit {
            name: UNIT_NAME.into(),
        },
    )?;

    run_quiet("systemctl", &["daemon-reload"])?;
    run_quiet("systemctl", &["enable", "--now", UNIT_NAME])?;
    println!("  {UNIT_NAME} enabled and started");

    // 5. First scan happens inside the daemon on connect; say so.
    println!();
    println!("Done. The machine will show as connected in the panel within a few seconds,");
    println!("and its first service scan will follow.");
    println!();
    println!("  status:    serverosd status");
    println!("  audit log: {}", paths.actions_log().display());
    println!("  remove:    serverosd uninstall --yes");

    Ok(())
}

fn run_quiet(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("could not run {program}: {e}"))?;

    if !out.status.success() {
        anyhow::bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    Ok(())
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

fn free_bytes(dir: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };

    (unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } == 0)
        .then(|| stat.f_bavail as u64 * stat.f_frsize as u64)
}
