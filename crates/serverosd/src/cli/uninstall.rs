use daemon_audit::{Actor, AuditLog, Entry, Outcome};
use daemon_core::Paths;
use daemon_uninstall::{plan, remove_artifact, remove_own, Manifest, Report};

use super::require_root;

fn run_tool(program: &str, args: &[&str]) -> bool {
    std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn managed_services(paths: &Paths) -> Vec<String> {
    daemon_state::State::open(&paths.state_db())
        .ok()
        .and_then(|s| daemon_services::Registry::new(&s).all().ok())
        .map(|all| all.into_iter().map(|m| m.key).collect())
        .unwrap_or_default()
}

pub fn disconnect(paths: Paths, yes: bool) -> anyhow::Result<()> {
    require_root("disconnect")?;

    if !yes {
        println!("This stops ServerOS managing this machine and deletes its credentials.");
        println!("Every service keeps running exactly as it is. The daemon binary stays for `serverosd enrol`.");
        println!("Re-run with --yes to proceed.");
        return Ok(());
    }

    if let Ok(audit) = AuditLog::open(&paths.actions_log()) {
        let _ = audit.record(Entry {
            actor: &Actor::local("serverosd disconnect"),
            action: "daemon.disconnect",
            target: "this machine",
            outcome: Outcome::Ok,
            duration: None,
            note: Some("credentials removed; services untouched"),
        });
    }

    run_tool("systemctl", &["disable", "--now", super::enrol::UNIT_NAME]);

    for file in [
        paths.private_key(),
        paths.client_cert(),
        paths.pinned_ca(),
        paths.config_file(),
    ] {
        let _ = std::fs::remove_file(file);
    }

    println!("Disconnected. Services are untouched. Revoke the machine in the panel to finish, and run `serverosd uninstall --yes` to remove the daemon entirely.");

    Ok(())
}

pub fn run(paths: Paths, yes: bool, plan_only: bool) -> anyhow::Result<()> {
    require_root("uninstall")?;

    let manifest = Manifest::load(&paths.manifest_file());
    let managed = managed_services(&paths);
    let planned = plan(&paths, &manifest, &managed);

    if plan_only || !yes {
        println!("Uninstall would remove:");
        for r in &planned.removed {
            println!("  - {r}");
        }
        println!("\nand leave exactly as it is:");
        for l in &planned.left_behind {
            println!("  - {l}");
        }
        if !yes {
            println!("\nRe-run with --yes to proceed.");
        }
        return Ok(());
    }

    if let Ok(audit) = AuditLog::open(&paths.actions_log()) {
        let _ = audit.record(Entry {
            actor: &Actor::local("serverosd uninstall"),
            action: "daemon.uninstall",
            target: "this machine",
            outcome: Outcome::Started,
            duration: None,
            note: None,
        });
    }

    let mut report = Report {
        removed: Vec::new(),
        left_behind: planned.left_behind.clone(),
        failed: Vec::new(),
    };

    run_tool("systemctl", &["disable", "--now", super::enrol::UNIT_NAME]);

    for artifact in &manifest.created {
        match remove_artifact(artifact, &run_tool) {
            Ok(label) => report.removed.push(label),
            Err(label) => report.failed.push(label),
        }
    }

    let unit = paths.systemd_unit();
    if unit.exists() {
        match std::fs::remove_file(&unit) {
            Ok(()) => report
                .removed
                .push(format!("systemd unit {}", unit.display())),
            Err(e) => report.failed.push(format!("{}: {e}", unit.display())),
        }
        run_tool("systemctl", &["daemon-reload"]);
    }

    for result in remove_own(&paths) {
        match result {
            Ok(label) => report.removed.push(label),
            Err(label) => report.failed.push(label),
        }
    }

    print!("{}", report.render());

    if !report.failed.is_empty() {
        anyhow::bail!("{} item(s) could not be removed", report.failed.len());
    }

    Ok(())
}
