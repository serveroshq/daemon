use daemon_core::Paths;
use daemon_security::{audit, Options, Report};

use super::runtime;

pub fn run(paths: &Paths, json: bool) -> anyhow::Result<()> {
    let rt = runtime()?;
    let report = rt.block_on(audit(Options {
        apps_dir: Some(paths.state_dir.join("apps")),
        ..Options::default()
    }));

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    print_summary(&report);

    Ok(())
}

fn print_summary(report: &Report) {
    println!(
        "Audited in {} ms{}",
        report.duration_ms,
        if report.truncated {
            " (some folders not read)"
        } else {
            ""
        }
    );
    println!();
    println!(
        "Packages: {} in {} projects (matched to vulnerabilities on the panel)",
        report.packages.len(),
        report.projects.len()
    );
    for runtime in &report.runtimes {
        println!(
            "Runtime:  {} {} ({})",
            runtime.name, runtime.version, runtime.path
        );
    }
    for site in &report.sites {
        let names = if site.names.is_empty() {
            "(no name)".to_string()
        } else {
            site.names.join(", ")
        };
        println!(
            "Site:     {} via {}{}",
            names,
            site.server,
            site.root
                .as_deref()
                .map(|r| format!(" from {r}"))
                .unwrap_or_default()
        );
        for file in &site.risky_files {
            println!("          shouldn't be in the web root: {file}");
        }
        if let Some(wp) = &site.wordpress {
            println!(
                "          WordPress {} with {} plugins",
                wp.version.as_deref().unwrap_or("?"),
                wp.plugins.len()
            );
        }
    }
    for app in report.apps.iter().filter(|a| a.debug_in_production) {
        println!("App:      {} runs in production with debug on", app.path);
    }
    for issue in &report.databases {
        println!(
            "Database: {} {} ({}): {}",
            issue.service, issue.issue, issue.config, issue.detail
        );
    }
    for container in &report.containers {
        let mut risks = Vec::new();
        if container.privileged {
            risks.push("privileged".to_string());
        }
        if container.docker_socket {
            risks.push("has the Docker socket".to_string());
        }
        if container.host_network {
            risks.push("host network".to_string());
        }
        for port in &container.public_ports {
            risks.push(format!("publishes {}/{}", port.host_port, port.proto));
        }
        println!(
            "Container: {} ({}): {}",
            container.name,
            container.image,
            risks.join(", ")
        );
    }
    let host = &report.host;
    for item in &host.suspicious {
        println!(
            "Suspicious {}: {} [{}] {}",
            item.kind,
            item.source,
            item.reasons.join(", "),
            item.command
        );
    }
    for file in &host.setuid {
        println!(
            "Setuid:   {} ({}, owned by {})",
            file.path, file.reason, file.owner
        );
    }
    for name in &host.accounts.extra_root {
        println!("Account:  {name} has root's user id");
    }
    for name in &host.accounts.system_logins {
        println!("Account:  {name} is a system account that can sign in with an SSH key");
    }
    for lib in &host.preload {
        println!("Preload:  {lib}");
    }
    for w in &host.writable {
        println!("Writable: {} ({}, by {})", w.path, w.reason, w.by);
    }
    let keys: usize = host.ssh_keys.iter().map(|k| k.keys.len()).sum();
    println!("SSH keys: {keys} across {} files", host.ssh_keys.len());
    if host.reboot.required {
        println!("Reboot:   needed ({})", host.reboot.packages.join(", "));
    }
    for warning in &report.warnings {
        println!("Note:     {warning}");
    }
}
