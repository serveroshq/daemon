use daemon_inventory::Scanner;

use super::runtime;

pub fn run(json: bool) -> anyhow::Result<()> {
    let rt = runtime()?;
    let report = rt.block_on(Scanner::default().scan());

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!(
        "Discovered {} services in {} ms{}",
        report.services.len(),
        report.duration_ms,
        if report.complete {
            ""
        } else {
            " (scan truncated)"
        }
    );
    println!();

    for s in &report.services {
        let ports = if s.ports.is_empty() {
            String::new()
        } else {
            format!(
                " :{}",
                s.ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",:")
            )
        };
        println!(
            "  {:<28} {:<12} {:<10} {:>3}%  {}{}",
            s.name,
            format!("{:?}", s.manager).to_lowercase(),
            format!("{:?}", s.status).to_lowercase(),
            s.confidence,
            s.key,
            ports
        );
        if let Some(notes) = s.details.get("notes") {
            for note in notes.split(" | ") {
                println!("      note: {note}");
            }
        }
        if let Some(warning) = s.details.get("warning") {
            println!("      warning: {warning}");
        }
    }

    if !report.unknown.is_empty() {
        println!();
        println!("Unknown:");
        for u in &report.unknown {
            println!("  {}", u.note);
        }
    }

    if !report.certificates.is_empty() {
        println!();
        println!("Certificates:");
        for c in &report.certificates {
            let days = (c.not_after - time::OffsetDateTime::now_utc().unix_timestamp()) / 86_400;
            println!(
                "  {:<40} expires in {days} days{}",
                c.names
                    .first()
                    .cloned()
                    .unwrap_or_else(|| c.subject.clone()),
                c.renewal
                    .as_deref()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default()
            );
        }
    }

    if !report.warnings.is_empty() {
        println!();
        for w in &report.warnings {
            println!("  ! {w}");
        }
    }

    Ok(())
}
