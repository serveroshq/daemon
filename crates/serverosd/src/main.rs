mod cli;
mod daemon;
mod logging;
mod settings;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use daemon_core::error_reports;
use daemon_core::{BuildInfo, Paths};

#[derive(Parser)]
#[command(name = "serverosd", version = BuildInfo::current().version, about = "The ServerOS daemon")]
struct Cli {
    #[arg(long, global = true, hide = true)]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run,
    Enrol {
        #[arg(long)]
        token: String,
        #[arg(long, default_value = daemon_core::links::DEFAULT_PANEL_URL)]
        panel: String,
        #[arg(long)]
        dry_run: bool,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
    Inventory {
        #[arg(long)]
        json: bool,
    },
    Doctor,
    Update {
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        check: bool,
    },
    Disconnect {
        #[arg(long)]
        yes: bool,
    },
    Uninstall {
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        plan: bool,
    },
    Version,
    /// Tools for checking a build; not part of the everyday CLI.
    #[command(hide = true)]
    Debug {
        #[command(subcommand)]
        command: DebugCommand,
    },
}

#[derive(Subcommand)]
enum DebugCommand {
    /// Send one test error report and wait for it to go.
    SentryTest,
}

fn main() {
    let cli = Cli::parse();
    let paths = cli.root.as_deref().map(Paths::under).unwrap_or_default();

    let file = error_reports::FileSettings::read(&paths.config_file());
    let decision = error_reports::decide(&file);
    let tags = error_reports::daemon_tags(file.machine_id.as_deref());
    let tags: Vec<(&str, &str)> = tags.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let reports = error_reports::init("serverosd", BuildInfo::current().version, &decision, &tags);
    let is_run = matches!(cli.command, Command::Run);

    let result = match cli.command {
        Command::Run => daemon::run(paths),
        Command::Enrol {
            token,
            panel,
            dry_run,
        } => cli::enrol::run(paths, &token, &panel, dry_run),
        Command::Status { json } => cli::status::run(paths, json),
        Command::Inventory { json } => cli::inventory::run(json),
        Command::Doctor => cli::doctor::run(paths),
        Command::Update { to, check } => cli::update::run(paths, to, check),
        Command::Disconnect { yes } => cli::uninstall::disconnect(paths, yes),
        Command::Uninstall { yes, plan } => cli::uninstall::run(paths, yes, plan),
        Command::Version => {
            println!("{}", BuildInfo::current().banner());
            Ok(())
        }
        Command::Debug {
            command: DebugCommand::SentryTest,
        } => sentry_test(&decision, reports.is_on()),
    };

    if let Err(e) = result {
        // The daemon stopping on an error is worth a report; a CLI command
        // refusing (not root, not enrolled) is not.
        if is_run {
            error_reports::capture_error(&format!("serverosd run stopped: {e:#}"));
        }
        eprintln!("serverosd: {e:#}");
        error_reports::flush(std::time::Duration::from_secs(2));
        std::process::exit(1);
    }
}

fn sentry_test(decision: &error_reports::Decision, on: bool) -> anyhow::Result<()> {
    match decision {
        error_reports::Decision::TurnedOff(why) => {
            anyhow::bail!("error reports are off ({why}), so nothing was sent")
        }
        error_reports::Decision::NoDsn => anyhow::bail!(
            "this build has no error report address; set SERVEROS_SENTRY_DSN or [error_reports] dsn"
        ),
        error_reports::Decision::On { .. } if !on => {
            anyhow::bail!("the error report address isn't a valid Sentry DSN")
        }
        error_reports::Decision::On { .. } => {}
    }

    let id = error_reports::capture_error("serverosd debug sentry-test: this is a test error");
    let flushed = error_reports::flush(std::time::Duration::from_secs(10));
    let outcome = error_reports::last_delivery().unwrap_or_else(|| "nothing sent".into());

    if !flushed {
        anyhow::bail!("test event {id} did not go out within 10 seconds ({outcome})");
    }
    if !outcome.starts_with("HTTP 2") {
        anyhow::bail!("test event {id} was not accepted: {outcome}");
    }
    println!(
        "sent test event {id} ({}): {outcome}",
        error_reports::environment()
    );
    Ok(())
}
