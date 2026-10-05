mod cli;
mod daemon;
mod logging;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
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
}

fn main() {
    let cli = Cli::parse();
    let paths = cli.root.as_deref().map(Paths::under).unwrap_or_default();

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
    };

    if let Err(e) = result {
        eprintln!("serverosd: {e:#}");
        std::process::exit(1);
    }
}
