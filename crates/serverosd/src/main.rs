//! `serverosd`: the ServerOS daemon and its command line.
//!
//! ```text
//! serverosd run                    the long-running service (what systemd starts)
//! serverosd enrol --token …        first-time enrolment on this machine
//! serverosd status                 what the running daemon is doing
//! serverosd inventory              a read-only discovery scan, printed
//! serverosd doctor                 checks a person can act on
//! serverosd update [--to X]        check for, or install, a release
//! serverosd disconnect             stop management, keep everything running
//! serverosd uninstall --yes        remove ServerOS, leave the server as it was
//! serverosd version
//! ```

mod cli;
mod daemon;
mod logging;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use daemon_core::{BuildInfo, Paths};

#[derive(Parser)]
#[command(name = "serverosd", version = BuildInfo::current().version, about = "The ServerOS daemon")]
struct Cli {
    /// Re-root every path under this directory (for tests and dry runs).
    #[arg(long, global = true, hide = true)]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon in the foreground (systemd runs this).
    Run,
    /// Enrol this machine with the panel using a one-time token.
    Enrol {
        #[arg(long)]
        token: String,
        /// Panel base URL (build default: SERVEROS_PANEL_URL).
        #[arg(long, default_value = daemon_core::links::DEFAULT_PANEL_URL)]
        panel: String,
        /// Print what would happen and stop before changing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Show what the running daemon is doing.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Run a discovery scan and print what was found.
    Inventory {
        #[arg(long)]
        json: bool,
    },
    /// Check the installation and explain anything wrong.
    Doctor,
    /// Check for a release, or install a specific version.
    Update {
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        check: bool,
    },
    /// Stop management. Services keep running; credentials are removed.
    Disconnect {
        #[arg(long)]
        yes: bool,
    },
    /// Remove ServerOS from this machine.
    Uninstall {
        #[arg(long)]
        yes: bool,
        /// Show what would be removed and stop.
        #[arg(long)]
        plan: bool,
    },
    /// Print the version and build.
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
