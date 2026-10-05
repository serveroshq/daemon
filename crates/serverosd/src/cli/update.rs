use daemon_core::{BuildInfo, Config, Paths};
use daemon_http::{Client, Trust};
use daemon_selfupdate::{decide, install, Candidate, Decision, Policy};

use super::{require_root, runtime};

pub fn run(paths: Paths, to: Option<String>, check_only: bool) -> anyhow::Result<()> {
    let config = Config::load(&paths.config_file())?;
    let current = BuildInfo::current().version;
    let policy = Policy::from(&config.updates);
    let rt = runtime()?;

    let url = format!(
        "https://{}/api/daemon/releases/latest?channel={}&arch={}",
        config.panel.host,
        config.updates.channel,
        std::env::consts::ARCH
    );
    let client = Client::new(Trust::WebPki, format!("serverosd/{current} (update-check)"));
    let response = rt.block_on(client.get(&url))?;

    if response.status != 200 {
        anyhow::bail!("the release feed answered HTTP {}", response.status);
    }

    let candidate: Candidate = response
        .json()
        .map_err(|e| anyhow::anyhow!("release feed was not understood: {e}"))?;
    let explicit = to.is_some();

    if let Some(wanted) = &to {
        if daemon_core::buildinfo::parse_semver(wanted)
            != daemon_core::buildinfo::parse_semver(&candidate.version)
        {
            anyhow::bail!(
                "the feed offers {}, not {wanted}; only the offered release can be installed",
                candidate.version
            );
        }
    }

    let decision = decide(&policy, current, &candidate, explicit, 0, 0);
    println!(
        "installed: {current}\noffered:   {} ({})",
        candidate.version, candidate.channel
    );

    match decision {
        Decision::Refuse(reason) => {
            println!("decision:  refused: {reason}");
            return Ok(());
        }
        Decision::NeedsApproval(reason) => {
            println!("decision:  needs approval: {reason}");
            println!(
                "           run `serverosd update --to {}` to install it explicitly",
                candidate.version
            );
            return Ok(());
        }
        Decision::Defer(reason) => println!(
            "decision:  would defer while running ({reason}); installing now because you asked"
        ),
        Decision::Install => println!("decision:  install"),
    }

    if check_only {
        return Ok(());
    }

    require_root("installing an update")?;

    let installed = rt.block_on(install(
        &paths.binary,
        &paths.state_dir,
        current,
        &candidate,
        |host| config.updates.permits_host(&config.panel.host, host),
    ))?;

    println!(
        "installed {} → {} (previous kept at {})",
        installed.from,
        installed.to,
        installed.previous_binary.display()
    );
    println!("restart to apply: systemctl restart serverosd");

    Ok(())
}
