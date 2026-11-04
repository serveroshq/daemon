//! The daemon's side of project networks (crates/daemon-network): one
//! `Networks` for the machine, and every stored network brought back up
//! when the daemon starts, each checked and written to actions.log.

use std::sync::Arc;

use daemon_audit::Actor;
use daemon_capability::{MachineOp, Operation, Request};
use daemon_network::exec::SystemExec;
use tracing::{info, warn};

use super::App;

pub async fn restore_all(app: Arc<App>) {
    let backend = app
        .config
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .integrations
        .firewall;

    app.networks
        .restore(
            &SystemExec,
            backend,
            |network| {
                app.broker
                    .authorize(Request {
                        actor: Actor::daemon(),
                        operation: Operation::Machine(MachineOp::WriteNetwork {
                            network: network.to_string(),
                        }),
                        confirmed: false,
                    })
                    .map_err(
                        |denied| warn!(network, reason = %denied, "not bringing a network back up"),
                    )
                    .ok()
            },
            |grant, network, result| {
                grant.finish(
                    &result.as_ref().map(|_| ()),
                    Some("brought back up on start"),
                );
                match result {
                    Ok(_) => info!(network, "network up"),
                    Err(e) => warn!(network, error = %e, "couldn't bring a network back up"),
                }
            },
        )
        .await;
}
