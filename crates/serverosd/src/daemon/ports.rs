//! Opening and closing a port to the internet: read the firewall, work out
//! the fewest changes that do it, make them, then read it again and check.
//!
//! Closing never removes a rule that covers more than the one port; when
//! something broader lets it in, a deny goes in front instead. SSH and ports
//! Docker publishes are refused: one locks everyone out, and the other
//! wouldn't be closed at all, since Docker's rules come first.

use std::path::Path;
use std::time::Duration;

use daemon_core::config::FirewallBackend;
use daemon_inventory::firewall::{self, Ruleset, MARK, NFT_CHAIN, NFT_TABLE};
use daemon_inventory::{docker, exec, listeners};
use daemon_jobs::{Failure, JobContext};
use daemon_protocol::{Exposure, FirewallAction, Listener};
use serde_json::{json, Value};

use super::machine::run;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// `ufw delete …`, naming the rule as ufw does.
    UfwDelete(Vec<String>),
    /// `ufw …`; `first` puts it ahead of every other rule (`ufw prepend`).
    UfwAdd {
        args: Vec<String>,
        first: bool,
    },
    /// A rule in ServerOS's nftables chain, by handle.
    NftDelete(u64),
    NftAdd(String),
    /// `iptables -D INPUT …`.
    IptDelete(Vec<String>),
    /// `iptables -I INPUT 1 …`.
    IptInsert(Vec<String>),
}

/// The changes that open or close `port/proto`, or why ServerOS won't.
pub fn plan(ruleset: &Ruleset, port: u16, proto: &str, open: bool) -> Result<Vec<Step>, String> {
    let (exposure, because) = ruleset.exposure(port, proto);
    let done = if open {
        ruleset.least_exposure(port, proto).0 == Exposure::Open
    } else {
        matches!(exposure, Exposure::Blocked | Exposure::Restricted)
    };
    if done {
        return Ok(Vec::new());
    }

    let name = firewall::backend_name(ruleset.backend);
    if !ruleset.readable {
        return Err(format!(
            "Couldn't read {name}'s rules, so ServerOS won't change them. Check `{name}` works on the machine."
        ));
    }
    if !open {
        if ruleset.backend == FirewallBackend::None {
            return Err("No firewall backend is set for this machine, so there's nothing to close the port with. Set `[integrations] firewall` in /etc/serveros/daemon.toml.".into());
        }
        if !ruleset.installed {
            return Err(format!("{name} isn't installed on this machine, so nothing can close the port. Install it (apt install {name}) and turn it on first."));
        }
        if !ruleset.active {
            return Err(format!("{name} is installed but turned off, so it isn't blocking anything and a rule wouldn't either. Turn it on first, after allowing SSH."));
        }
    }

    let spec = format!("{port}/{proto}");
    let mut steps = Vec::new();

    match ruleset.backend {
        FirewallBackend::Ufw => {
            let mut left = ruleset.clone();
            left.chains[0].rules.retain(|rule| {
                let remove = rule.just(port, proto) && rule.info.verdict.lets_in() != open;
                // Deleting a rule deletes its IPv6 copy too, or the IPv6 rule
                // alone when that's all there is. ufw won't put a deny ahead
                // of an IPv6 allow for the same port, so it has to go.
                let step = Step::UfwDelete(rule.spec.clone());
                if remove && !steps.contains(&step) {
                    steps.push(step);
                }
                !remove
            });
            let (now, _) = left.exposure(port, proto);
            let add = if open && left.least_exposure(port, proto).0 != Exposure::Open {
                // Added last, an allow only beats the default. A rule that
                // blocks it for everyone, like a deny for a range, would
                // still come first, so the allow goes ahead of it.
                let blocked_by_rule = left.chains[0].rules.iter().any(|r| {
                    r.covers(port, proto) && r.info.source.is_none() && !r.info.verdict.lets_in()
                });
                Some(("allow", blocked_by_rule))
            } else if !open && !matches!(now, Exposure::Blocked | Exposure::Restricted) {
                // Open, or a rule ServerOS can't read may let it in: a deny
                // ahead of everything settles it either way.
                Some(("deny", !left.chains[0].rules.is_empty()))
            } else {
                None
            };
            if let Some((verdict, first)) = add {
                if first {
                    // ufw skips a rule it already has further down, so that
                    // one goes before it's put first.
                    for rule in left.chains[0].rules.iter().filter(|r| r.just(port, proto)) {
                        let step = Step::UfwDelete(rule.spec.clone());
                        if !steps.contains(&step) {
                            steps.push(step);
                        }
                    }
                }
                steps.push(Step::UfwAdd {
                    args: words(&[verdict, &spec, "comment", MARK]),
                    first,
                });
            }
        }
        FirewallBackend::Nftables => {
            let ours = ruleset.chains.iter().find(|c| c.managed);
            for rule in ours.into_iter().flat_map(|c| &c.rules) {
                if rule.just(port, proto) && rule.info.verdict.lets_in() != open {
                    steps.extend(rule.handle.map(Step::NftDelete));
                }
            }
            if open {
                // An accept here can't undo a drop in another table: every
                // input chain has to let it through. When other tables let
                // it in over IPv4 or IPv6, ServerOS's own drops still go,
                // and the check afterwards says what's still blocked.
                let mut others = ruleset.clone();
                others.chains.retain(|c| !c.managed);
                match others.exposure(port, proto) {
                    (Exposure::Open | Exposure::Docker, _) => {}
                    (Exposure::Restricted, why) => {
                        return Err(format!("{spec} is allowed only from some addresses by nftables rules outside ServerOS's own ({why}). Change it where those are set up, usually /etc/nftables.conf."));
                    }
                    (_, why) => {
                        return Err(format!("{spec} is blocked by nftables rules outside ServerOS's own ({why}). Change it where those are set up, usually /etc/nftables.conf."));
                    }
                }
            } else {
                let already = ours.is_some_and(|c| {
                    c.rules
                        .iter()
                        .any(|r| r.just(port, proto) && !r.info.verdict.lets_in())
                });
                if !already {
                    steps.push(Step::NftAdd(format!(
                        "iifname != \"lo\" {proto} dport {port} drop"
                    )));
                }
            }
        }
        FirewallBackend::Iptables => {
            let mut left = ruleset.clone();
            left.chains[0].rules.retain(|rule| {
                let remove = rule.just(port, proto)
                    && rule.info.verdict.lets_in() != open
                    && (open || rule.info.managed);
                if remove {
                    steps.push(Step::IptDelete(rule.spec.clone()));
                }
                !remove
            });
            if open && left.least_exposure(port, proto).0 != Exposure::Open {
                steps.push(Step::IptInsert(iptables_rule(port, proto, "ACCEPT")));
            } else if !open
                && !matches!(
                    left.exposure(port, proto).0,
                    Exposure::Blocked | Exposure::Restricted
                )
            {
                steps.push(Step::IptInsert(iptables_rule(port, proto, "DROP")));
            }
        }
        FirewallBackend::None => {
            return Err(format!("{spec} can't be changed: {because}."));
        }
    }

    Ok(steps)
}

fn iptables_rule(port: u16, proto: &str, verdict: &str) -> Vec<String> {
    let port = port.to_string();
    let mut args = Vec::new();
    if verdict == "DROP" {
        // Local programs keep reaching it over loopback.
        args.extend(words(&["!", "-i", "lo"]));
    }
    args.extend(words(&[
        "-p",
        proto,
        "-m",
        proto,
        "--dport",
        &port,
        "-m",
        "comment",
        "--comment",
        MARK,
        "-j",
        verdict,
    ]));
    args
}

fn words(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

/// Why closing this port is refused, if it is.
pub fn refuse_close(port: u16, ssh_ports: &[u16], docker_ports: &[u16]) -> Option<String> {
    if ssh_ports.contains(&port) {
        return Some(format!("Port {port} is SSH. Closing it could lock everyone out of this machine, so ServerOS won't. To limit who can reach it, allow only your own addresses on the machine."));
    }
    if docker_ports.contains(&port) {
        return Some(format!("Port {port} is published by a Docker container. Docker's rules come before the firewall's, so a firewall rule wouldn't close it. Publish it on 127.0.0.1 instead (\"127.0.0.1:{port}:\" and the container's port, in the compose file's ports) and redeploy."));
    }
    None
}

/// The ports SSH listens on: 22, any `Port` in its config, and whatever
/// sshd itself is listening on.
pub fn ssh_ports(listeners: &[Listener], configs: &[String]) -> Vec<u16> {
    let mut ports = vec![22];
    for config in configs {
        for line in config.lines() {
            let mut words = line.split_whitespace();
            if words.next().is_some_and(|w| w.eq_ignore_ascii_case("port")) {
                ports.extend(words.next().and_then(|p| p.parse::<u16>().ok()));
            }
        }
    }
    for listener in listeners {
        let exe = listener.exe.as_deref().unwrap_or("");
        let name = exe.rsplit('/').next().unwrap_or("");
        if name.starts_with("sshd") {
            ports.push(listener.port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn ssh_configs() -> Vec<String> {
    let mut files = vec![std::path::PathBuf::from("/etc/ssh/sshd_config")];
    if let Ok(dir) = std::fs::read_dir("/etc/ssh/sshd_config.d") {
        files.extend(dir.flatten().map(|e| e.path()));
    }
    files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .collect()
}

/// `PORT` or `PORT/PROTO`.
pub fn parse_target(rule: &str) -> Option<(u16, String)> {
    let (port, proto) = rule.trim().split_once('/').unwrap_or((rule.trim(), "tcp"));
    let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
    matches!(proto, "tcp" | "udp").then(|| (port, proto.to_string()))
}

pub async fn change(
    ctx: &JobContext,
    backend: FirewallBackend,
    state_dir: &Path,
    action: FirewallAction,
    rule: &str,
) -> Result<Value, Failure> {
    let open = action == FirewallAction::Open;
    let Some((port, proto)) = parse_target(rule) else {
        return Err(Failure::new(
            "firewall",
            format!("{rule:?} isn't a port: use PORT or PORT/tcp or PORT/udp"),
        ));
    };

    let (listening, _) = listeners::discover(Path::new("/proc"));
    let docker_ports: Vec<u16> =
        docker::discover(Path::new(docker::SOCKET), Duration::from_secs(5))
            .await
            .map(|(containers, _)| {
                containers
                    .iter()
                    .filter(|c| c.state == "running")
                    .flat_map(|c| c.ports.clone())
                    .collect()
            })
            .unwrap_or_default();

    if !open {
        if let Some(why) = refuse_close(port, &ssh_ports(&listening, &ssh_configs()), &docker_ports)
        {
            return Err(Failure::new("firewall", why));
        }
    }

    ctx.progress.phase("reading the firewall", Some(10)).await;
    let before = firewall::read(backend, Duration::from_secs(15)).await;
    if open && docker_ports.contains(&port) {
        // Docker's own rules already let it in, whatever the firewall says.
        return Ok(json!({
            "port": port,
            "proto": proto,
            "exposure": Exposure::Docker,
            "because": firewall::DOCKER_REASON,
            "changes": 0,
            "firewall": before.report(&listening, &docker_ports),
        }));
    }
    let steps = plan(&before, port, &proto, open).map_err(|e| Failure::new("firewall", e))?;

    ctx.progress.phase("changing the firewall", Some(40)).await;
    for step in &steps {
        apply(ctx, step).await?;
    }
    if !steps.is_empty() {
        persist(ctx, backend, state_dir).await;
    }

    ctx.progress.phase("checking", Some(90)).await;
    let after = firewall::read(backend, Duration::from_secs(15)).await;
    // Opened means open over IPv4 and IPv6; closed means closed over both.
    let (exposure, because) = if open {
        after.least_exposure(port, &proto)
    } else {
        after.exposure(port, &proto)
    };
    let worked = match exposure {
        Exposure::Open => open,
        Exposure::Blocked | Exposure::Restricted => !open,
        Exposure::Unknown | Exposure::Docker => false,
    };
    if !worked {
        return Err(Failure::new(
            "firewall",
            format!(
                "{port}/{proto} {} after the change: {because}",
                match (open, exposure) {
                    (_, Exposure::Unknown) => "may still be open",
                    (true, _) => "is still blocked",
                    (false, _) => "is still open",
                }
            ),
        )
        .with_next_step(
            "Look at the firewall's rules on the machine: a broader rule may be deciding it.",
        ));
    }

    Ok(json!({
        "port": port,
        "proto": proto,
        "exposure": exposure,
        "because": because,
        "changes": steps.len(),
        "firewall": after.report(&listening, &docker_ports),
    }))
}

async fn apply(ctx: &JobContext, step: &Step) -> Result<(), Failure> {
    let (program, args): (&str, Vec<String>) = match step {
        Step::UfwDelete(spec) => (
            "ufw",
            [vec!["--force".into(), "delete".into()], spec.clone()].concat(),
        ),
        Step::UfwAdd { args, first: false } => ("ufw", args.clone()),
        Step::UfwAdd { args, first: true } => {
            let args = [vec!["prepend".to_string()], args.clone()].concat();
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            if run(ctx, "ufw", &refs, 60).await.success() {
                return Ok(());
            }
            // ufw before 0.36 has no prepend.
            (
                "ufw",
                [words(&["insert", "1"]), args[1..].to_vec()].concat(),
            )
        }
        Step::NftDelete(handle) => {
            let delete = format!("delete rule inet {NFT_TABLE} {NFT_CHAIN} handle {handle}");
            ("nft", vec![delete])
        }
        Step::NftAdd(expression) => {
            for setup in [
                format!("add table inet {NFT_TABLE}"),
                format!("add chain inet {NFT_TABLE} {NFT_CHAIN} {{ type filter hook input priority 0; policy accept; }}"),
            ] {
                let outcome = run(ctx, "nft", &[setup.as_str()], 30).await;
                if !outcome.success() {
                    return Err(Failure::new("firewall", "could not prepare the nftables table")
                        .with_output(outcome.tail().to_vec()));
                }
            }
            let add = format!("add rule inet {NFT_TABLE} {NFT_CHAIN} {expression}");
            ("nft", vec![add])
        }
        Step::IptDelete(spec) => ("iptables", [words(&["-D", "INPUT"]), spec.clone()].concat()),
        Step::IptInsert(spec) => (
            "iptables",
            [words(&["-I", "INPUT", "1"]), spec.clone()].concat(),
        ),
    };

    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = run(ctx, program, &refs, 60).await;
    if outcome.success() {
        Ok(())
    } else {
        Err(
            Failure::new("firewall", format!("{program} refused: {}", args.join(" ")))
                .with_output(outcome.tail().to_vec()),
        )
    }
}

/// Where ServerOS keeps its nftables table between restarts.
pub fn nft_saved(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("firewall.nft")
}

/// Keep the change past a reboot. ufw saves its own rules; nftables and
/// iptables only hold them in the kernel.
pub async fn persist(ctx: &JobContext, backend: FirewallBackend, state_dir: &Path) {
    match backend {
        FirewallBackend::Nftables => {
            let table = exec::output(
                "nft",
                &["list", "table", "inet", NFT_TABLE],
                Duration::from_secs(15),
            )
            .await;
            if let Some(table) = table {
                let _ = std::fs::write(nft_saved(state_dir), table);
            }
        }
        FirewallBackend::Iptables if Path::new("/usr/sbin/netfilter-persistent").exists() => {
            let _ = run(ctx, "netfilter-persistent", &["save"], 60).await;
        }
        _ => {}
    }
}

/// Put ServerOS's nftables table back after a reboot, when it isn't there.
pub async fn restore(backend: FirewallBackend, state_dir: &Path) {
    let saved = nft_saved(state_dir);
    if backend != FirewallBackend::Nftables || !saved.exists() {
        return;
    }
    let present = exec::output(
        "nft",
        &["list", "table", "inet", NFT_TABLE],
        Duration::from_secs(15),
    )
    .await
    .is_some();
    if present {
        return;
    }
    let path = saved.to_string_lossy().into_owned();
    match exec::output("nft", &["-f", &path], Duration::from_secs(15)).await {
        Some(_) => tracing::info!("restored ServerOS's nftables rules"),
        None => tracing::warn!(path, "could not restore ServerOS's nftables rules"),
    }
}

#[cfg(test)]
mod tests {
    use daemon_inventory::firewall::{parse_iptables, parse_nft, parse_ufw};

    use super::*;

    const UFW: &str = "Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
5432/tcp                   ALLOW IN    Anywhere
6000:6010/tcp              ALLOW IN    Anywhere
6379/tcp                   DENY IN     Anywhere                   # ServerOS
";

    fn ufw_add(args: &[&str], first: bool) -> Step {
        Step::UfwAdd {
            args: words(args),
            first,
        }
    }

    #[test]
    fn closing_on_ufw_removes_the_one_rule_that_opens_it() {
        let ruleset = parse_ufw(UFW);

        assert_eq!(
            plan(&ruleset, 5432, "tcp", false).unwrap(),
            [Step::UfwDelete(words(&["allow", "5432/tcp"]))]
        );
    }

    #[test]
    fn closing_inside_a_wider_rule_puts_a_deny_first() {
        let ruleset = parse_ufw(UFW);

        assert_eq!(
            plan(&ruleset, 6005, "tcp", false).unwrap(),
            [ufw_add(&["deny", "6005/tcp", "comment", "ServerOS"], true)]
        );
    }

    #[test]
    fn closing_what_an_unreadable_rule_may_let_in_puts_a_deny_first() {
        let ruleset = parse_ufw(
            "Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
6004/tcp on eth0           ALLOW IN    Anywhere
",
        );

        assert_eq!(
            plan(&ruleset, 6004, "tcp", false).unwrap(),
            [ufw_add(&["deny", "6004/tcp", "comment", "ServerOS"], true)]
        );
    }

    #[test]
    fn opening_on_ufw_removes_the_deny_and_allows_it() {
        let ruleset = parse_ufw(UFW);

        assert_eq!(
            plan(&ruleset, 6379, "tcp", true).unwrap(),
            [
                Step::UfwDelete(words(&["deny", "6379/tcp"])),
                ufw_add(&["allow", "6379/tcp", "comment", "ServerOS"], false),
            ]
        );
        assert_eq!(plan(&ruleset, 22, "tcp", true).unwrap(), [], "already open");
        assert_eq!(
            plan(&ruleset, 3306, "tcp", false).unwrap(),
            [],
            "already closed"
        );
    }

    #[test]
    fn a_rule_for_both_protocols_is_left_alone_so_the_other_keeps_working() {
        let ruleset = parse_ufw(
            "Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
53                         ALLOW IN    Anywhere
8001                       DENY IN     Anywhere
",
        );

        assert_eq!(
            plan(&ruleset, 53, "tcp", false).unwrap(),
            [ufw_add(&["deny", "53/tcp", "comment", "ServerOS"], true)]
        );
        assert_eq!(
            plan(&ruleset, 8001, "tcp", true).unwrap(),
            [ufw_add(&["allow", "8001/tcp", "comment", "ServerOS"], true)]
        );
    }

    #[test]
    fn opening_inside_a_denied_range_puts_the_allow_first() {
        let ruleset = parse_ufw(
            "Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
8040:8060/tcp              DENY IN     Anywhere
8070/tcp                   DENY IN     10.0.0.0/8
",
        );

        assert_eq!(
            plan(&ruleset, 8050, "tcp", true).unwrap(),
            [ufw_add(&["allow", "8050/tcp", "comment", "ServerOS"], true)]
        );
        assert_eq!(
            plan(&ruleset, 8070, "tcp", true).unwrap(),
            [ufw_add(
                &["allow", "8070/tcp", "comment", "ServerOS"],
                false
            )],
            "a deny for some addresses doesn't stop an allow for everyone"
        );
    }

    #[test]
    fn a_port_open_only_over_ipv6_is_closed_for_both() {
        let mut ruleset = parse_ufw(
            "Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
8010/tcp (v6)              ALLOW IN    Anywhere (v6)
8030/tcp                   ALLOW IN    Anywhere
8030/tcp (v6)              DENY IN     Anywhere (v6)
",
        );
        ruleset.ipv6 = true;

        assert_eq!(
            plan(&ruleset, 8010, "tcp", false).unwrap(),
            [Step::UfwDelete(words(&["allow", "8010/tcp"]))]
        );
        assert_eq!(
            plan(&ruleset, 8030, "tcp", true).unwrap(),
            [
                Step::UfwDelete(words(&["deny", "8030/tcp"])),
                ufw_add(&["allow", "8030/tcp", "comment", "ServerOS"], false)
            ],
            "open over IPv4 isn't open until IPv6 is too"
        );
        assert_eq!(
            plan(
                &parse_ufw(&format!(
                    "{UFW}5432/tcp (v6)              ALLOW IN    Anywhere (v6)\n"
                )),
                5432,
                "tcp",
                false
            )
            .unwrap(),
            [Step::UfwDelete(words(&["allow", "5432/tcp"]))],
            "a rule and its IPv6 copy go in one delete"
        );
    }

    #[test]
    fn a_rule_put_first_replaces_the_same_rule_further_down() {
        let mut ruleset = parse_ufw(
            "Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
8000/tcp                   ALLOW IN    Anywhere
7990:8009/tcp (v6)         DENY IN     Anywhere (v6)
8000/tcp (v6)              ALLOW IN    Anywhere (v6)
",
        );
        ruleset.ipv6 = true;

        assert_eq!(
            plan(&ruleset, 8000, "tcp", true).unwrap(),
            [
                Step::UfwDelete(words(&["allow", "8000/tcp"])),
                ufw_add(&["allow", "8000/tcp", "comment", "ServerOS"], true)
            ]
        );
    }

    #[test]
    fn ufw_turned_off_is_refused_rather_than_pretending() {
        let ruleset = parse_ufw("Status: inactive\n");

        assert!(plan(&ruleset, 5432, "tcp", false)
            .unwrap_err()
            .contains("turned off"));
        assert_eq!(plan(&ruleset, 5432, "tcp", true).unwrap(), []);
    }

    #[test]
    fn closing_on_nftables_adds_a_drop_to_serveros_chain() {
        let json: Value = serde_json::from_str(r#"{"nftables":[
            {"chain":{"family":"inet","table":"serveros","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}},
            {"rule":{"family":"inet","table":"serveros","chain":"input","handle":7,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":5432}},{"accept":null}]}}
        ]}"#).unwrap();
        let ruleset = parse_nft(&json);

        assert_eq!(
            plan(&ruleset, 5432, "tcp", false).unwrap(),
            [
                Step::NftDelete(7),
                Step::NftAdd("iifname != \"lo\" tcp dport 5432 drop".into())
            ]
        );
    }

    #[test]
    fn rules_that_couldnt_be_read_are_never_changed() {
        let mut ruleset = parse_ufw("Status: active\n");
        ruleset.readable = false;

        assert!(plan(&ruleset, 5432, "tcp", false)
            .unwrap_err()
            .contains("won't change them"));
        assert!(plan(&ruleset, 5432, "tcp", true).is_err());
        assert_eq!(ruleset.exposure(5432, "tcp").0, Exposure::Unknown);
    }

    #[test]
    fn closing_where_nothing_is_set_up_yet_still_works() {
        let nft = parse_nft(&serde_json::json!({"nftables": []}));
        let iptables = parse_iptables("-P INPUT ACCEPT\n");

        assert_eq!(
            plan(&nft, 5432, "tcp", false).unwrap(),
            [Step::NftAdd("iifname != \"lo\" tcp dport 5432 drop".into())]
        );
        assert_eq!(plan(&iptables, 5432, "tcp", false).unwrap().len(), 1);
    }

    #[test]
    fn opening_on_nftables_wont_pretend_to_override_another_table() {
        let json: Value = serde_json::from_str(r#"{"nftables":[
            {"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}}
        ]}"#).unwrap();
        let ruleset = parse_nft(&json);

        assert!(plan(&ruleset, 8080, "tcp", true)
            .unwrap_err()
            .contains("/etc/nftables.conf"));
    }

    #[test]
    fn reopening_on_nftables_removes_serveros_drop_even_if_ipv6_stays_blocked() {
        let json: Value = serde_json::from_str(r#"{"nftables":[
            {"chain":{"family":"inet","table":"serveros","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}},
            {"rule":{"family":"inet","table":"serveros","chain":"input","handle":9,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8003}},{"drop":null}]}},
            {"chain":{"family":"ip6","table":"v6only","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}},
            {"rule":{"family":"ip6","table":"v6only","chain":"input","handle":3,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8003}},{"drop":null}]}}
        ]}"#).unwrap();
        let mut ruleset = parse_nft(&json);
        ruleset.ipv6 = true;

        assert_eq!(
            plan(&ruleset, 8003, "tcp", true).unwrap(),
            [Step::NftDelete(9)]
        );
    }

    #[test]
    fn closing_on_iptables_only_removes_serveros_accept_when_that_is_enough() {
        let ruleset = parse_iptables(
            "-P INPUT ACCEPT
-A INPUT -p tcp -m tcp --dport 8005 -m comment --comment ServerOS -j ACCEPT
-A INPUT -p tcp -m multiport --dports 8005,8006 -j DROP
",
        );

        assert_eq!(
            plan(&ruleset, 8005, "tcp", false).unwrap(),
            [Step::IptDelete(words(&[
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--dport",
                "8005",
                "-m",
                "comment",
                "--comment",
                "ServerOS",
                "-j",
                "ACCEPT"
            ]))]
        );
    }

    #[test]
    fn closing_on_iptables_inserts_a_drop_first() {
        let ruleset =
            parse_iptables("-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 5432 -j ACCEPT\n");

        assert_eq!(
            plan(&ruleset, 5432, "tcp", false).unwrap(),
            [Step::IptInsert(words(&[
                "!",
                "-i",
                "lo",
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--dport",
                "5432",
                "-m",
                "comment",
                "--comment",
                "ServerOS",
                "-j",
                "DROP"
            ]))]
        );
    }

    #[test]
    fn ssh_and_docker_ports_are_never_closed() {
        let sshd = Listener {
            proto: "tcp".into(),
            address: "0.0.0.0".into(),
            port: 2222,
            pid: Some(1),
            exe: Some("/usr/sbin/sshd".into()),
            user: None,
            cmdline: None,
        };
        let ports = ssh_ports(&[sshd], &["# Port 23\nPort 2200\n".into()]);

        assert_eq!(ports, [22, 2200, 2222]);
        assert!(refuse_close(2222, &ports, &[]).unwrap().contains("SSH"));
        assert!(refuse_close(8080, &ports, &[8080])
            .unwrap()
            .contains("Docker"));
        assert_eq!(refuse_close(5432, &ports, &[8080]), None);
    }

    #[test]
    fn targets_are_a_port_and_protocol() {
        assert_eq!(parse_target("5432"), Some((5432, "tcp".into())));
        assert_eq!(parse_target("53/udp"), Some((53, "udp".into())));
        assert_eq!(parse_target("0"), None);
        assert_eq!(parse_target("22/icmp"), None);
        assert_eq!(parse_target("from 1.2.3.4"), None);
    }
}
