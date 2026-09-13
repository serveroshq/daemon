//! Machine-level jobs that are small enough to live here: package
//! updates, reboot, firewall rules, and SSH keys for managed users.

use std::path::Path;
use std::time::Duration;

use daemon_core::config::FirewallBackend;
use daemon_jobs::{run_child, ChildOutcome, Failure, JobContext};
use daemon_protocol::{FirewallAction, KeyAction};

#[derive(serde::Serialize)]
pub struct PackageReport {
    pub manager: String,
    pub upgradable: Vec<String>,
    pub security: Vec<String>,
    pub reboot_required: bool,
    pub applied: bool,
}

fn manager() -> Option<&'static str> {
    if Path::new("/usr/bin/apt-get").exists() {
        Some("apt")
    } else if Path::new("/usr/bin/dnf").exists() {
        Some("dnf")
    } else if Path::new("/usr/bin/yum").exists() {
        Some("yum")
    } else {
        None
    }
}

pub async fn package_updates(
    ctx: &JobContext,
    apply: bool,
    security_only: bool,
) -> Result<PackageReport, Failure> {
    let manager = manager().ok_or_else(|| {
        Failure::new(
            "packages",
            "no supported package manager (apt, dnf, yum) on this machine",
        )
    })?;
    let mut cancel = ctx.cancel.clone();
    let progress = &ctx.progress;

    let (upgradable, security) = match manager {
        "apt" => {
            let _ = run_child(
                "apt-get",
                &["update", "-q"],
                None,
                &[("DEBIAN_FRONTEND", "noninteractive")],
                Duration::from_secs(300),
                &mut cancel,
                progress,
                None,
            )
            .await;
            let outcome = run_child(
                "apt",
                &["list", "--upgradable"],
                None,
                &[("DEBIAN_FRONTEND", "noninteractive")],
                Duration::from_secs(120),
                &mut cancel,
                progress,
                None,
            )
            .await;
            let lines: Vec<String> = outcome
                .tail()
                .iter()
                .filter(|l| l.contains('/') && l.contains('['))
                .cloned()
                .collect();
            let security: Vec<String> = lines
                .iter()
                .filter(|l| l.contains("-security"))
                .cloned()
                .collect();
            (lines, security)
        }
        _ => {
            let outcome = run_child(
                manager,
                &["check-update", "-q"],
                None,
                &[],
                Duration::from_secs(300),
                &mut cancel,
                progress,
                None,
            )
            .await;
            let lines: Vec<String> = outcome
                .tail()
                .iter()
                .filter(|l| l.split_whitespace().count() == 3)
                .cloned()
                .collect();
            let outcome = run_child(
                manager,
                &["updateinfo", "list", "security", "-q"],
                None,
                &[],
                Duration::from_secs(120),
                &mut cancel,
                progress,
                None,
            )
            .await;
            let security: Vec<String> = outcome.tail().to_vec();
            (lines, security)
        }
    };

    let mut applied = false;

    if apply {
        progress.phase("apply", Some(50)).await;
        let outcome = match (manager, security_only) {
            ("apt", true) => {
                run_child(
                    "unattended-upgrade",
                    &["-v"],
                    None,
                    &[("DEBIAN_FRONTEND", "noninteractive")],
                    ctx.timeout,
                    &mut cancel,
                    progress,
                    None,
                )
                .await
            }
            ("apt", false) => {
                run_child(
                    "apt-get",
                    &[
                        "-y",
                        "-q",
                        "-o",
                        "Dpkg::Options::=--force-confold",
                        "upgrade",
                    ],
                    None,
                    &[("DEBIAN_FRONTEND", "noninteractive")],
                    ctx.timeout,
                    &mut cancel,
                    progress,
                    None,
                )
                .await
            }
            (m, true) => {
                run_child(
                    m,
                    &["-y", "-q", "upgrade", "--security"],
                    None,
                    &[],
                    ctx.timeout,
                    &mut cancel,
                    progress,
                    None,
                )
                .await
            }
            (m, false) => {
                run_child(
                    m,
                    &["-y", "-q", "upgrade"],
                    None,
                    &[],
                    ctx.timeout,
                    &mut cancel,
                    progress,
                    None,
                )
                .await
            }
        };

        match outcome {
            ChildOutcome::Exited { code: 0, .. } => applied = true,
            ChildOutcome::Cancelled { tail } => {
                return Err(Failure::new("cancelled", "package upgrade cancelled").with_output(tail))
            }
            other => {
                return Err(
                    Failure::new("apply", format!("{manager} upgrade did not complete"))
                        .with_output(other.tail().to_vec())
                        .with_next_step(
                            "Check the output; a held or broken package usually needs a person.",
                        ),
                )
            }
        }
    }

    Ok(PackageReport {
        manager: manager.into(),
        upgradable,
        security,
        reboot_required: Path::new("/var/run/reboot-required").exists()
            || Path::new("/run/reboot-required").exists(),
        applied,
    })
}

/// Schedule a reboot a few seconds out so the job result reaches the
/// panel first.
pub fn reboot_soon() {
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = std::process::Command::new("systemctl")
            .arg("reboot")
            .status();
    });
}

pub fn valid_firewall_rule(rule: &str) -> bool {
    !rule.is_empty()
        && rule.len() < 120
        && rule.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '/' | '.' | ':' | ',' | '-' | '_')
        })
}

/// The subset of ufw's rule syntax every backend understands:
/// `PORT[/PROTO]` or `from CIDR to any port PORT [proto PROTO]`. ufw gets
/// the rule verbatim; nftables and iptables get this parsed form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRule {
    pub port: u16,
    pub proto: String,
    pub source: Option<String>,
}

pub fn parse_port_rule(rule: &str) -> Option<PortRule> {
    let words: Vec<&str> = rule.split_whitespace().collect();

    let (port_spec, source, proto_word) = match words.as_slice() {
        [spec] => (*spec, None, None),
        ["from", source, "to", "any", "port", spec] => (*spec, Some(*source), None),
        ["from", source, "to", "any", "port", spec, "proto", proto] => {
            (*spec, Some(*source), Some(*proto))
        }
        _ => return None,
    };

    let (port, proto) = match port_spec.split_once('/') {
        Some((port, proto)) => (port, Some(proto)),
        None => (port_spec, proto_word),
    };
    let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
    let proto = proto.unwrap_or("tcp");

    if !matches!(proto, "tcp" | "udp") {
        return None;
    }

    if let Some(source) = source {
        let valid = source
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'));
        if !valid {
            return None;
        }
    }

    Some(PortRule {
        port,
        proto: proto.to_string(),
        source: source.map(str::to_string),
    })
}

impl PortRule {
    /// The rule as nftables spells it inside our chain.
    pub fn nft_expression(&self, action: FirewallAction) -> String {
        let verdict = match action {
            FirewallAction::Deny => "drop",
            FirewallAction::Allow | FirewallAction::Delete => "accept",
        };
        let source = match &self.source {
            Some(s) if s.contains(':') => format!("ip6 saddr {s} "),
            Some(s) => format!("ip saddr {s} "),
            None => String::new(),
        };

        format!("{source}{} dport {} {verdict}", self.proto, self.port)
    }

    /// iptables arguments after the chain operation.
    pub fn iptables_args(&self, action: FirewallAction) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(source) = &self.source {
            args.extend(["-s".to_string(), source.clone()]);
        }

        args.extend([
            "-p".to_string(),
            self.proto.clone(),
            "--dport".to_string(),
            self.port.to_string(),
            "-j".to_string(),
            match action {
                FirewallAction::Deny => "DROP",
                FirewallAction::Allow | FirewallAction::Delete => "ACCEPT",
            }
            .to_string(),
        ]);

        args
    }
}

const NFT_TABLE: &str = "inet serveros";
const NFT_CHAIN: &str = "input";

pub async fn firewall(
    ctx: &JobContext,
    backend: FirewallBackend,
    action: FirewallAction,
    rule: &str,
) -> Result<Vec<String>, Failure> {
    if !valid_firewall_rule(rule) {
        return Err(Failure::new(
            "firewall",
            format!("{rule:?} is not a rule ServerOS will pass to the firewall"),
        ));
    }

    match backend {
        FirewallBackend::Ufw => firewall_ufw(ctx, action, rule).await,
        FirewallBackend::Nftables => firewall_nft(ctx, action, rule).await,
        FirewallBackend::Iptables => firewall_iptables(ctx, action, rule).await,
        FirewallBackend::None => Err(Failure::new(
            "firewall",
            "no firewall backend is configured on this machine",
        )
        .with_next_step(
            "Set `[integrations] firewall` to ufw, nftables, or iptables in daemon.toml.",
        )),
    }
}

fn require_tool(tool: &str, paths: &[&str], install: &str) -> Result<(), Failure> {
    if paths.iter().any(|p| Path::new(p).exists()) {
        Ok(())
    } else {
        Err(Failure::new(
            "firewall",
            format!("{tool} is not installed on this machine"),
        )
        .with_next_step(install))
    }
}

async fn run(
    ctx: &JobContext,
    program: &str,
    args: &[&str],
    secs: u64,
) -> daemon_jobs::child::ChildOutcome {
    let mut cancel = ctx.cancel.clone();

    run_child(
        program,
        args,
        None,
        &[],
        Duration::from_secs(secs),
        &mut cancel,
        &ctx.progress,
        None,
    )
    .await
}

async fn firewall_ufw(
    ctx: &JobContext,
    action: FirewallAction,
    rule: &str,
) -> Result<Vec<String>, Failure> {
    require_tool("ufw", &["/usr/sbin/ufw"], "apt install ufw")?;

    let mut args: Vec<&str> = match action {
        FirewallAction::Allow => vec!["allow"],
        FirewallAction::Deny => vec!["deny"],
        FirewallAction::Delete => vec!["delete", "allow"],
    };
    args.extend(rule.split_whitespace());

    let outcome = run(ctx, "ufw", &args, 60).await;

    if !outcome.success() {
        return Err(
            Failure::new("firewall", "ufw refused the rule").with_output(outcome.tail().to_vec())
        );
    }

    Ok(run(ctx, "ufw", &["status", "numbered"], 30)
        .await
        .tail()
        .to_vec())
}

fn parsed(rule: &str) -> Result<PortRule, Failure> {
    parse_port_rule(rule).ok_or_else(|| {
        Failure::new(
            "firewall",
            format!("{rule:?} is not a port rule this backend can apply"),
        )
        .with_next_step(
            "Use `PORT/PROTO` or `from CIDR to any port PORT`, or switch the backend to ufw.",
        )
    })
}

async fn firewall_nft(
    ctx: &JobContext,
    action: FirewallAction,
    rule: &str,
) -> Result<Vec<String>, Failure> {
    require_tool(
        "nft",
        &["/usr/sbin/nft", "/sbin/nft"],
        "apt install nftables",
    )?;
    let port_rule = parsed(rule)?;
    let expression = port_rule.nft_expression(action);

    // Our own table and chain, created idempotently; nothing of the
    // operator's is touched.
    let table = format!("add table {NFT_TABLE}");
    let chain = format!(
        "add chain {NFT_TABLE} {NFT_CHAIN} {{ type filter hook input priority 0; policy accept; }}"
    );
    for setup in [table, chain] {
        let outcome = run(ctx, "nft", &[setup.as_str()], 30).await;
        if !outcome.success() {
            return Err(
                Failure::new("firewall", "could not prepare the nftables table")
                    .with_output(outcome.tail().to_vec()),
            );
        }
    }

    match action {
        FirewallAction::Allow | FirewallAction::Deny => {
            let add = format!("add rule {NFT_TABLE} {NFT_CHAIN} {expression}");
            let outcome = run(ctx, "nft", &[add.as_str()], 30).await;
            if !outcome.success() {
                return Err(Failure::new("firewall", "nft refused the rule")
                    .with_output(outcome.tail().to_vec()));
            }
        }
        FirewallAction::Delete => {
            let list = format!("list chain {NFT_TABLE} {NFT_CHAIN}");
            let listing = run(ctx, "nft", &["-a", list.as_str()], 30).await;
            let Some(handle) = nft_handle(listing.tail(), &expression) else {
                return Err(Failure::new(
                    "firewall",
                    format!("no rule matching {rule:?} in the ServerOS chain"),
                ));
            };
            let delete = format!("delete rule {NFT_TABLE} {NFT_CHAIN} handle {handle}");
            let outcome = run(ctx, "nft", &[delete.as_str()], 30).await;
            if !outcome.success() {
                return Err(Failure::new("firewall", "nft could not delete the rule")
                    .with_output(outcome.tail().to_vec()));
            }
        }
    }

    let list = format!("list chain {NFT_TABLE} {NFT_CHAIN}");
    Ok(run(ctx, "nft", &[list.as_str()], 30).await.tail().to_vec())
}

/// Find the handle of the rule whose text matches, in `nft -a list` output
/// (`… tcp dport 22 accept # handle 7`).
pub fn nft_handle(lines: &[String], expression: &str) -> Option<u64> {
    lines.iter().find_map(|line| {
        let (rule, handle) = line.trim().rsplit_once("# handle ")?;
        (rule.trim() == expression)
            .then(|| handle.trim().parse().ok())
            .flatten()
    })
}

async fn firewall_iptables(
    ctx: &JobContext,
    action: FirewallAction,
    rule: &str,
) -> Result<Vec<String>, Failure> {
    require_tool(
        "iptables",
        &["/usr/sbin/iptables", "/sbin/iptables"],
        "apt install iptables",
    )?;
    let port_rule = parsed(rule)?;
    let ipv6 = port_rule.source.as_deref().is_some_and(|s| s.contains(':'));
    let program = if ipv6 { "ip6tables" } else { "iptables" };

    let mut args = vec![
        match action {
            FirewallAction::Delete => "-D",
            _ => "-A",
        }
        .to_string(),
        "INPUT".to_string(),
    ];
    args.extend(port_rule.iptables_args(action));
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let outcome = run(ctx, program, &arg_refs, 30).await;
    if !outcome.success() {
        return Err(
            Failure::new("firewall", format!("{program} refused the rule"))
                .with_output(outcome.tail().to_vec()),
        );
    }

    let mut status = run(ctx, program, &["-S", "INPUT"], 30)
        .await
        .tail()
        .to_vec();
    if !Path::new("/usr/sbin/netfilter-persistent").exists() {
        status.push(
            "note: iptables rules do not survive a reboot without netfilter-persistent".into(),
        );
    }

    Ok(status)
}

pub fn valid_public_key(key: &str) -> bool {
    let mut parts = key.split_whitespace();
    let algo = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("");

    matches!(
        algo,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "sk-ssh-ed25519@openssh.com"
    ) && body.len() > 20
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && !key.contains('\n')
}

pub fn ssh_key(user: &str, action: KeyAction, public_key: &str) -> Result<usize, Failure> {
    if !valid_public_key(public_key) {
        return Err(Failure::new(
            "ssh",
            "that is not a public key ServerOS recognises (ed25519, rsa, ecdsa)",
        ));
    }

    let (uid, gid, home, _) = daemon_streams::pty::lookup(user)
        .ok_or_else(|| Failure::new("ssh", format!("user {user} does not exist")))?;
    let ssh_dir = Path::new(&home).join(".ssh");
    let file = ssh_dir.join("authorized_keys");

    std::fs::create_dir_all(&ssh_dir).map_err(|e| Failure::new("ssh", e.to_string()))?;
    let _ = std::os::unix::fs::chown(&ssh_dir, Some(uid), Some(gid));
    set_mode(&ssh_dir, 0o700);

    let existing = std::fs::read_to_string(&file).unwrap_or_default();
    let normalised = public_key
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let mut lines: Vec<String> = existing.lines().map(str::to_string).collect();

    match action {
        KeyAction::Add => {
            if !lines
                .iter()
                .any(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" ") == normalised)
            {
                lines.push(public_key.trim().to_string());
            }
        }
        KeyAction::Remove => lines
            .retain(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" ") != normalised),
    }

    std::fs::write(&file, lines.join("\n") + "\n")
        .map_err(|e| Failure::new("ssh", e.to_string()))?;
    let _ = std::os::unix::fs::chown(&file, Some(uid), Some(gid));
    set_mode(&file, 0o600);

    Ok(lines.len())
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_rules_parse_into_every_backend_s_syntax() {
        let simple = parse_port_rule("22/tcp").unwrap();
        assert_eq!(
            simple.nft_expression(FirewallAction::Allow),
            "tcp dport 22 accept"
        );
        assert_eq!(
            simple.iptables_args(FirewallAction::Deny),
            vec!["-p", "tcp", "--dport", "22", "-j", "DROP"]
        );

        let scoped = parse_port_rule("from 10.0.0.0/8 to any port 5432").unwrap();
        assert_eq!(
            scoped.nft_expression(FirewallAction::Deny),
            "ip saddr 10.0.0.0/8 tcp dport 5432 drop"
        );
        assert_eq!(parse_port_rule("53/udp").unwrap().proto, "udp");
        assert_eq!(
            parse_port_rule("from 2001:db8::/32 to any port 443 proto udp")
                .unwrap()
                .nft_expression(FirewallAction::Allow),
            "ip6 saddr 2001:db8::/32 udp dport 443 accept"
        );
        assert!(parse_port_rule("22/icmp").is_none());
        assert!(parse_port_rule("0").is_none());
        assert!(parse_port_rule("allow 22").is_none());

        let listing = vec![
            "table inet serveros {".to_string(),
            "\t\ttcp dport 22 accept # handle 4".to_string(),
            "\t\ttcp dport 80 accept # handle 9".to_string(),
        ];
        assert_eq!(nft_handle(&listing, "tcp dport 80 accept"), Some(9));
        assert_eq!(nft_handle(&listing, "tcp dport 81 accept"), None);
    }

    #[test]
    fn validates_firewall_rules_and_public_keys() {
        assert!(valid_firewall_rule("22/tcp"));
        assert!(valid_firewall_rule("from 10.0.0.0/8 to any port 5432"));
        assert!(!valid_firewall_rule("22; rm -rf /"));

        assert!(valid_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGmpAbc123def456ghi789jkl012 dylan@laptop"
        ));
        assert!(!valid_public_key("ssh-ed25519 short"));
        assert!(!valid_public_key(
            "command=\"rm -rf\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGmpAbc123def456ghi789jkl012"
        ));
    }
}
