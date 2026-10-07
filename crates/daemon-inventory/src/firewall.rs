//! What the machine's firewall lets in, read from the backend ServerOS
//! changes rules with: ufw's status, the nftables ruleset, or iptables'
//! INPUT chain. Read-only, like the rest of discovery.
//!
//! Rules are read as far as they are understood. A rule that can't be
//! (an interface, a jump to another chain) is counted, and a port it might
//! decide is reported as unknown rather than blocked: saying a port is open
//! when it isn't is safer than the other way round.

use std::path::Path;
use std::time::Duration;

use daemon_core::config::FirewallBackend;
use daemon_protocol::{
    Exposure, FirewallReport, FirewallRuleInfo, FirewallVerdict, Listener, PortExposure, PortRange,
};
use serde_json::Value;

use crate::exec;

/// The comment ServerOS puts on the ufw and iptables rules it adds.
pub const MARK: &str = "ServerOS";
/// ServerOS's own nftables table (family inet) and its input chain.
pub const NFT_TABLE: &str = "serveros";
pub const NFT_CHAIN: &str = "input";

const UFW: &[&str] = &["/usr/sbin/ufw"];
const NFT: &[&str] = &["/usr/sbin/nft", "/sbin/nft"];
const IPTABLES: &[&str] = &["/usr/sbin/iptables", "/sbin/iptables"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub info: FirewallRuleInfo,
    /// How to name the rule to delete it: ufw's words after `ufw delete`,
    /// iptables' after `-D INPUT`. Empty for nftables, which uses `handle`.
    pub spec: Vec<String>,
    pub handle: Option<u64>,
}

impl Rule {
    pub fn covers(&self, port: u16, proto: &str) -> bool {
        self.info.proto.as_deref().is_none_or(|p| p == proto)
            && (self.info.ports.is_empty() || self.info.ports.iter().any(|r| r.contains(port)))
    }

    /// About exactly this one port and protocol, from anywhere, over IPv4
    /// or IPv6: safe to remove without touching any other port. A rule for both TCP and UDP
    /// isn't, since removing it would change the other protocol too.
    pub fn just(&self, port: u16, proto: &str) -> bool {
        self.info.source.is_none()
            && !self.info.opaque
            && self.info.ports == [PortRange::single(port)]
            && self.info.proto.as_deref() == Some(proto)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub name: String,
    pub policy: FirewallVerdict,
    /// ServerOS's own nftables chain.
    pub managed: bool,
    pub rules: Vec<Rule>,
}

impl Chain {
    /// Whether this chain sees IPv4 or IPv6 traffic: nftables' `ip` and
    /// `ip6` tables see only theirs.
    pub fn sees(&self, v6: bool) -> bool {
        !self.name.starts_with(if v6 { "ip " } else { "ip6 " })
    }

    /// ufw keeps a list of rules for each: its IPv4 rules don't apply to
    /// IPv6, even those from anywhere.
    fn split_families(&self) -> bool {
        self.name == "ufw"
    }

    /// The rules worth showing. ufw lists most rules again for IPv6, and
    /// the copy says nothing new.
    pub fn shown(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| {
            !self.split_families()
                || !r.info.ipv6
                || r.info.source.is_some()
                || !self.rules.iter().any(|v| {
                    !v.info.ipv6
                        && v.info.source.is_none()
                        && v.info.verdict == r.info.verdict
                        && v.info.ports == r.info.ports
                        && v.info.proto == r.info.proto
                        && v.info.opaque == r.info.opaque
                })
        })
    }

    /// Whether this chain lets the internet reach the port over IPv4 or
    /// IPv6, and why.
    ///
    /// Rules are checked in order and the first that matches decides. A rule
    /// ServerOS can't read only matters when it comes first and may let the
    /// port in: then a port that would be closed is unknown instead.
    pub fn decide(&self, port: u16, proto: &str, v6: bool) -> (Exposure, String) {
        let mut allowed_from = None;
        let mut maybe = None;
        let family = |r: &&Rule| {
            let v6_source = r.info.source.as_deref().is_some_and(|s| s.contains(':'));
            if v6 {
                r.info.ipv6 || v6_source || (!self.split_families() && r.info.source.is_none())
            } else {
                !r.info.ipv6 && !v6_source
            }
        };
        let decided = 'rules: {
            for rule in self.rules.iter().filter(family) {
                if !rule.covers(port, proto) {
                    continue;
                }
                if rule.info.opaque {
                    if rule.info.verdict.lets_in() {
                        maybe.get_or_insert_with(|| rule.info.text.clone());
                    }
                    continue;
                }
                match (rule.info.source.is_some(), rule.info.verdict.lets_in()) {
                    (false, true) => break 'rules (Exposure::Open, rule.info.text.clone()),
                    (false, false) => break 'rules (Exposure::Blocked, rule.info.text.clone()),
                    (true, true) => {
                        allowed_from.get_or_insert_with(|| rule.info.text.clone());
                    }
                    (true, false) => {}
                }
            }

            let policy = format!("{}: by default {}", self.name, verdict_word(self.policy));
            match (self.policy.lets_in(), allowed_from) {
                (true, _) => (Exposure::Open, policy),
                (false, Some(rule)) => (Exposure::Restricted, rule),
                (false, None) => (Exposure::Blocked, policy),
            }
        };

        match (decided.0, maybe) {
            (Exposure::Blocked | Exposure::Restricted, Some(rule)) => (
                Exposure::Unknown,
                format!("{rule}: ServerOS can't read this rule, and it may let it in"),
            ),
            _ => decided,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    pub backend: FirewallBackend,
    pub installed: bool,
    pub active: bool,
    /// Every chain that sees incoming traffic. A packet has to get through
    /// all of them (nftables can have several; ufw and iptables have one).
    pub chains: Vec<Chain>,
    pub unreadable: u32,
    /// False when its rules couldn't be read at all: every port is then
    /// unknown, and nothing is changed.
    pub readable: bool,
    /// The machine has a public IPv6 address, so the internet can come in
    /// over IPv6 too, and those rules count as well.
    pub ipv6: bool,
    pub notes: Vec<String>,
}

impl Ruleset {
    fn empty(backend: FirewallBackend, installed: bool) -> Self {
        Self {
            backend,
            installed,
            active: false,
            chains: Vec::new(),
            unreadable: 0,
            readable: true,
            ipv6: false,
            notes: Vec::new(),
        }
    }

    pub fn default_incoming(&self) -> Option<FirewallVerdict> {
        if !self.active || !self.readable {
            return None;
        }
        Some(
            self.chains
                .iter()
                .map(|c| c.policy)
                .find(|p| !p.lets_in())
                .unwrap_or(FirewallVerdict::Allow),
        )
    }

    /// Whether the internet can reach the port, and the rule or policy
    /// that decided it.
    pub fn exposure(&self, port: u16, proto: &str) -> (Exposure, String) {
        // Between equals, IPv4 says it more plainly.
        self.settled().unwrap_or_else(|| {
            self.families(port, proto)
                .into_iter()
                .rev()
                .max_by_key(|(e, _)| reach(*e))
                .expect("IPv4 is always there")
        })
    }

    /// The least the internet can reach the port by, over IPv4 or IPv6: a
    /// port is only open once it's open over both.
    pub fn least_exposure(&self, port: u16, proto: &str) -> (Exposure, String) {
        self.settled().unwrap_or_else(|| {
            self.families(port, proto)
                .into_iter()
                .min_by_key(|(e, _)| reach(*e))
                .expect("IPv4 is always there")
        })
    }

    /// The answer for every port, when there are no rules to go by.
    fn settled(&self) -> Option<(Exposure, String)> {
        let name = backend_name(self.backend);
        if !self.installed {
            Some((Exposure::Open, format!("{name} is not installed")))
        } else if !self.active {
            Some((Exposure::Open, format!("{name} is not turned on")))
        } else if !self.readable {
            Some((Exposure::Unknown, format!("couldn't read {name}'s rules")))
        } else {
            None
        }
    }

    /// What IPv4, and IPv6 when the machine has it, let in.
    fn families(&self, port: u16, proto: &str) -> Vec<(Exposure, String)> {
        let mut families = vec![self.family_exposure(port, proto, false)];
        // ip6tables isn't read, so iptables can only speak for IPv4.
        if self.ipv6 && self.backend != FirewallBackend::Iptables {
            let (exposure, because) = self.family_exposure(port, proto, true);
            families.push((exposure, format!("over IPv6, {because}")));
        }
        families
    }

    fn family_exposure(&self, port: u16, proto: &str, v6: bool) -> (Exposure, String) {
        // It has to get through every chain: a block anywhere is final.
        let rank = |e: Exposure| match e {
            Exposure::Blocked => 3,
            Exposure::Unknown => 2,
            Exposure::Restricted => 1,
            _ => 0,
        };
        let mut decided = (
            Exposure::Open,
            "no rules filter incoming connections".to_string(),
        );
        for (i, chain) in self.chains.iter().filter(|c| c.sees(v6)).enumerate() {
            let (exposure, because) = chain.decide(port, proto, v6);
            // Between equals, a rule says more than a chain's default.
            let says_more = rank(exposure) == rank(decided.0)
                && decided.1.contains(": by default ")
                && !because.contains(": by default ");
            if i == 0 || rank(exposure) > rank(decided.0) || says_more {
                decided = (exposure, because);
            }
        }
        decided
    }

    /// The report for the panel: the rules, and what they mean for each
    /// port listening beyond loopback.
    pub fn report(&self, listeners: &[Listener], docker_ports: &[u16]) -> FirewallReport {
        let mut ports: Vec<PortExposure> = Vec::new();
        for listener in listeners.iter().filter(|l| !loopback(&l.address)) {
            let proto = listener.proto.trim_end_matches('6').to_string();
            if ports
                .iter()
                .any(|p| p.port == listener.port && p.proto == proto)
            {
                continue;
            }
            let docker = docker_ports.contains(&listener.port)
                || listener
                    .exe
                    .as_deref()
                    .is_some_and(|e| e.ends_with("docker-proxy"));
            let (exposure, because) = if docker {
                (
                    Exposure::Docker,
                    "published by Docker, whose rules come before the host firewall's".into(),
                )
            } else {
                self.exposure(listener.port, &proto)
            };
            ports.push(PortExposure {
                port: listener.port,
                proto,
                exposure,
                because: Some(because),
            });
        }
        ports.sort_by(|a, b| (a.port, &a.proto).cmp(&(b.port, &b.proto)));

        FirewallReport {
            backend: backend_name(self.backend).into(),
            installed: self.installed,
            active: self.active,
            default_incoming: self.default_incoming(),
            rules: self
                .chains
                .iter()
                .flat_map(|c| c.shown().map(|r| r.info.clone()))
                .collect(),
            ports,
            unreadable: self.unreadable,
            notes: self.notes.clone(),
        }
    }
}

pub fn backend_name(backend: FirewallBackend) -> &'static str {
    match backend {
        FirewallBackend::Ufw => "ufw",
        FirewallBackend::Nftables => "nftables",
        FirewallBackend::Iptables => "iptables",
        FirewallBackend::None => "none",
    }
}

pub fn installed(backend: FirewallBackend) -> bool {
    let paths = match backend {
        FirewallBackend::Ufw => UFW,
        FirewallBackend::Nftables => NFT,
        FirewallBackend::Iptables => IPTABLES,
        FirewallBackend::None => return false,
    };
    paths.iter().any(|p| Path::new(p).exists())
}

fn loopback(address: &str) -> bool {
    let address = address.trim_matches(|c| c == '[' || c == ']');
    address == "::1" || address == "localhost" || address.starts_with("127.")
}

fn verdict_word(verdict: FirewallVerdict) -> &'static str {
    match verdict {
        FirewallVerdict::Allow => "allow",
        FirewallVerdict::Limit => "limit",
        FirewallVerdict::Deny => "deny",
        FirewallVerdict::Reject => "reject",
    }
}

/// Read the firewall the way ServerOS will change it.
pub async fn read(backend: FirewallBackend, timeout: Duration) -> Ruleset {
    let installed = installed(backend);
    if !installed {
        let mut ruleset = Ruleset::empty(backend, false);
        ruleset.notes.push(match backend {
            FirewallBackend::None => {
                "No firewall backend is set in daemon.toml, so ServerOS doesn't manage one.".into()
            }
            _ => format!("{} is not installed.", backend_name(backend)),
        });
        return ruleset;
    }

    let mut ruleset = match backend {
        FirewallBackend::Ufw => exec::output("ufw", &["status", "verbose"], timeout)
            .await
            .map(|text| parse_ufw(&text)),
        FirewallBackend::Nftables => exec::output("nft", &["-j", "list", "ruleset"], timeout)
            .await
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .map(|json| parse_nft(&json)),
        FirewallBackend::Iptables => exec::output("iptables", &["-S", "INPUT"], timeout)
            .await
            .map(|text| parse_iptables(&text)),
        FirewallBackend::None => None,
    }
    .unwrap_or_else(|| {
        let mut ruleset = Ruleset::empty(backend, true);
        ruleset.active = true;
        ruleset.readable = false;
        ruleset.notes.push(format!(
            "Couldn't read {}'s rules, so ServerOS can't tell what they let in and won't change them.",
            backend_name(backend)
        ));
        ruleset
    });
    ruleset.backend = backend;
    ruleset.ipv6 = public_ipv6(Path::new("/proc/net/if_inet6"));
    if backend == FirewallBackend::Iptables && !Path::new("/usr/sbin/netfilter-persistent").exists()
    {
        ruleset.notes.push(
            "iptables rules don't survive a restart without netfilter-persistent (apt install iptables-persistent).".into(),
        );
    }
    ruleset
}

/// How much of the internet gets through: the more, the higher.
fn reach(exposure: Exposure) -> u8 {
    match exposure {
        Exposure::Open | Exposure::Docker => 3,
        Exposure::Unknown => 2,
        Exposure::Restricted => 1,
        Exposure::Blocked => 0,
    }
}

/// Whether any interface but loopback has a global IPv6 address that isn't
/// a private (fc00::/7) one.
fn public_ipv6(if_inet6: &Path) -> bool {
    std::fs::read_to_string(if_inet6)
        .map(|text| {
            text.lines().any(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                matches!(words.as_slice(), [address, _, _, "00", _, name]
                    if *name != "lo" && !address.starts_with("fc") && !address.starts_with("fd"))
            })
        })
        .unwrap_or(false)
}

// --- ufw -------------------------------------------------------------------

enum Parsed {
    Rule(Rule),
    /// Doesn't decide what reaches the machine from the internet: outgoing,
    /// loopback, replies to connections already made.
    Ignore,
    Unreadable,
}

pub fn parse_ufw(text: &str) -> Ruleset {
    let mut ruleset = Ruleset::empty(FirewallBackend::Ufw, true);
    let mut policy = FirewallVerdict::Deny;
    let mut rules: Vec<Rule> = Vec::new();
    let mut in_table = false;

    for line in text.lines().map(str::trim) {
        if let Some(status) = line.strip_prefix("Status:") {
            ruleset.active = status.trim() == "active";
        } else if let Some(defaults) = line.strip_prefix("Default:") {
            let incoming = defaults.split(',').next().unwrap_or("");
            policy = match incoming.split_whitespace().next() {
                Some("allow") => FirewallVerdict::Allow,
                Some("reject") => FirewallVerdict::Reject,
                _ => FirewallVerdict::Deny,
            };
        } else if line.starts_with("--") {
            in_table = true;
        } else if in_table && !line.is_empty() {
            match parse_ufw_rule(line) {
                Parsed::Rule(rule) => rules.push(rule),
                Parsed::Ignore => {}
                Parsed::Unreadable => rules.extend(opaque_ufw(line)),
            }
        }
    }

    if ruleset.active {
        ruleset.chains.push(Chain {
            name: "ufw".into(),
            policy,
            managed: false,
            rules,
        });
        ruleset.unreadable = count_opaque(&ruleset.chains);
    } else {
        ruleset
            .notes
            .push("ufw is installed but turned off, so it isn't blocking anything.".into());
    }
    ruleset
}

fn parse_ufw_rule(line: &str) -> Parsed {
    let (body, comment) = match line.split_once(" # ") {
        Some((body, comment)) => (body.trim(), Some(comment.trim())),
        None => (line, None),
    };
    let tokens: Vec<&str> = body.split_whitespace().collect();
    let Some(at) = tokens
        .iter()
        .position(|t| matches!(*t, "ALLOW" | "DENY" | "REJECT" | "LIMIT"))
    else {
        return Parsed::Unreadable;
    };
    let verdict = match tokens[at] {
        "ALLOW" => FirewallVerdict::Allow,
        "DENY" => FirewallVerdict::Deny,
        "REJECT" => FirewallVerdict::Reject,
        _ => FirewallVerdict::Limit,
    };
    let mut rest = &tokens[at + 1..];
    match rest.first() {
        Some(&"IN") => rest = &rest[1..],
        Some(&"OUT") | Some(&"FWD") => return Parsed::Ignore,
        _ => {}
    }

    let to = tokens[..at].join(" ");
    let from = rest.join(" ");
    let ipv6 = to.contains("(v6)") || from.contains("(v6)");
    let to = to.replace(" (v6)", "");
    let from = from.replace(" (v6)", "");
    if to.contains(" on ") || from.contains(" on ") {
        return Parsed::Unreadable;
    }

    // An application profile, shown as its ports: "80,443/tcp (Nginx Full)".
    let (to, app) = match to.find(" (") {
        Some(open) if to.ends_with(')') => (
            to[..open].to_string(),
            Some(to[open + 2..to.len() - 1].to_string()),
        ),
        _ => (to, None),
    };
    let (ports, proto) = if to == "Anywhere" {
        (Vec::new(), None)
    } else {
        match port_spec(&to) {
            Some(spec) => spec,
            None => return Parsed::Unreadable,
        }
    };
    let source = match from.as_str() {
        "Anywhere" => None,
        _ if from.contains(' ') => return Parsed::Unreadable,
        _ => Some(from.clone()),
    };

    let word = verdict_word(verdict).to_string();
    let target = app.clone().unwrap_or_else(|| to.clone());
    let spec = match (&source, &app) {
        (None, _) if to == "Anywhere" && app.is_none() => vec![word, "from".into(), "any".into()],
        (None, _) => vec![word, target],
        (Some(source), None) if to == "Anywhere" => vec![word, "from".into(), source.clone()],
        (Some(source), None) => {
            let (port, proto) = match to.split_once('/') {
                Some((port, proto)) => (port.to_string(), Some(proto.to_string())),
                None => (to.clone(), None),
            };
            let mut spec = vec![
                word,
                "from".into(),
                source.clone(),
                "to".into(),
                "any".into(),
                "port".into(),
                port,
            ];
            if let Some(proto) = proto {
                spec.extend(["proto".into(), proto]);
            }
            spec
        }
        (Some(source), Some(app)) => vec![
            word,
            "from".into(),
            source.clone(),
            "to".into(),
            "any".into(),
            "app".into(),
            app.clone(),
        ],
    };

    Parsed::Rule(Rule {
        info: FirewallRuleInfo {
            verdict,
            ports,
            proto,
            source,
            ipv6,
            managed: comment == Some(MARK),
            opaque: false,
            text: tokens.join(" "),
        },
        spec,
        handle: None,
    })
}

/// "22", "22/tcp", "80,443/tcp", "6000:6007/udp".
fn port_spec(spec: &str) -> Option<(Vec<PortRange>, Option<String>)> {
    let (ports, proto) = match spec.split_once('/') {
        Some((ports, proto)) if matches!(proto, "tcp" | "udp") => (ports, Some(proto.to_string())),
        Some(_) => return None,
        None => (spec, None),
    };
    let ranges = ports
        .split(',')
        .map(port_range)
        .collect::<Option<Vec<_>>>()?;
    Some((ranges, proto))
}

/// "22", or a range as "1000:2000" or "1000-2000".
fn port_range(text: &str) -> Option<PortRange> {
    let text = text.trim();
    match text.split_once([':', '-']) {
        Some((start, end)) => Some(PortRange {
            start: start.parse().ok()?,
            end: end.parse().ok()?,
        }),
        None => text.parse().ok().map(PortRange::single),
    }
}

// --- nftables --------------------------------------------------------------

pub fn parse_nft(json: &Value) -> Ruleset {
    let mut ruleset = Ruleset::empty(FirewallBackend::Nftables, true);
    let items = json["nftables"].as_array().cloned().unwrap_or_default();

    for chain in items.iter().filter_map(|i| i.get("chain")) {
        let family = chain["family"].as_str().unwrap_or("");
        if chain["hook"].as_str() != Some("input")
            || chain["type"].as_str() != Some("filter")
            || !matches!(family, "ip" | "ip6" | "inet")
        {
            continue;
        }
        let table = chain["table"].as_str().unwrap_or("");
        let name = chain["name"].as_str().unwrap_or("");
        ruleset.chains.push(Chain {
            name: format!("{family} {table} {name}"),
            policy: match chain["policy"].as_str() {
                Some("drop") => FirewallVerdict::Deny,
                _ => FirewallVerdict::Allow,
            },
            managed: family == "inet" && table == NFT_TABLE && name == NFT_CHAIN,
            rules: Vec::new(),
        });
    }

    for rule in items.iter().filter_map(|i| i.get("rule")) {
        let key = format!(
            "{} {} {}",
            rule["family"].as_str().unwrap_or(""),
            rule["table"].as_str().unwrap_or(""),
            rule["chain"].as_str().unwrap_or("")
        );
        let Some(chain) = ruleset.chains.iter_mut().find(|c| c.name == key) else {
            continue;
        };
        match parse_nft_rule(rule, chain.managed, chain.name.starts_with("ip6 ")) {
            Parsed::Rule(rule) => chain.rules.push(rule),
            Parsed::Ignore => {}
            Parsed::Unreadable => {
                let rule = opaque_nft(rule, chain.managed, chain.name.starts_with("ip6 "));
                chain.rules.push(rule);
            }
        }
    }

    ruleset.unreadable = count_opaque(&ruleset.chains);
    // nftables has no off switch: with no input chain, nothing is filtered
    // yet, and closing a port creates ServerOS's own.
    ruleset.active = true;
    ruleset
}

fn parse_nft_rule(rule: &Value, managed: bool, ipv6_chain: bool) -> Parsed {
    let Some(exprs) = rule["expr"].as_array() else {
        return Parsed::Unreadable;
    };
    let mut proto: Option<String> = None;
    let mut ports: Vec<PortRange> = Vec::new();
    let mut source: Option<String> = None;
    let mut ipv6 = ipv6_chain;
    let mut verdict = None;

    for expr in exprs {
        if let Some(m) = expr.get("match") {
            let op = m["op"].as_str().unwrap_or("==");
            let (left, right) = (&m["left"], &m["right"]);

            if let Some(payload) = left.get("payload") {
                match (payload["protocol"].as_str(), payload["field"].as_str(), op) {
                    (Some(p @ ("tcp" | "udp" | "th")), Some("dport"), "==") => {
                        if p != "th" {
                            proto = Some(p.into());
                        }
                        match nft_ports(right) {
                            Some(found) => ports = found,
                            None => return Parsed::Unreadable,
                        }
                    }
                    (Some(family @ ("ip" | "ip6")), Some("saddr"), "==") => {
                        match nft_address(right) {
                            Some(address) => source = Some(address),
                            None => return Parsed::Unreadable,
                        }
                        ipv6 |= family == "ip6";
                    }
                    (Some("ip"), Some("protocol"), "==") | (Some("ip6"), Some("nexthdr"), "==") => {
                        match l4(right) {
                            L4::One(p) => proto = Some(p),
                            L4::Both => {}
                            L4::Icmp => return Parsed::Ignore,
                            L4::Other => return Parsed::Unreadable,
                        }
                    }
                    _ => return Parsed::Unreadable,
                }
            } else if let Some(meta) = left.get("meta") {
                match meta["key"].as_str() {
                    Some("iifname" | "iif") if right.as_str() == Some("lo") => {
                        if op == "==" {
                            return Parsed::Ignore;
                        }
                        // != "lo": everything else, the internet included.
                    }
                    Some("l4proto") if op == "==" => match l4(right) {
                        L4::One(p) => proto = Some(p),
                        L4::Both => {}
                        L4::Icmp => return Parsed::Ignore,
                        L4::Other => return Parsed::Unreadable,
                    },
                    Some("nfproto") if op == "==" => ipv6 |= right.as_str() == Some("ipv6"),
                    _ => return Parsed::Unreadable,
                }
            } else if left.get("ct").and_then(|ct| ct["key"].as_str()) == Some("state") {
                let states = strings(right);
                if states.iter().any(|s| s == "new") {
                    // Applies to new connections, the ones in question.
                } else if !states.is_empty()
                    && states.iter().all(|s| {
                        matches!(
                            s.as_str(),
                            "established" | "related" | "invalid" | "untracked"
                        )
                    })
                {
                    return Parsed::Ignore;
                } else {
                    return Parsed::Unreadable;
                }
            } else {
                return Parsed::Unreadable;
            }
        } else if expr.get("accept").is_some() {
            verdict = Some(FirewallVerdict::Allow);
        } else if expr.get("drop").is_some() {
            verdict = Some(FirewallVerdict::Deny);
        } else if expr.get("reject").is_some() {
            verdict = Some(FirewallVerdict::Reject);
        } else if expr.get("counter").is_some() || expr.get("log").is_some() {
        } else {
            return Parsed::Unreadable;
        }
    }

    let Some(verdict) = verdict else {
        return Parsed::Ignore;
    };
    let text = nft_text(verdict, &ports, proto.as_deref(), source.as_deref(), ipv6);
    Parsed::Rule(Rule {
        info: FirewallRuleInfo {
            verdict,
            ports,
            proto,
            source,
            ipv6,
            managed,
            opaque: false,
            text,
        },
        spec: Vec::new(),
        handle: rule["handle"].as_u64(),
    })
}

enum L4 {
    One(String),
    Both,
    Icmp,
    Other,
}

fn l4(right: &Value) -> L4 {
    let found = strings(right);
    if found.iter().all(|p| p == "tcp" || p == "udp") && !found.is_empty() {
        if found.len() == 1 {
            L4::One(found[0].clone())
        } else {
            L4::Both
        }
    } else if found.iter().all(|p| p == "icmp" || p == "ipv6-icmp") && !found.is_empty() {
        L4::Icmp
    } else {
        L4::Other
    }
}

fn strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items.iter().flat_map(strings).collect(),
        Value::Object(o) => o.get("set").map(strings).unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn nft_ports(value: &Value) -> Option<Vec<PortRange>> {
    match value {
        Value::Number(n) => Some(vec![PortRange::single(u16::try_from(n.as_u64()?).ok()?)]),
        Value::String(s) => Some(vec![PortRange::single(match s.as_str() {
            "ssh" => 22,
            "http" => 80,
            "https" => 443,
            other => other.parse().ok()?,
        })]),
        Value::Array(items) => items
            .iter()
            .map(nft_ports)
            .collect::<Option<Vec<_>>>()
            .map(|v| v.concat()),
        Value::Object(o) => {
            if let Some(set) = o.get("set") {
                nft_ports(set)
            } else if let Some(Value::Array(bounds)) = o.get("range") {
                let start = nft_ports(bounds.first()?)?.first()?.start;
                let end = nft_ports(bounds.get(1)?)?.first()?.start;
                Some(vec![PortRange { start, end }])
            } else {
                None
            }
        }
        _ => None,
    }
}

fn nft_address(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => {
            let prefix = o.get("prefix")?;
            Some(format!(
                "{}/{}",
                prefix["addr"].as_str()?,
                prefix["len"].as_u64()?
            ))
        }
        _ => None,
    }
}

fn nft_text(
    verdict: FirewallVerdict,
    ports: &[PortRange],
    proto: Option<&str>,
    source: Option<&str>,
    ipv6: bool,
) -> String {
    let mut parts = Vec::new();
    if let Some(source) = source {
        parts.push(format!(
            "{} saddr {source}",
            if ipv6 { "ip6" } else { "ip" }
        ));
    }
    match (ports.is_empty(), proto) {
        (false, proto) => {
            let list: Vec<String> = ports
                .iter()
                .map(|r| {
                    if r.start == r.end {
                        r.start.to_string()
                    } else {
                        format!("{}-{}", r.start, r.end)
                    }
                })
                .collect();
            let list = if list.len() == 1 {
                list[0].clone()
            } else {
                format!("{{ {} }}", list.join(", "))
            };
            parts.push(format!("{} dport {list}", proto.unwrap_or("th")));
        }
        (true, Some(proto)) => parts.push(format!("meta l4proto {proto}")),
        (true, None) => {}
    }
    parts.push(
        match verdict {
            FirewallVerdict::Allow | FirewallVerdict::Limit => "accept",
            FirewallVerdict::Deny => "drop",
            FirewallVerdict::Reject => "reject",
        }
        .into(),
    );
    parts.join(" ")
}

// --- iptables --------------------------------------------------------------

pub fn parse_iptables(text: &str) -> Ruleset {
    let mut ruleset = Ruleset::empty(FirewallBackend::Iptables, true);
    let mut chain = Chain {
        name: "iptables INPUT".into(),
        policy: FirewallVerdict::Allow,
        managed: false,
        rules: Vec::new(),
    };

    for line in text.lines() {
        let words = shell_words(line);
        match words
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["-P", "INPUT", policy] => {
                chain.policy = if *policy == "ACCEPT" {
                    FirewallVerdict::Allow
                } else {
                    FirewallVerdict::Deny
                };
            }
            ["-A", "INPUT", ..] => match parse_iptables_rule(&words[2..]) {
                Parsed::Rule(rule) => chain.rules.push(rule),
                Parsed::Ignore => {}
                Parsed::Unreadable => chain.rules.push(opaque_iptables(&words[2..])),
            },
            _ => {}
        }
    }

    // Nor does iptables: an empty INPUT that accepts still takes rules.
    ruleset.active = true;
    ruleset.chains.push(chain);
    ruleset.unreadable = count_opaque(&ruleset.chains);
    ruleset
        .notes
        .push("Only IPv4 rules are read; ip6tables is left as it is.".into());
    ruleset
}

fn parse_iptables_rule(args: &[String]) -> Parsed {
    let mut proto = None;
    let mut ports = Vec::new();
    let mut source = None;
    let mut managed = false;
    let mut verdict = None;
    let mut i = 0;

    while i < args.len() {
        let next = args.get(i + 1).map(String::as_str);
        match args[i].as_str() {
            "-s" => {
                source = next.filter(|s| *s != "0.0.0.0/0").map(str::to_string);
                i += 2;
            }
            "-p" => {
                match next {
                    Some(p @ ("tcp" | "udp")) => proto = Some(p.to_string()),
                    Some("all") => {}
                    Some("icmp") => return Parsed::Ignore,
                    _ => return Parsed::Unreadable,
                }
                i += 2;
            }
            "-m" => i += 2,
            "--dport" | "--dports" => {
                let Some(found) =
                    next.and_then(|n| n.split(',').map(port_range).collect::<Option<Vec<_>>>())
                else {
                    return Parsed::Unreadable;
                };
                ports = found;
                i += 2;
            }
            "-i" if next == Some("lo") => return Parsed::Ignore,
            "!" if next == Some("-i") && args.get(i + 2).map(String::as_str) == Some("lo") => {
                i += 3;
            }
            "--ctstate" | "--state" => {
                let states: Vec<&str> = next.unwrap_or("").split(',').collect();
                if states.contains(&"NEW") {
                } else if states
                    .iter()
                    .all(|s| matches!(*s, "ESTABLISHED" | "RELATED" | "INVALID" | "UNTRACKED"))
                {
                    return Parsed::Ignore;
                } else {
                    return Parsed::Unreadable;
                }
                i += 2;
            }
            "--comment" => {
                managed = next == Some(MARK);
                i += 2;
            }
            "-j" => {
                verdict = Some(match next {
                    Some("ACCEPT") => FirewallVerdict::Allow,
                    Some("DROP") => FirewallVerdict::Deny,
                    Some("REJECT") => FirewallVerdict::Reject,
                    _ => return Parsed::Unreadable,
                });
                i += 2;
            }
            "--reject-with" => i += 2,
            _ => return Parsed::Unreadable,
        }
    }

    let Some(verdict) = verdict else {
        return Parsed::Ignore;
    };
    Parsed::Rule(Rule {
        info: FirewallRuleInfo {
            verdict,
            ports,
            proto,
            source,
            ipv6: false,
            managed,
            opaque: false,
            text: format!("-A INPUT {}", args.join(" ")),
        },
        spec: args.to_vec(),
        handle: None,
    })
}

/// Split as iptables-save quotes: words, with "double quoted" ones whole.
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    words.push(std::mem::take(&mut word));
                    any = false;
                }
            }
            c => {
                word.push(c);
                any = true;
            }
        }
    }
    if any {
        words.push(word);
    }
    words
}

// --- rules ServerOS can't fully read -----------------------------------------

fn count_opaque(chains: &[Chain]) -> u32 {
    chains
        .iter()
        .flat_map(|c| c.shown())
        .filter(|r| r.info.opaque)
        .count() as u32
}

/// A rule kept in its place with what can be told: its verdict when it's
/// plain, and its ports when they can be found; otherwise it may let any
/// port in.
fn opaque(
    verdict: Option<FirewallVerdict>,
    ports: Option<(Vec<PortRange>, Option<String>)>,
    ipv6: bool,
    managed: bool,
    text: String,
) -> Rule {
    let (ports, proto) = ports.unwrap_or_default();
    Rule {
        info: FirewallRuleInfo {
            verdict: verdict.unwrap_or(FirewallVerdict::Allow),
            ports,
            proto,
            source: None,
            ipv6,
            managed,
            opaque: true,
            text,
        },
        spec: Vec::new(),
        handle: None,
    }
}

/// "6004/tcp on eth0  ALLOW IN  Anywhere", "Anywhere on eth0 …", "10.0.0.5 22/tcp …".
fn opaque_ufw(line: &str) -> Option<Rule> {
    let body = line.split_once(" # ").map_or(line, |(body, _)| body.trim());
    let tokens: Vec<&str> = body.split_whitespace().collect();
    let at = tokens
        .iter()
        .position(|t| matches!(*t, "ALLOW" | "DENY" | "REJECT" | "LIMIT"));
    let verdict = at.map(|at| match tokens[at] {
        "ALLOW" => FirewallVerdict::Allow,
        "DENY" => FirewallVerdict::Deny,
        "REJECT" => FirewallVerdict::Reject,
        _ => FirewallVerdict::Limit,
    });
    if let Some(at) = at {
        if matches!(tokens.get(at + 1), Some(&"OUT") | Some(&"FWD")) {
            return None;
        }
    }
    let to = &tokens[..at.unwrap_or(tokens.len())];
    let ports = to.iter().find_map(|t| port_spec(t));
    Some(opaque(
        verdict,
        ports,
        body.contains("(v6)"),
        false,
        tokens.join(" "),
    ))
}

fn opaque_nft(rule: &Value, managed: bool, ipv6_chain: bool) -> Rule {
    let exprs = rule["expr"].as_array().cloned().unwrap_or_default();
    let verdict = exprs.iter().find_map(|e| {
        if e.get("accept").is_some() {
            Some(FirewallVerdict::Allow)
        } else if e.get("drop").is_some() {
            Some(FirewallVerdict::Deny)
        } else if e.get("reject").is_some() {
            Some(FirewallVerdict::Reject)
        } else {
            None
        }
    });
    let ports = exprs.iter().find_map(|e| {
        let m = e.get("match")?;
        let payload = m["left"].get("payload")?;
        if payload["field"].as_str() != Some("dport") || m["op"].as_str().unwrap_or("==") != "==" {
            return None;
        }
        let proto = payload["protocol"]
            .as_str()
            .filter(|p| *p != "th")
            .map(str::to_string);
        Some((nft_ports(&m["right"])?, proto))
    });
    // As much of it as can be said: its ports, and where it goes.
    let mut words = Vec::new();
    if let Some((ports, proto)) = &ports {
        words.push(
            nft_text(FirewallVerdict::Allow, ports, proto.as_deref(), None, false)
                .trim_end_matches(" accept")
                .to_string(),
        );
    }
    words.push(
        exprs
            .iter()
            .find_map(|e| {
                ["jump", "goto"].iter().find_map(|kind| {
                    let target = e.get(*kind)?.get("target")?.as_str()?;
                    Some(format!("{kind} {target}"))
                })
            })
            .or_else(|| verdict.map(|v| nft_text(v, &[], None, None, false)))
            .unwrap_or_else(|| {
                format!(
                    "rule {} in {}",
                    rule["handle"].as_u64().unwrap_or(0),
                    rule["chain"].as_str().unwrap_or("")
                )
            }),
    );
    let mut built = opaque(
        verdict,
        ports.clone(),
        ipv6_chain,
        managed,
        words.join(" … "),
    );
    built.handle = rule["handle"].as_u64();
    built
}

fn opaque_iptables(args: &[String]) -> Rule {
    let after = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
    };
    let verdict = match after("-j").map(String::as_str) {
        Some("ACCEPT") => Some(FirewallVerdict::Allow),
        Some("DROP") => Some(FirewallVerdict::Deny),
        Some("REJECT") => Some(FirewallVerdict::Reject),
        _ => None,
    };
    let ports = after("--dport")
        .or_else(|| after("--dports"))
        .and_then(|p| p.split(',').map(port_range).collect::<Option<Vec<_>>>())
        .map(|ports| {
            (
                ports,
                after("-p")
                    .filter(|p| matches!(p.as_str(), "tcp" | "udp"))
                    .cloned(),
            )
        });
    let mut built = opaque(
        verdict,
        ports,
        false,
        false,
        format!("-A INPUT {}", args.join(" ")),
    );
    built.spec = args.to_vec();
    built
}

#[cfg(test)]
mod tests {
    use super::*;

    const UFW_ACTIVE: &str = "Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     LIMIT IN    Anywhere
80,443/tcp (Nginx Full)    ALLOW IN    Anywhere
5432/tcp                   ALLOW IN    10.0.0.0/8
6379                       DENY IN     Anywhere                   # ServerOS
Anywhere on eth1           ALLOW IN    Anywhere
53                         ALLOW OUT   Anywhere
22/tcp (v6)                LIMIT IN    Anywhere (v6)
80,443/tcp (Nginx Full (v6)) ALLOW IN    Anywhere (v6)
6379 (v6)                  DENY IN     Anywhere (v6)              # ServerOS
";

    fn without_interface_rule() -> String {
        UFW_ACTIVE
            .lines()
            .filter(|l| !l.contains(" on eth1"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn listener(address: &str, port: u16) -> Listener {
        Listener {
            proto: "tcp".into(),
            address: address.into(),
            port,
            pid: None,
            exe: None,
            user: None,
            cmdline: None,
        }
    }

    #[test]
    fn reads_ufw_rules_once_each_with_how_to_delete_them() {
        let ruleset = parse_ufw(UFW_ACTIVE);

        assert!(ruleset.active);
        assert_eq!(ruleset.unreadable, 1, "the interface rule");
        let rules: Vec<&Rule> = ruleset.chains[0].shown().collect();
        assert_eq!(rules.len(), 5, "v6 copies and outgoing rules left out");
        assert!(rules[4].info.opaque);
        assert_eq!(rules[4].info.text, "Anywhere on eth1 ALLOW IN Anywhere");
        assert_eq!(rules[0].info.verdict, FirewallVerdict::Limit);
        assert_eq!(rules[0].spec, ["limit", "22/tcp"]);
        assert_eq!(
            rules[1].info.ports,
            [PortRange::single(80), PortRange::single(443)]
        );
        assert_eq!(rules[1].spec, ["allow", "Nginx Full"]);
        assert_eq!(
            rules[2].spec,
            [
                "allow",
                "from",
                "10.0.0.0/8",
                "to",
                "any",
                "port",
                "5432",
                "proto",
                "tcp"
            ]
        );
        assert!(rules[3].info.managed);
        assert_eq!(rules[3].info.proto, None);
    }

    #[test]
    fn decides_what_the_internet_can_reach() {
        let ruleset = parse_ufw(&without_interface_rule());

        assert_eq!(ruleset.exposure(22, "tcp").0, Exposure::Open);
        assert_eq!(ruleset.exposure(443, "tcp").0, Exposure::Open);
        assert_eq!(ruleset.exposure(5432, "tcp").0, Exposure::Restricted);
        assert_eq!(ruleset.exposure(6379, "tcp").0, Exposure::Blocked);
        assert_eq!(ruleset.exposure(3306, "tcp").0, Exposure::Blocked);
        assert_eq!(ruleset.default_incoming(), Some(FirewallVerdict::Deny));
    }

    #[test]
    fn an_unreadable_rule_never_makes_a_port_look_safe() {
        let ruleset = parse_ufw(UFW_ACTIVE);

        assert_eq!(ruleset.exposure(3306, "tcp").0, Exposure::Unknown);
        assert_eq!(ruleset.exposure(5432, "tcp").0, Exposure::Unknown);
        assert_eq!(ruleset.exposure(22, "tcp").0, Exposure::Open);
        assert_eq!(
            ruleset.exposure(6379, "tcp").0,
            Exposure::Blocked,
            "its deny comes first, so the interface rule is never reached"
        );
    }

    #[test]
    fn an_unreadable_rule_only_clouds_the_ports_it_may_cover() {
        let ruleset = parse_ufw(
            "Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
8000/tcp                   DENY IN     Anywhere                   # ServerOS
6004/tcp on eth0           ALLOW IN    Anywhere
6005/tcp                   REJECT IN   Anywhere
6004/tcp (v6) on eth0      ALLOW IN    Anywhere (v6)
",
        );

        assert_eq!(ruleset.unreadable, 1, "its v6 copy isn't counted again");
        assert_eq!(ruleset.exposure(6004, "tcp").0, Exposure::Unknown);
        assert_eq!(ruleset.exposure(6005, "tcp").0, Exposure::Blocked);
        assert_eq!(ruleset.exposure(8000, "tcp").0, Exposure::Blocked);
        assert_eq!(ruleset.exposure(3306, "tcp").0, Exposure::Blocked);
        assert!(
            plan_free(&ruleset),
            "an unreadable rule is never one ServerOS deletes"
        );
    }

    fn plan_free(ruleset: &Ruleset) -> bool {
        ruleset.chains[0]
            .rules
            .iter()
            .filter(|r| r.info.opaque)
            .all(|r| !r.just(6004, "tcp"))
    }

    #[test]
    fn ufw_turned_off_blocks_nothing() {
        let ruleset = parse_ufw("Status: inactive\n");

        assert!(!ruleset.active);
        assert_eq!(ruleset.exposure(5432, "tcp").0, Exposure::Open);
        assert_eq!(ruleset.default_incoming(), None);
    }

    #[test]
    fn reports_listeners_beyond_loopback_and_docker_published_ports() {
        let ruleset = parse_ufw(&without_interface_rule());
        let mut docker = listener("0.0.0.0", 8080);
        docker.exe = Some("/usr/bin/docker-proxy".into());
        let mut v6 = listener("::", 22);
        v6.proto = "tcp6".into();
        let report = ruleset.report(
            &[
                listener("0.0.0.0", 22),
                v6,
                listener("127.0.0.1", 6379),
                listener("0.0.0.0", 5432),
                docker,
                listener("0.0.0.0", 9000),
            ],
            &[9000],
        );

        let seen: Vec<(u16, Exposure)> =
            report.ports.iter().map(|p| (p.port, p.exposure)).collect();
        assert_eq!(
            seen,
            [
                (22, Exposure::Open),
                (5432, Exposure::Restricted),
                (8080, Exposure::Docker),
                (9000, Exposure::Docker),
            ]
        );
        assert_eq!(report.backend, "ufw");
        assert_eq!(report.rules.len(), 4);
    }

    #[test]
    fn reads_every_nftables_input_chain() {
        let json: Value = serde_json::from_str(r#"{"nftables":[
            {"metainfo":{"version":"1.0.9"}},
            {"table":{"family":"inet","name":"filter","handle":1}},
            {"chain":{"family":"inet","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
            {"chain":{"family":"inet","table":"filter","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
            {"rule":{"family":"inet","table":"filter","chain":"input","handle":3,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"accept":null}]}},
            {"rule":{"family":"inet","table":"filter","chain":"input","handle":4,"expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":{"set":["established","related"]}}},{"accept":null}]}},
            {"rule":{"family":"inet","table":"filter","chain":"input","handle":5,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[22,80,443]}}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
            {"rule":{"family":"inet","table":"filter","chain":"input","handle":6,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.0.0.0","len":8}}}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":5432}},{"accept":null}]}},
            {"chain":{"family":"inet","table":"serveros","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"accept"}},
            {"rule":{"family":"inet","table":"serveros","chain":"input","handle":2,"expr":[{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"drop":null}]}}
        ]}"#).unwrap();
        let ruleset = parse_nft(&json);

        assert!(ruleset.active);
        assert_eq!(ruleset.unreadable, 0);
        assert_eq!(
            ruleset.chains.len(),
            2,
            "forward chains aren't about the machine"
        );
        assert_eq!(
            ruleset.chains[0].rules.len(),
            2,
            "loopback and replies left out"
        );
        assert_eq!(
            ruleset.chains[0].rules[0].info.text,
            "tcp dport { 22, 80, 443 } accept"
        );
        assert_eq!(
            ruleset.chains[0].rules[1].info.source.as_deref(),
            Some("10.0.0.0/8")
        );
        assert!(ruleset.chains[1].managed);
        assert_eq!(ruleset.chains[1].rules[0].handle, Some(2));

        assert_eq!(ruleset.exposure(22, "tcp").0, Exposure::Open);
        assert_eq!(
            ruleset.exposure(443, "tcp").0,
            Exposure::Blocked,
            "a drop in any chain wins"
        );
        assert_eq!(ruleset.exposure(5432, "tcp").0, Exposure::Restricted);
        assert_eq!(ruleset.exposure(3306, "tcp").0, Exposure::Blocked);
    }

    #[test]
    fn says_what_it_can_of_nftables_rules_it_cant_read() {
        let json: Value = serde_json::from_str(r#"{"nftables":[
            {"chain":{"family":"ip","table":"filter","name":"INPUT","type":"filter","hook":"input","prio":0,"policy":"accept"}},
            {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":45,"expr":[{"counter":{"packets":1,"bytes":1}},{"jump":{"target":"ufw-before-input"}}]}},
            {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":46,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8080}},{"drop":null}]}}
        ]}"#).unwrap();
        let ruleset = parse_nft(&json);
        let rules = &ruleset.chains[0].rules;

        assert_eq!(ruleset.unreadable, 2);
        assert_eq!(rules[0].info.text, "jump ufw-before-input");
        assert_eq!(rules[1].info.text, "tcp dport 8080 … drop");
        assert_eq!(rules[1].info.verdict, FirewallVerdict::Deny);
        assert_eq!(
            ruleset.exposure(5432, "tcp"),
            (Exposure::Open, "ip filter INPUT: by default allow".into())
        );
    }

    #[test]
    fn iptables_and_nftables_with_nothing_set_up_still_take_rules() {
        let iptables = parse_iptables("-P INPUT ACCEPT\n");
        let nft = parse_nft(&serde_json::json!({"nftables": []}));

        assert!(iptables.active && nft.active);
        assert_eq!(iptables.default_incoming(), Some(FirewallVerdict::Allow));
        assert_eq!(nft.default_incoming(), Some(FirewallVerdict::Allow));
        assert_eq!(
            nft.exposure(5432, "tcp"),
            (
                Exposure::Open,
                "no rules filter incoming connections".into()
            )
        );
    }

    #[test]
    fn reads_iptables_input() {
        let ruleset = parse_iptables(
            "-P INPUT DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 80,443,8000:8100 -j ACCEPT
-A INPUT ! -i lo -p tcp -m tcp --dport 8080 -m comment --comment \"ServerOS\" -j DROP
-A INPUT -j ufw-before-input
",
        );

        assert_eq!(ruleset.unreadable, 1);
        let rules = &ruleset.chains[0].rules;
        assert_eq!(rules.len(), 4, "the jump is kept in its place");
        assert!(rules[3].info.opaque);
        assert_eq!(
            rules[0].spec,
            ["-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"]
        );
        assert!(rules[2].info.managed);
        assert_eq!(ruleset.exposure(8050, "tcp").0, Exposure::Open);
        assert_eq!(
            ruleset.exposure(8080, "tcp").0,
            Exposure::Open,
            "a drop appended after an accept for its range never matches"
        );
        assert_eq!(ruleset.exposure(3306, "tcp").0, Exposure::Unknown);
    }

    #[test]
    fn ipv6_rules_count_once_the_machine_has_a_public_ipv6_address() {
        let mut ruleset = parse_ufw(
            "Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
8020/tcp                   ALLOW IN    2001:db8::/32
22/tcp (v6)                ALLOW IN    Anywhere (v6)
8010/tcp (v6)              ALLOW IN    Anywhere (v6)
",
        );
        assert_eq!(
            ruleset.exposure(8010, "tcp").0,
            Exposure::Blocked,
            "IPv4 only"
        );
        assert_eq!(
            ruleset.exposure(8020, "tcp").0,
            Exposure::Blocked,
            "an IPv6 source"
        );

        ruleset.ipv6 = true;
        assert_eq!(
            ruleset.exposure(8010, "tcp"),
            (
                Exposure::Open,
                "over IPv6, 8010/tcp (v6) ALLOW IN Anywhere (v6)".into()
            )
        );
        assert_eq!(ruleset.least_exposure(8010, "tcp").0, Exposure::Blocked);
        assert_eq!(ruleset.exposure(8020, "tcp").0, Exposure::Restricted);
        assert_eq!(
            ruleset.exposure(22, "tcp"),
            (Exposure::Open, "22/tcp ALLOW IN Anywhere".into()),
            "IPv4 explains it when both agree"
        );
    }

    #[test]
    fn an_ipv6_table_doesnt_decide_ipv4() {
        let json: Value = serde_json::from_str(r#"{"nftables":[
            {"chain":{"family":"ip6","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}}
        ]}"#).unwrap();
        let mut ruleset = parse_nft(&json);

        assert_eq!(ruleset.exposure(80, "tcp").0, Exposure::Open);
        ruleset.ipv6 = true;
        assert_eq!(ruleset.exposure(80, "tcp").0, Exposure::Open);
        assert_eq!(ruleset.least_exposure(80, "tcp").0, Exposure::Blocked);
    }

    #[test]
    fn finds_public_ipv6_addresses() {
        let dir = std::env::temp_dir().join(format!("serveros-if-inet6-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("if_inet6");
        let local = "00000000000000000000000000000001 01 80 10 80       lo
fe800000000000000000000000000001 02 40 20 80     eth0
fd000000000000000000000000000010 02 40 00 80     eth0
";
        std::fs::write(&file, local).unwrap();
        assert!(!public_ipv6(&file));

        std::fs::write(
            &file,
            format!("{local}20010db8000000000000000000000010 02 40 00 80     eth0\n"),
        )
        .unwrap();
        assert!(public_ipv6(&file));
        assert!(!public_ipv6(&dir.join("missing")));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
