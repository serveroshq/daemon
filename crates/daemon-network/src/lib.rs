//! Project networks: a private WireGuard network per project, joining the
//! machines its apps and services run on. Each machine has one address on
//! it; services are offered on that address by small TCP forwarders, and
//! the firewall lets in WireGuard's port, the network, and local
//! containers reaching the offered ports.
//!
//! "up" applies exactly the state it's given and can be sent again any
//! time; the last state applied is kept in state.db and put back when the
//! daemon starts, since WireGuard interfaces don't survive a reboot. Each
//! network's private key is made here once, kept in a root-only file, and
//! never leaves the machine; only the public key is sent back.

pub mod exec;
pub mod forward;
pub mod ifaces;
pub mod render;
pub mod spec;

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use daemon_core::config::FirewallBackend;
use daemon_jobs::{Failure, Progress};
use daemon_protocol::{NetworkAction, NetworkSpec};
use daemon_state::State;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use exec::{Exec, ExecOutput};
use forward::Forwarders;
use render::{iptables_chain, nft_chain, Rule, NFT_INPUT, NFT_TABLE};
use spec::{check_network_id, interface_name, Plan};

const KV_KEY: &str = "networks";
const QUICK: Duration = Duration::from_secs(30);
const INSTALL: Duration = Duration::from_secs(600);

const WG_PATHS: &[&str] = &["/usr/bin/wg", "/usr/sbin/wg", "/bin/wg", "/sbin/wg"];
const UFW_PATHS: &[&str] = &["/usr/sbin/ufw"];
const NFT_PATHS: &[&str] = &["/usr/sbin/nft", "/sbin/nft"];
const IPTABLES_PATHS: &[&str] = &["/usr/sbin/iptables", "/sbin/iptables"];

/// The firewall rules a network has on the machine, and through which
/// backend, so they can be taken out again exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedFirewall {
    pub backend: FirewallBackend,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    spec: NetworkSpec,
    #[serde(default)]
    firewall: Option<AppliedFirewall>,
}

pub struct Networks {
    state: Arc<State>,
    dir: PathBuf,
    /// One change at a time, and the forwarders running per network.
    running: Mutex<HashMap<String, Forwarders>>,
}

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

async fn note(progress: Option<&Progress>, line: impl Into<String>) {
    if let Some(p) = progress {
        p.line(line).await;
    }
}

/// Failure output is the end of what the tool printed.
const FAILURE_LINES: usize = 40;

fn failed(phase: &str, message: impl Into<String>, out: ExecOutput) -> Failure {
    let mut lines = out.lines;
    if lines.len() > FAILURE_LINES {
        lines.drain(..lines.len() - FAILURE_LINES);
    }
    Failure::new(phase, message).with_output(lines)
}

impl Networks {
    /// `dir` holds the private keys: `state_dir/networks`.
    pub fn new(state: Arc<State>, dir: PathBuf) -> Self {
        Self {
            state,
            dir,
            running: Mutex::new(HashMap::new()),
        }
    }

    pub async fn apply<E: Exec>(
        &self,
        exec: &E,
        backend: FirewallBackend,
        spec: &NetworkSpec,
        progress: Option<&Progress>,
    ) -> Result<Value, Failure> {
        match spec.action {
            NetworkAction::Up => self.up(exec, backend, spec, progress).await,
            NetworkAction::Down => self.down(exec, &spec.network, progress).await,
        }
    }

    /// Every network this machine was last told to have, as stored.
    pub fn stored(&self) -> Vec<NetworkSpec> {
        self.load().into_values().map(|s| s.spec).collect()
    }

    async fn up<E: Exec>(
        &self,
        exec: &E,
        backend: FirewallBackend,
        spec: &NetworkSpec,
        progress: Option<&Progress>,
    ) -> Result<Value, Failure> {
        let plan = spec::plan(spec)?;
        let mut running = self.running.lock().await;

        ensure_wireguard_tools(exec, progress).await?;
        let (private_key, public_key) = self.key(&plan.network)?;

        ensure_interface(exec, &plan.interface, progress).await?;
        self.sync_peers(exec, &plan, &private_key).await?;
        set_address(exec, &plan, progress).await?;
        let up = exec
            .run(
                "ip",
                &args(&["link", "set", "dev", &plan.interface, "up"]),
                QUICK,
            )
            .await;
        if !up.ok {
            return Err(failed(
                "wireguard",
                format!("couldn't bring {} up", plan.interface),
                up,
            ));
        }

        let previous = self.load().remove(&plan.network).and_then(|s| s.firewall);
        let firewall = apply_firewall(exec, backend, &plan, previous.as_ref(), progress).await;
        // What's on the machine now is recorded even if the firewall half
        // failed, so a later down still finds it.
        let applied = match &firewall {
            Ok(applied) => applied.clone(),
            Err(_) => previous,
        };
        self.save(&plan.network, spec, applied)?;
        firewall?;

        let forwarders = running.entry(plan.network.clone()).or_default();
        forwarders
            .replace(plan.address.ip, plan.address.network(), &plan.expose)
            .await?;
        for (port, target) in forwarders.ports() {
            note(
                progress,
                format!("offering {}:{port} → {target}", plan.address.ip),
            )
            .await;
        }

        Ok(json!({
            "network": plan.network,
            "interface": plan.interface,
            "public_key": public_key,
            "address": plan.address.to_string(),
            "listen_port": plan.listen_port,
        }))
    }

    async fn down<E: Exec>(
        &self,
        exec: &E,
        network: &str,
        progress: Option<&Progress>,
    ) -> Result<Value, Failure> {
        check_network_id(network)?;
        let mut running = self.running.lock().await;

        if let Some(mut forwarders) = running.remove(network) {
            forwarders.stop_all().await;
        }

        let interface = interface_name(network);
        if exec
            .run("ip", &args(&["link", "show", "dev", &interface]), QUICK)
            .await
            .ok
        {
            note(progress, format!("removing {interface}")).await;
            let out = exec
                .run("ip", &args(&["link", "del", "dev", &interface]), QUICK)
                .await;
            if !out.ok {
                return Err(failed(
                    "wireguard",
                    format!("couldn't remove {interface}"),
                    out,
                ));
            }
        }

        let stored = self.load().remove(network);
        if let Some(applied) = stored.as_ref().and_then(|s| s.firewall.as_ref()) {
            remove_firewall(exec, network, applied, progress).await?;
        }

        let key = self.key_path(network);
        if key.exists() {
            std::fs::remove_file(&key).map_err(|e| {
                Failure::new("key", format!("couldn't remove {}: {e}", key.display()))
            })?;
        }
        let mut all = self.load();
        if all.remove(network).is_some() {
            self.store(&all)?;
        }

        Ok(json!({"network": network, "removed": true}))
    }

    async fn sync_peers<E: Exec>(
        &self,
        exec: &E,
        plan: &Plan,
        private_key: &str,
    ) -> Result<(), Failure> {
        // syncconf reads a file; it holds the private key, so it's written
        // root-only beside the key and removed straight after.
        let config = render::wg_config(private_key, plan.listen_port, &plan.peers);
        let path = self.dir.join(format!("{}.conf", plan.network));
        write_secret(&path, config.as_bytes(), true)?;
        let out = exec
            .run(
                "wg",
                &args(&["syncconf", &plan.interface, &path.display().to_string()]),
                QUICK,
            )
            .await;
        let _ = std::fs::remove_file(&path);
        if !out.ok {
            return Err(failed(
                "wireguard",
                format!("wg couldn't set the peers on {}", plan.interface),
                out,
            ));
        }
        Ok(())
    }

    fn key_path(&self, network: &str) -> PathBuf {
        self.dir.join(format!("{network}.key"))
    }

    /// The network's private key (made the first time) and its public key,
    /// both base64.
    fn key(&self, network: &str) -> Result<(String, String), Failure> {
        let path = self.key_path(network);
        let engine = base64::engine::general_purpose::STANDARD;
        let bytes: [u8; 32] = match std::fs::read_to_string(&path) {
            Ok(text) => engine
                .decode(text.trim())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| {
                    Failure::new(
                        "key",
                        format!("{} isn't a WireGuard private key", path.display()),
                    )
                    .with_next_step(
                        "Take the network down on this machine and bring it up again for a new key.",
                    )
                })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut bytes = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
                write_secret(&path, engine.encode(bytes).as_bytes(), false)?;
                bytes
            }
            Err(e) => {
                return Err(Failure::new(
                    "key",
                    format!("couldn't read {}: {e}", path.display()),
                ))
            }
        };
        Ok((engine.encode(bytes), engine.encode(public_key(&bytes))))
    }

    fn load(&self) -> BTreeMap<String, Stored> {
        self.state
            .kv_get(KV_KEY)
            .ok()
            .flatten()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    fn store(&self, all: &BTreeMap<String, Stored>) -> Result<(), Failure> {
        let text = serde_json::to_string(all).unwrap_or_default();
        self.state
            .kv_set(KV_KEY, &text)
            .map_err(|e| Failure::new("state", format!("couldn't save the network: {e}")))
    }

    fn save(
        &self,
        network: &str,
        spec: &NetworkSpec,
        firewall: Option<AppliedFirewall>,
    ) -> Result<(), Failure> {
        let mut all = self.load();
        all.insert(
            network.to_string(),
            Stored {
                spec: spec.clone(),
                firewall,
            },
        );
        self.store(&all)
    }
}

/// X25519's public key for a private one, as WireGuard works it out (the
/// scalar clamped first).
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(*private).to_bytes()
}

/// Writes a root-only file: 0600 in a 0700 folder. With `replace` an old
/// one is overwritten; without, it must not exist yet.
fn write_secret(path: &Path, contents: &[u8], replace: bool) -> Result<(), Failure> {
    let fail =
        |e: std::io::Error| Failure::new("key", format!("couldn't write {}: {e}", path.display()));
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(fail)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(fail)?;
    }
    if replace {
        let _ = std::fs::remove_file(path);
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(fail)?;
    file.write_all(contents).map_err(fail)?;
    file.sync_all().map_err(fail)
}

/// `wg`, installed with the machine's package manager if it's missing:
/// apt, then dnf, then yum, as for package jobs.
async fn ensure_wireguard_tools<E: Exec>(
    exec: &E,
    progress: Option<&Progress>,
) -> Result<(), Failure> {
    if exec.has(WG_PATHS) {
        return Ok(());
    }
    note(progress, "installing wireguard-tools").await;

    let out = if exec.has(&["/usr/bin/apt-get"]) {
        let install = args(&[
            "install",
            "-y",
            "-q",
            "--no-install-recommends",
            "wireguard-tools",
        ]);
        let first = exec.run("apt-get", &install, INSTALL).await;
        if first.ok {
            first
        } else {
            // Usually stale package lists on a fresh machine.
            exec.run("apt-get", &args(&["update", "-q"]), INSTALL).await;
            exec.run("apt-get", &install, INSTALL).await
        }
    } else if let Some(manager) = ["dnf", "yum"]
        .into_iter()
        .find(|m| exec.has(&[&format!("/usr/bin/{m}")]))
    {
        exec.run(
            manager,
            &args(&["-y", "-q", "install", "wireguard-tools"]),
            INSTALL,
        )
        .await
    } else {
        return Err(Failure::new(
            "install",
            "wg isn't installed and there's no supported package manager (apt, dnf, yum) to install it",
        )
        .with_next_step("Install wireguard-tools on the machine, then retry."));
    };

    if !out.ok || !exec.has(WG_PATHS) {
        return Err(failed("install", "couldn't install wireguard-tools", out)
            .with_next_step("Install wireguard-tools on the machine, then retry."));
    }
    Ok(())
}

async fn ensure_interface<E: Exec>(
    exec: &E,
    interface: &str,
    progress: Option<&Progress>,
) -> Result<(), Failure> {
    if exec
        .run("ip", &args(&["link", "show", "dev", interface]), QUICK)
        .await
        .ok
    {
        return Ok(());
    }

    note(progress, format!("creating {interface}")).await;
    // Built in from Linux 5.6; a module before that, loaded on first use
    // on most systems, but not always.
    let _ = exec.run("modprobe", &args(&["wireguard"]), QUICK).await;
    let out = exec
        .run(
            "ip",
            &args(&["link", "add", "dev", interface, "type", "wireguard"]),
            QUICK,
        )
        .await;
    if out.ok {
        return Ok(());
    }

    let text = out.lines.join(" ").to_lowercase();
    if text.contains("unknown device type")
        || text.contains("not supported")
        || text.contains("no such device")
    {
        return Err(failed(
            "wireguard",
            "this machine's kernel has no WireGuard support",
            out,
        )
        .with_next_step(
            "WireGuard is part of Linux 5.6 and later. On an older kernel install the wireguard kernel module; on a container VPS (OpenVZ, LXC) ask the provider to enable it.",
        ));
    }
    Err(failed(
        "wireguard",
        format!("couldn't create {interface}"),
        out,
    ))
}

/// The IPv4 addresses `ip -o -4 address show` lists.
pub fn listed_addresses(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            words.find(|w| *w == "inet")?;
            words.next().map(str::to_string)
        })
        .collect()
}

async fn set_address<E: Exec>(
    exec: &E,
    plan: &Plan,
    progress: Option<&Progress>,
) -> Result<(), Failure> {
    let wanted = plan.address.to_string();
    let listed = exec
        .run(
            "ip",
            &args(&["-o", "-4", "address", "show", "dev", &plan.interface]),
            QUICK,
        )
        .await;
    if listed.ok && listed_addresses(&listed.lines) == [wanted.clone()] {
        return Ok(());
    }

    note(
        progress,
        format!("setting {} on {}", wanted, plan.interface),
    )
    .await;
    let _ = exec
        .run(
            "ip",
            &args(&["address", "flush", "dev", &plan.interface]),
            QUICK,
        )
        .await;
    let out = exec
        .run(
            "ip",
            &args(&["address", "add", &wanted, "dev", &plan.interface]),
            QUICK,
        )
        .await;
    if !out.ok {
        return Err(failed(
            "wireguard",
            format!("couldn't give {} the address {wanted}", plan.interface),
            out,
        ));
    }
    Ok(())
}

fn require<E: Exec>(exec: &E, tool: &str, paths: &[&str], install: &str) -> Result<(), Failure> {
    if exec.has(paths) {
        Ok(())
    } else {
        Err(Failure::new(
            "firewall",
            format!("{tool} is not installed on this machine"),
        )
        .with_next_step(install))
    }
}

async fn apply_firewall<E: Exec>(
    exec: &E,
    backend: FirewallBackend,
    plan: &Plan,
    previous: Option<&AppliedFirewall>,
    progress: Option<&Progress>,
) -> Result<Option<AppliedFirewall>, Failure> {
    let rules = render::rules_for(plan);

    // Rules left by another backend (the setting changed) come out first.
    let previous = match previous {
        Some(p) if p.backend != backend => {
            remove_firewall(exec, &plan.network, p, progress).await?;
            None
        }
        other => other,
    };

    match backend {
        FirewallBackend::None => return Ok(None),
        FirewallBackend::Ufw => {
            require(exec, "ufw", UFW_PATHS, "apt install ufw")?;
            if let Some(previous) = previous {
                for stale in previous.rules.iter().filter(|r| !rules.contains(r)) {
                    ufw(exec, &["delete", "allow"], stale).await?;
                }
            }
            for rule in &rules {
                ufw(exec, &["allow"], rule).await?;
            }
        }
        FirewallBackend::Nftables => {
            require(exec, "nft", NFT_PATHS, "apt install nftables")?;
            let chain = nft_chain(&plan.network);
            nft(exec, &[&format!("add table {NFT_TABLE}")]).await?;
            // Made only if missing: `add chain` with a policy on a chain
            // that exists would reset whatever policy it has now.
            let input = format!("list chain {NFT_TABLE} {NFT_INPUT}");
            if !exec.run("nft", &args(&[&input]), QUICK).await.ok {
                nft(
                    exec,
                    &[&format!(
                        "add chain {NFT_TABLE} {NFT_INPUT} {{ type filter hook input priority 0; policy accept; }}"
                    )],
                )
                .await?;
            }
            let mut steps = vec![
                format!("add chain {NFT_TABLE} {chain}"),
                format!("flush chain {NFT_TABLE} {chain}"),
            ];
            steps.extend(
                rules
                    .iter()
                    .map(|r| format!("add rule {NFT_TABLE} {chain} {}", r.nft_expression())),
            );
            for step in steps {
                nft(exec, &[&step]).await?;
            }
            let listing = format!("list chain {NFT_TABLE} {NFT_INPUT}");
            let listed = nft(exec, &["-a", &listing]).await?;
            if nft_handle(&listed.lines, &format!("jump {chain}")).is_none() {
                nft(
                    exec,
                    &[&format!("insert rule {NFT_TABLE} {NFT_INPUT} jump {chain}")],
                )
                .await?;
            }

            // Every base chain on the input hook has its say, and a drop in
            // any of them is final: an accept in our table doesn't get past
            // the operator's `policy drop`. So the rules also go at the top
            // of each other inet input chain, tagged so they can be found
            // and taken out again.
            let tag = nft_tag(&plan.network);
            for (table, other) in nft_input_chains(exec).await? {
                untag_nft_chain(exec, &table, &other, &tag).await?;
                for rule in rules.iter().rev() {
                    nft(
                        exec,
                        &[&format!(
                            "insert rule inet {table} {other} {} comment \"{tag}\"",
                            rule.nft_expression()
                        )],
                    )
                    .await?;
                }
            }
        }
        FirewallBackend::Iptables => {
            require(exec, "iptables", IPTABLES_PATHS, "apt install iptables")?;
            let chain = iptables_chain(&plan.network);
            // Already there on a second up; that's fine.
            let _ = exec.run("iptables", &args(&["-N", &chain]), QUICK).await;
            iptables(exec, &args(&["-F", &chain])).await?;
            for rule in &rules {
                let mut a = args(&["-A", &chain]);
                a.extend(rule.iptables_args());
                iptables(exec, &a).await?;
            }
            let jump = args(&["-C", "INPUT", "-j", &chain]);
            if !exec.run("iptables", &jump, QUICK).await.ok {
                iptables(exec, &args(&["-I", "INPUT", "1", "-j", &chain])).await?;
            }
        }
    }

    note(
        progress,
        format!("firewall: {} rules for {}", rules.len(), plan.interface),
    )
    .await;
    Ok(Some(AppliedFirewall { backend, rules }))
}

async fn remove_firewall<E: Exec>(
    exec: &E,
    network: &str,
    applied: &AppliedFirewall,
    progress: Option<&Progress>,
) -> Result<(), Failure> {
    note(
        progress,
        format!("removing the firewall rules for {network}"),
    )
    .await;
    match applied.backend {
        FirewallBackend::None => {}
        FirewallBackend::Ufw => {
            for rule in &applied.rules {
                ufw(exec, &["delete", "allow"], rule).await?;
            }
        }
        FirewallBackend::Nftables => {
            let chain = nft_chain(network);
            let listing = format!("list chain {NFT_TABLE} {NFT_INPUT}");
            if let Ok(listed) = nft(exec, &["-a", &listing]).await {
                if let Some(handle) = nft_handle(&listed.lines, &format!("jump {chain}")) {
                    nft(
                        exec,
                        &[&format!(
                            "delete rule {NFT_TABLE} {NFT_INPUT} handle {handle}"
                        )],
                    )
                    .await?;
                }
            }
            // Gone already is fine.
            let _ = nft(exec, &[&format!("flush chain {NFT_TABLE} {chain}")]).await;
            let _ = nft(exec, &[&format!("delete chain {NFT_TABLE} {chain}")]).await;
            let tag = nft_tag(network);
            for (table, other) in nft_input_chains(exec).await.unwrap_or_default() {
                untag_nft_chain(exec, &table, &other, &tag).await?;
            }
        }
        FirewallBackend::Iptables => {
            let chain = iptables_chain(network);
            while exec
                .run("iptables", &args(&["-D", "INPUT", "-j", &chain]), QUICK)
                .await
                .ok
            {}
            let _ = exec.run("iptables", &args(&["-F", &chain]), QUICK).await;
            let _ = exec.run("iptables", &args(&["-X", &chain]), QUICK).await;
        }
    }
    Ok(())
}

/// The comment on the rules a network adds to other tables' chains.
pub fn nft_tag(network: &str) -> String {
    format!("serveros:{}", nft_chain(network))
}

/// The base chains on the input hook in inet tables other than ours, as
/// `nft -j list chains` lists them. ip and ip6 tables are left alone: those
/// are iptables-nft's, and it can't read rules the nft tool adds.
pub fn other_input_chains(json: &str) -> Vec<(String, String)> {
    let Ok(listing) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let ours = NFT_TABLE.trim_start_matches("inet ");
    listing["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let chain = item.get("chain")?;
            let field = |k: &str| chain.get(k).and_then(Value::as_str);
            let (table, name) = (field("table")?, field("name")?);
            (field("family")? == "inet" && field("hook")? == "input" && table != ours)
                .then(|| (table.to_string(), name.to_string()))
        })
        .collect()
}

/// The handles of rules carrying `tag`, in `nft -a list chain` output.
pub fn tagged_handles(lines: &[String], tag: &str) -> Vec<u64> {
    let marker = format!("comment \"{tag}\"");
    lines
        .iter()
        .filter(|line| line.contains(&marker))
        .filter_map(|line| line.rsplit_once("# handle ")?.1.trim().parse().ok())
        .collect()
}

/// Table and chain names nft prints are plain words; anything else is left
/// alone rather than pasted into a command.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

async fn nft_input_chains<E: Exec>(exec: &E) -> Result<Vec<(String, String)>, Failure> {
    let listed = nft(exec, &["-j", "list", "chains"]).await?;
    Ok(other_input_chains(&listed.lines.join("\n"))
        .into_iter()
        .filter(|(table, chain)| plain_name(table) && plain_name(chain))
        .collect())
}

async fn untag_nft_chain<E: Exec>(
    exec: &E,
    table: &str,
    chain: &str,
    tag: &str,
) -> Result<(), Failure> {
    let listing = format!("list chain inet {table} {chain}");
    let listed = nft(exec, &["-a", &listing]).await?;
    for handle in tagged_handles(&listed.lines, tag) {
        nft(
            exec,
            &[&format!("delete rule inet {table} {chain} handle {handle}")],
        )
        .await?;
    }
    Ok(())
}

async fn ufw<E: Exec>(exec: &E, verb: &[&str], rule: &Rule) -> Result<(), Failure> {
    let mut a = args(verb);
    a.extend(rule.ufw_args());
    let out = exec.run("ufw", &a, Duration::from_secs(60)).await;
    // Deleting a rule that's already gone is what we wanted anyway.
    let gone = verb.first() == Some(&"delete")
        && out
            .lines
            .iter()
            .any(|l| l.contains("Could not delete non-existent rule"));
    if out.ok || gone {
        Ok(())
    } else {
        Err(failed(
            "firewall",
            format!("ufw refused {}", a.join(" ")),
            out,
        ))
    }
}

async fn nft<E: Exec>(exec: &E, words: &[&str]) -> Result<ExecOutput, Failure> {
    let out = exec.run("nft", &args(words), QUICK).await;
    if out.ok {
        Ok(out)
    } else {
        Err(failed(
            "firewall",
            format!("nft refused {}", words.join(" ")),
            out,
        ))
    }
}

async fn iptables<E: Exec>(exec: &E, a: &[String]) -> Result<(), Failure> {
    let out = exec.run("iptables", a, QUICK).await;
    if out.ok {
        Ok(())
    } else {
        Err(failed(
            "firewall",
            format!("iptables refused {}", a.join(" ")),
            out,
        ))
    }
}

/// Each tool's answer to "which rule is this?": the handle nft prints
/// after a rule matching `expression`, in `nft -a list` output.
pub fn nft_handle(lines: &[String], expression: &str) -> Option<u64> {
    lines.iter().find_map(|line| {
        let (rule, handle) = line.trim().rsplit_once("# handle ")?;
        (rule.trim() == expression)
            .then(|| handle.trim().parse().ok())
            .flatten()
    })
}

impl Networks {
    /// Every stored network, applied again, as the daemon does when it
    /// starts: after a reboot nothing of them is left but what the firewall
    /// keeps. `permit` is asked first for each (the daemon's capability
    /// check; `None` skips the network) and `finish` is told how it went.
    pub async fn restore<E: Exec, G>(
        &self,
        exec: &E,
        backend: FirewallBackend,
        permit: impl Fn(&str) -> Option<G>,
        finish: impl Fn(G, &str, &Result<Value, Failure>),
    ) -> usize {
        let mut restored = 0;
        for spec in self.stored() {
            let Some(grant) = permit(&spec.network) else {
                continue;
            };
            let result = self.apply(exec, backend, &spec, None).await;
            if result.is_ok() {
                restored += 1;
            }
            finish(grant, &spec.network, &result);
        }
        restored
    }
}

#[cfg(test)]
mod tests {
    use daemon_protocol::{NetworkExpose, NetworkPeer};

    use super::exec::fake::Scripted;
    use super::*;

    const PEER: &str = "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=";

    fn up_spec(listen_port: u16, expose: Vec<NetworkExpose>) -> NetworkSpec {
        NetworkSpec {
            network: "p7k2q9".into(),
            action: NetworkAction::Up,
            address: Some("10.88.3.2/24".into()),
            listen_port: Some(listen_port),
            peers: vec![NetworkPeer {
                public_key: PEER.into(),
                address: "10.88.3.3/32".into(),
                endpoint: Some("203.0.113.5:51831".into()),
            }],
            expose,
        }
    }

    fn down_spec() -> NetworkSpec {
        NetworkSpec {
            network: "p7k2q9".into(),
            action: NetworkAction::Down,
            address: None,
            listen_port: None,
            peers: vec![],
            expose: vec![],
        }
    }

    fn networks() -> (Networks, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let networks = Networks::new(
            Arc::new(State::in_memory().unwrap()),
            dir.path().join("networks"),
        );
        (networks, dir)
    }

    fn machine() -> Scripted {
        let fake = Scripted::with_tools(&[
            "/usr/bin/wg",
            "/usr/sbin/ufw",
            "/usr/sbin/nft",
            "/usr/sbin/iptables",
        ]);
        // No interface yet.
        fake.answer(
            "ip link show",
            false,
            &["Device \"sosp7k2q9\" does not exist."],
        );
        fake
    }

    #[test]
    fn public_keys_are_x25519() {
        // RFC 7748, section 6.1.
        let private: [u8; 32] =
            hex_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        assert_eq!(
            public_key(&private),
            hex_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
    }

    fn hex_bytes(text: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn reads_the_addresses_ip_lists() {
        let lines = vec![
            "7: sosp7k2q9    inet 10.88.3.2/24 scope global sosp7k2q9\\       valid_lft forever preferred_lft forever".to_string(),
        ];
        assert_eq!(listed_addresses(&lines), vec!["10.88.3.2/24"]);
        assert!(listed_addresses(&[]).is_empty());
    }

    #[tokio::test]
    async fn up_creates_the_interface_and_down_takes_out_exactly_what_up_added() {
        let (networks, dir) = networks();
        let fake = machine();

        let result = networks
            .apply(&fake, FirewallBackend::Ufw, &up_spec(51831, vec![]), None)
            .await
            .unwrap();
        assert_eq!(result["network"], "p7k2q9");
        assert_eq!(result["interface"], "sosp7k2q9");
        assert_eq!(result["address"], "10.88.3.2/24");
        assert_eq!(result["listen_port"], 51831);
        let public = result["public_key"].as_str().unwrap().to_string();
        assert!(spec::valid_public_key(&public));

        let calls = fake.take();
        let conf = dir
            .path()
            .join("networks/p7k2q9.conf")
            .display()
            .to_string();
        assert_eq!(
            calls,
            vec![
                "ip link show dev sosp7k2q9".to_string(),
                "modprobe wireguard".into(),
                "ip link add dev sosp7k2q9 type wireguard".into(),
                format!("wg syncconf sosp7k2q9 {conf}"),
                "ip -o -4 address show dev sosp7k2q9".into(),
                "ip address flush dev sosp7k2q9".into(),
                "ip address add 10.88.3.2/24 dev sosp7k2q9".into(),
                "ip link set dev sosp7k2q9 up".into(),
                "ufw allow 51831/udp".into(),
                "ufw allow in on sosp7k2q9 from 10.88.3.0/24".into(),
            ]
        );
        // The config with the private key doesn't stay on disk; the key does,
        // root-only, and the same key comes back next time.
        assert!(!Path::new(&conf).exists());
        let key = dir.path().join("networks/p7k2q9.key");
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(dir.path().join("networks"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        // Again, on a new port: the interface is there, the address is
        // right, the old port's rule goes.
        fake.rules.lock().unwrap().clear();
        fake.answer(
            "ip -o -4 address show",
            true,
            &["7: sosp7k2q9    inet 10.88.3.2/24 scope global sosp7k2q9"],
        );
        let again = networks
            .apply(&fake, FirewallBackend::Ufw, &up_spec(51900, vec![]), None)
            .await
            .unwrap();
        assert_eq!(again["public_key"], public.as_str());
        let calls = fake.take();
        assert!(!calls.iter().any(|c| c.starts_with("ip link add")));
        assert!(!calls.iter().any(|c| c.starts_with("ip address add")));
        assert!(calls.contains(&"ufw delete allow 51831/udp".to_string()));
        assert!(calls.contains(&"ufw allow 51900/udp".to_string()));
        assert_eq!(networks.stored()[0].listen_port, Some(51900));

        let removed = networks
            .apply(&fake, FirewallBackend::Ufw, &down_spec(), None)
            .await
            .unwrap();
        assert_eq!(removed, json!({"network": "p7k2q9", "removed": true}));
        assert_eq!(
            fake.take(),
            vec![
                "ip link show dev sosp7k2q9",
                "ip link del dev sosp7k2q9",
                "ufw delete allow 51900/udp",
                "ufw delete allow in on sosp7k2q9 from 10.88.3.0/24",
            ]
        );
        assert!(!key.exists());
        assert!(networks.stored().is_empty());
    }

    #[tokio::test]
    async fn down_on_an_unknown_network_has_nothing_to_do() {
        let (networks, _dir) = networks();
        let fake = machine();
        let removed = networks
            .apply(&fake, FirewallBackend::Ufw, &down_spec(), None)
            .await
            .unwrap();
        assert_eq!(removed["removed"], true);
        assert_eq!(fake.take(), vec!["ip link show dev sosp7k2q9"]);

        let mut bad = down_spec();
        bad.network = "../x".into();
        assert!(networks
            .apply(&fake, FirewallBackend::Ufw, &bad, None)
            .await
            .is_err());
        assert!(fake.take().is_empty());
    }

    #[tokio::test]
    async fn exposed_ports_are_opened_to_local_containers_and_closed_when_they_go() {
        let rules = render::rules_for(
            &spec::plan(&up_spec(
                51831,
                vec![NetworkExpose {
                    port: 5432,
                    target: "127.0.0.1:5432".into(),
                }],
            ))
            .unwrap(),
        );
        let fake = machine();
        let previous = AppliedFirewall {
            backend: FirewallBackend::Ufw,
            rules,
        };
        let plan = spec::plan(&up_spec(51831, vec![])).unwrap();
        apply_firewall(&fake, FirewallBackend::Ufw, &plan, Some(&previous), None)
            .await
            .unwrap();
        assert_eq!(
            fake.take(),
            vec![
                "ufw delete allow in on docker+ proto tcp from 172.16.0.0/12 to 10.88.3.2 port 5432",
                "ufw delete allow in on br-+ proto tcp from 172.16.0.0/12 to 10.88.3.2 port 5432",
                "ufw allow 51831/udp",
                "ufw allow in on sosp7k2q9 from 10.88.3.0/24",
            ]
        );
    }

    #[tokio::test]
    async fn nftables_rules_live_in_a_chain_of_the_network_s_own() {
        let fake = machine();
        // A fresh machine: no ServerOS input chain yet, no other tables.
        fake.answer(
            "nft list chain inet serveros input",
            false,
            &["No such file or directory"],
        );
        let plan = spec::plan(&up_spec(
            51831,
            vec![NetworkExpose {
                port: 5432,
                target: "127.0.0.1:5432".into(),
            }],
        ))
        .unwrap();
        apply_firewall(&fake, FirewallBackend::Nftables, &plan, None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            fake.take(),
            vec![
                "nft add table inet serveros",
                "nft list chain inet serveros input",
                "nft add chain inet serveros input { type filter hook input priority 0; policy accept; }",
                "nft add chain inet serveros net_p7k2q9",
                "nft flush chain inet serveros net_p7k2q9",
                "nft add rule inet serveros net_p7k2q9 udp dport 51831 accept",
                "nft add rule inet serveros net_p7k2q9 iifname \"sosp7k2q9\" ip saddr 10.88.3.0/24 accept",
                "nft add rule inet serveros net_p7k2q9 iifname \"docker*\" ip saddr 172.16.0.0/12 ip daddr 10.88.3.2 tcp dport 5432 accept",
                "nft add rule inet serveros net_p7k2q9 iifname \"br-*\" ip saddr 172.16.0.0/12 ip daddr 10.88.3.2 tcp dport 5432 accept",
                "nft -a list chain inet serveros input",
                "nft insert rule inet serveros input jump net_p7k2q9",
                "nft -j list chains",
            ]
        );
    }

    #[tokio::test]
    async fn nftables_rules_also_go_into_the_operator_s_input_chains() {
        let fake = machine();
        // Our input chain exists (its policy is left as it is), the jump is
        // there, and the operator has inet filter with policy drop; ip
        // filter is iptables-nft's and is left alone.
        fake.answer(
            "nft -a list chain inet serveros input",
            true,
            &["\t\tjump net_p7k2q9 # handle 12"],
        );
        fake.answer(
            "nft -j list chains",
            true,
            &[r#"{"nftables": [{"metainfo": {"version": "1.0.6"}}, {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}, {"chain": {"family": "inet", "table": "serveros", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}}]}"#],
        );
        fake.answer(
            "nft -a list chain inet filter input",
            true,
            &[
                "\t\tudp dport 51831 accept comment \"serveros:net_p7k2q9\" # handle 30",
                "\t\tudp dport 9 accept comment \"serveros:net_other\" # handle 31",
                "\t\tct state established,related accept # handle 2",
            ],
        );
        let plan = spec::plan(&up_spec(51831, vec![])).unwrap();
        let applied = apply_firewall(&fake, FirewallBackend::Nftables, &plan, None, None)
            .await
            .unwrap()
            .unwrap();
        let calls = fake.take();
        assert!(!calls.iter().any(|c| c.contains("policy")), "{calls:?}");
        assert!(!calls
            .iter()
            .any(|c| c.contains("insert rule inet serveros input")));
        assert!(!calls.iter().any(|c| c.contains(" ip filter")));
        assert_eq!(
            calls[calls.len() - 4..],
            [
                "nft -a list chain inet filter input",
                "nft delete rule inet filter input handle 30",
                "nft insert rule inet filter input iifname \"sosp7k2q9\" ip saddr 10.88.3.0/24 accept comment \"serveros:net_p7k2q9\"",
                "nft insert rule inet filter input udp dport 51831 accept comment \"serveros:net_p7k2q9\"",
            ]
        );

        remove_firewall(&fake, "p7k2q9", &applied, None)
            .await
            .unwrap();
        assert_eq!(
            fake.take(),
            vec![
                "nft -a list chain inet serveros input",
                "nft delete rule inet serveros input handle 12",
                "nft flush chain inet serveros net_p7k2q9",
                "nft delete chain inet serveros net_p7k2q9",
                "nft -j list chains",
                "nft -a list chain inet filter input",
                "nft delete rule inet filter input handle 30",
            ]
        );
    }

    #[test]
    fn reads_nft_listings() {
        assert!(other_input_chains("").is_empty());
        assert!(other_input_chains("not json").is_empty());
        let lines = vec![
            "udp dport 1 accept comment \"serveros:net_a\" # handle 7".to_string(),
            "udp dport 2 accept comment \"serveros:net_ab\" # handle 8".to_string(),
        ];
        assert_eq!(tagged_handles(&lines, "serveros:net_a"), vec![7]);
        assert!(plain_name("filter"));
        assert!(!plain_name("filter; flush ruleset"));
    }

    #[tokio::test]
    async fn iptables_rules_live_in_a_chain_of_the_network_s_own() {
        let fake = machine();
        fake.answer("iptables -C INPUT", false, &[]);
        let plan = spec::plan(&up_spec(
            51831,
            vec![NetworkExpose {
                port: 5432,
                target: "127.0.0.1:5432".into(),
            }],
        ))
        .unwrap();
        let applied = apply_firewall(&fake, FirewallBackend::Iptables, &plan, None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            fake.take(),
            vec![
                "iptables -N SOS-p7k2q9",
                "iptables -F SOS-p7k2q9",
                "iptables -A SOS-p7k2q9 -p udp --dport 51831 -j ACCEPT",
                "iptables -A SOS-p7k2q9 -i sosp7k2q9 -s 10.88.3.0/24 -j ACCEPT",
                "iptables -A SOS-p7k2q9 -i docker+ -s 172.16.0.0/12 -d 10.88.3.2 -p tcp --dport 5432 -j ACCEPT",
                "iptables -A SOS-p7k2q9 -i br-+ -s 172.16.0.0/12 -d 10.88.3.2 -p tcp --dport 5432 -j ACCEPT",
                "iptables -C INPUT -j SOS-p7k2q9",
                "iptables -I INPUT 1 -j SOS-p7k2q9",
            ]
        );

        fake.answer("iptables -D INPUT", false, &[]);
        remove_firewall(&fake, "p7k2q9", &applied, None)
            .await
            .unwrap();
        assert_eq!(
            fake.take(),
            vec![
                "iptables -D INPUT -j SOS-p7k2q9",
                "iptables -F SOS-p7k2q9",
                "iptables -X SOS-p7k2q9",
            ]
        );
    }

    #[tokio::test]
    async fn no_firewall_backend_means_no_rules() {
        let fake = machine();
        let plan = spec::plan(&up_spec(51831, vec![])).unwrap();
        let applied = apply_firewall(&fake, FirewallBackend::None, &plan, None, None)
            .await
            .unwrap();
        assert_eq!(applied, None);
        assert!(fake.take().is_empty());
    }

    #[tokio::test]
    async fn a_kernel_without_wireguard_says_so() {
        let (networks, _dir) = networks();
        let fake = machine();
        fake.answer("ip link add", false, &["Error: Unknown device type."]);
        let failure = networks
            .apply(&fake, FirewallBackend::Ufw, &up_spec(51831, vec![]), None)
            .await
            .unwrap_err();
        assert_eq!(failure.phase, "wireguard");
        assert!(failure.message.contains("no WireGuard support"));
        assert!(failure.next_step.unwrap().contains("5.6"));
    }

    #[tokio::test]
    async fn wireguard_tools_are_installed_when_missing() {
        let fake = Scripted::with_tools(&["/usr/bin/apt-get"]);
        fake.answer("apt-get install", false, &["E: Unable to locate package"]);
        let failure = ensure_wireguard_tools(&fake, None).await.unwrap_err();
        assert_eq!(failure.phase, "install");
        assert_eq!(
            fake.take(),
            vec![
                "apt-get install -y -q --no-install-recommends wireguard-tools",
                "apt-get update -q",
                "apt-get install -y -q --no-install-recommends wireguard-tools",
            ]
        );

        let fake = Scripted::with_tools(&["/usr/bin/dnf"]);
        assert!(ensure_wireguard_tools(&fake, None).await.is_err());
        assert_eq!(fake.take(), vec!["dnf -y -q install wireguard-tools"]);

        let fake = Scripted::with_tools(&[]);
        let failure = ensure_wireguard_tools(&fake, None).await.unwrap_err();
        assert!(failure.message.contains("no supported package manager"));
    }
}
