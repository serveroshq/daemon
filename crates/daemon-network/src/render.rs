//! What a network becomes on the machine, as text: the WireGuard config
//! `wg syncconf` reads, and the firewall rules for each backend.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use super::spec::{Cidr, PeerPlan, Plan, DOCKER_RANGE};

pub const KEEPALIVE_SECS: u16 = 25;

/// The config for `wg syncconf`: the interface's key and port, then every
/// peer. Peers not in it are removed; ones that are keep their sessions.
pub fn wg_config(private_key: &str, listen_port: u16, peers: &[PeerPlan]) -> String {
    let mut out = format!("[Interface]\nPrivateKey = {private_key}\nListenPort = {listen_port}\n");
    for peer in peers {
        out.push_str(&format!(
            "\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/32\n",
            peer.public_key, peer.address
        ));
        if let Some(endpoint) = &peer.endpoint {
            out.push_str(&format!(
                "Endpoint = {endpoint}\nPersistentKeepalive = {KEEPALIVE_SECS}\n"
            ));
        }
    }
    out
}

/// One firewall opening a network needs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Rule {
    /// WireGuard's own UDP port, from anywhere.
    ListenUdp { port: u16 },
    /// Everything arriving on the interface from the network.
    FromNetwork { interface: String, cidr: Cidr },
    /// Local containers reaching an exposed port on this machine's network
    /// address. Only from Docker's bridges: matching the source range alone
    /// would also let in anything on a wan or provider network that happens
    /// to be in 172.16.0.0/12 (an AWS VPC is 172.31.0.0/16) and routes the
    /// network's addresses to this machine.
    LocalToExpose {
        bridge: Bridge,
        address: Ipv4Addr,
        port: u16,
    },
}

/// The interfaces Docker's containers arrive on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bridge {
    /// docker0, and docker_gwbridge for swarm.
    Docker,
    /// A user-defined network's br-{id}.
    UserDefined,
}

pub const BRIDGES: [Bridge; 2] = [Bridge::Docker, Bridge::UserDefined];

impl Bridge {
    /// The interface name prefix, as `docker` or `br-`.
    pub fn prefix(self) -> &'static str {
        match self {
            Bridge::Docker => "docker",
            Bridge::UserDefined => "br-",
        }
    }

    /// iptables' (and so ufw's) wildcard: `docker+`.
    pub fn iptables_name(self) -> String {
        format!("{}+", self.prefix())
    }

    /// nftables' wildcard: `docker*`.
    pub fn nft_name(self) -> String {
        format!("{}*", self.prefix())
    }
}

pub fn rules_for(plan: &Plan) -> Vec<Rule> {
    let mut rules = vec![
        Rule::ListenUdp {
            port: plan.listen_port,
        },
        Rule::FromNetwork {
            interface: plan.interface.clone(),
            cidr: plan.address.network(),
        },
    ];
    rules.extend(plan.expose.iter().flat_map(|e| {
        BRIDGES.map(|bridge| Rule::LocalToExpose {
            bridge,
            address: plan.address.ip,
            port: e.port,
        })
    }));
    rules
}

impl Rule {
    /// ufw's words for the rule, after `allow` (or `delete allow`).
    pub fn ufw_args(&self) -> Vec<String> {
        let words: Vec<String> = match self {
            Rule::ListenUdp { port } => vec![format!("{port}/udp")],
            Rule::FromNetwork { interface, cidr } => vec![
                "in".into(),
                "on".into(),
                interface.clone(),
                "from".into(),
                cidr.to_string(),
            ],
            Rule::LocalToExpose {
                bridge,
                address,
                port,
            } => vec![
                "in".into(),
                "on".into(),
                bridge.iptables_name(),
                "proto".into(),
                "tcp".into(),
                "from".into(),
                DOCKER_RANGE.to_string(),
                "to".into(),
                address.to_string(),
                "port".into(),
                port.to_string(),
            ],
        };
        words
    }

    /// The nftables rule expression.
    pub fn nft_expression(&self) -> String {
        match self {
            Rule::ListenUdp { port } => format!("udp dport {port} accept"),
            Rule::FromNetwork { interface, cidr } => {
                format!("iifname \"{interface}\" ip saddr {cidr} accept")
            }
            Rule::LocalToExpose {
                bridge,
                address,
                port,
            } => format!(
                "iifname \"{}\" ip saddr {DOCKER_RANGE} ip daddr {address} tcp dport {port} accept",
                bridge.nft_name()
            ),
        }
    }

    /// iptables' match and target, after `-A CHAIN`.
    pub fn iptables_args(&self) -> Vec<String> {
        let words: Vec<String> = match self {
            Rule::ListenUdp { port } => {
                vec![
                    "-p".into(),
                    "udp".into(),
                    "--dport".into(),
                    port.to_string(),
                ]
            }
            Rule::FromNetwork { interface, cidr } => {
                vec![
                    "-i".into(),
                    interface.clone(),
                    "-s".into(),
                    cidr.to_string(),
                ]
            }
            Rule::LocalToExpose {
                bridge,
                address,
                port,
            } => vec![
                "-i".into(),
                bridge.iptables_name(),
                "-s".into(),
                DOCKER_RANGE.to_string(),
                "-d".into(),
                address.to_string(),
                "-p".into(),
                "tcp".into(),
                "--dport".into(),
                port.to_string(),
            ],
        };
        words
            .into_iter()
            .chain(["-j".to_string(), "ACCEPT".to_string()])
            .collect()
    }
}

pub const NFT_TABLE: &str = "inet serveros";
pub const NFT_INPUT: &str = "input";

/// The network's own chain: in `inet serveros` for nftables, in the filter
/// table for iptables. Jumped to from input, so taking the network down is
/// dropping the jump and the chain, whatever rules it had.
pub fn nft_chain(network: &str) -> String {
    format!("net_{network}")
}

pub fn iptables_chain(network: &str) -> String {
    format!("SOS-{network}")
}

#[cfg(test)]
mod tests {
    use daemon_protocol::{NetworkAction, NetworkExpose, NetworkPeer, NetworkSpec};

    use super::super::spec::plan;
    use super::*;

    fn planned() -> Plan {
        plan(&NetworkSpec {
            network: "p7k2q9".into(),
            action: NetworkAction::Up,
            address: Some("10.88.3.2/24".into()),
            listen_port: Some(51831),
            peers: vec![
                NetworkPeer {
                    public_key: "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=".into(),
                    address: "10.88.3.3/32".into(),
                    endpoint: Some("203.0.113.5:51831".into()),
                },
                NetworkPeer {
                    public_key: "d29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGU=".into(),
                    address: "10.88.3.4/32".into(),
                    endpoint: None,
                },
            ],
            expose: vec![NetworkExpose {
                port: 5432,
                target: "127.0.0.1:5432".into(),
            }],
        })
        .unwrap()
    }

    #[test]
    fn wg_config_lists_every_peer_with_keepalive_only_where_there_is_an_endpoint() {
        let p = planned();
        assert_eq!(
            wg_config("PRIVATE", p.listen_port, &p.peers),
            "[Interface]\n\
             PrivateKey = PRIVATE\n\
             ListenPort = 51831\n\
             \n\
             [Peer]\n\
             PublicKey = aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=\n\
             AllowedIPs = 10.88.3.3/32\n\
             Endpoint = 203.0.113.5:51831\n\
             PersistentKeepalive = 25\n\
             \n\
             [Peer]\n\
             PublicKey = d29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGU=\n\
             AllowedIPs = 10.88.3.4/32\n"
        );
        assert_eq!(
            wg_config("PRIVATE", 51831, &[]),
            "[Interface]\nPrivateKey = PRIVATE\nListenPort = 51831\n"
        );
    }

    #[test]
    fn a_network_opens_its_port_its_interface_and_each_exposed_port_to_containers() {
        let rules = rules_for(&planned());
        assert_eq!(
            rules,
            vec![
                Rule::ListenUdp { port: 51831 },
                Rule::FromNetwork {
                    interface: "sosp7k2q9".into(),
                    cidr: Cidr::parse("10.88.3.0/24").unwrap(),
                },
                Rule::LocalToExpose {
                    bridge: Bridge::Docker,
                    address: Ipv4Addr::new(10, 88, 3, 2),
                    port: 5432,
                },
                Rule::LocalToExpose {
                    bridge: Bridge::UserDefined,
                    address: Ipv4Addr::new(10, 88, 3, 2),
                    port: 5432,
                },
            ]
        );
    }

    #[test]
    fn rules_render_for_every_backend() {
        let rules = rules_for(&planned());
        let ufw: Vec<String> = rules.iter().map(|r| r.ufw_args().join(" ")).collect();
        assert_eq!(
            ufw,
            vec![
                "51831/udp",
                "in on sosp7k2q9 from 10.88.3.0/24",
                "in on docker+ proto tcp from 172.16.0.0/12 to 10.88.3.2 port 5432",
                "in on br-+ proto tcp from 172.16.0.0/12 to 10.88.3.2 port 5432",
            ]
        );

        let nft: Vec<String> = rules.iter().map(Rule::nft_expression).collect();
        assert_eq!(
            nft,
            vec![
                "udp dport 51831 accept",
                "iifname \"sosp7k2q9\" ip saddr 10.88.3.0/24 accept",
                "iifname \"docker*\" ip saddr 172.16.0.0/12 ip daddr 10.88.3.2 tcp dport 5432 accept",
                "iifname \"br-*\" ip saddr 172.16.0.0/12 ip daddr 10.88.3.2 tcp dport 5432 accept",
            ]
        );

        let iptables: Vec<String> = rules.iter().map(|r| r.iptables_args().join(" ")).collect();
        assert_eq!(
            iptables,
            vec![
                "-p udp --dport 51831 -j ACCEPT",
                "-i sosp7k2q9 -s 10.88.3.0/24 -j ACCEPT",
                "-i docker+ -s 172.16.0.0/12 -d 10.88.3.2 -p tcp --dport 5432 -j ACCEPT",
                "-i br-+ -s 172.16.0.0/12 -d 10.88.3.2 -p tcp --dport 5432 -j ACCEPT",
            ]
        );

        assert_eq!(nft_chain("p7k2q9"), "net_p7k2q9");
        assert_eq!(iptables_chain("p7k2q9"), "SOS-p7k2q9");
    }

    #[test]
    fn applied_rules_round_trip_through_the_state_file() {
        let rules = rules_for(&planned());
        let json = serde_json::to_string(&rules).unwrap();
        assert_eq!(serde_json::from_str::<Vec<Rule>>(&json).unwrap(), rules);
    }
}
