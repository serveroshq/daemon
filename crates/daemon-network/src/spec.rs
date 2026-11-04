//! Checking a network job before anything on the machine is touched: the
//! id, this machine's address, the peers and the ports to offer. What
//! passes is a `Plan` with everything parsed.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use base64::Engine;
use daemon_jobs::Failure;
use daemon_protocol::NetworkSpec;
use serde::{Deserialize, Serialize};

pub const MAX_NETWORK_ID: usize = 12;
pub const MAX_PEERS: usize = 250;
pub const MAX_EXPOSE: usize = 64;

/// Where Docker puts its bridges: local containers reach the exposed ports
/// from here, and exposed ports may forward into here.
pub const DOCKER_RANGE: Cidr = Cidr {
    ip: Ipv4Addr::new(172, 16, 0, 0),
    prefix: 12,
};
const LOOPBACK_RANGE: Cidr = Cidr {
    ip: Ipv4Addr::new(127, 0, 0, 0),
    prefix: 8,
};

/// The private ranges a project network may use. Docker's 172.16.0.0/12 is
/// left out on purpose: a network there would collide with the bridges.
const NETWORK_RANGES: [Cidr; 3] = [
    Cidr {
        ip: Ipv4Addr::new(10, 0, 0, 0),
        prefix: 8,
    },
    Cidr {
        ip: Ipv4Addr::new(100, 64, 0, 0),
        prefix: 10,
    },
    Cidr {
        ip: Ipv4Addr::new(192, 168, 0, 0),
        prefix: 16,
    },
];

/// The interface for a network: `sos` and the id, at most 15 characters,
/// the kernel's limit.
pub fn interface_name(network: &str) -> String {
    format!("sos{network}")
}

pub fn valid_network_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_NETWORK_ID
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

pub fn check_network_id(id: &str) -> Result<(), Failure> {
    if valid_network_id(id) {
        Ok(())
    } else {
        Err(invalid(format!(
            "{id:?} isn't a network id: 1 to {MAX_NETWORK_ID} lowercase letters and digits"
        )))
    }
}

fn invalid(message: impl Into<String>) -> Failure {
    Failure::new("validate", message)
}

/// An IPv4 address with a prefix length, like 10.88.3.2/24.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cidr {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Self> {
        let (ip, prefix) = text.split_once('/')?;
        if prefix.is_empty() || prefix.len() > 2 || !prefix.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let prefix: u8 = prefix.parse().ok().filter(|p| *p <= 32)?;
        Some(Self {
            ip: ip.parse().ok()?,
            prefix,
        })
    }

    fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix))
        }
    }

    /// The network this address is on: 10.88.3.0/24 for 10.88.3.2/24.
    pub fn network(&self) -> Cidr {
        Cidr {
            ip: Ipv4Addr::from(u32::from(self.ip) & self.mask()),
            prefix: self.prefix,
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.ip) & self.mask()
    }

    fn within(&self, outer: &Cidr) -> bool {
        self.prefix >= outer.prefix && outer.contains(self.ip)
    }

    fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.ip) | !self.mask())
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPlan {
    pub public_key: String,
    pub address: Ipv4Addr,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExposePlan {
    pub port: u16,
    pub target: SocketAddrV4,
}

/// An "up" job, checked and parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub network: String,
    pub interface: String,
    pub address: Cidr,
    pub listen_port: u16,
    pub peers: Vec<PeerPlan>,
    pub expose: Vec<ExposePlan>,
}

pub fn plan(spec: &NetworkSpec) -> Result<Plan, Failure> {
    check_network_id(&spec.network)?;

    let address_text = spec
        .address
        .as_deref()
        .ok_or_else(|| invalid("bringing a network up needs this machine's address"))?;
    let address = Cidr::parse(address_text).ok_or_else(|| {
        invalid(format!(
            "{address_text:?} isn't an IPv4 address with a prefix, like 10.88.3.2/24"
        ))
    })?;
    if !(8..=30).contains(&address.prefix) {
        return Err(invalid(format!(
            "{address_text} needs a prefix between /8 and /30"
        )));
    }
    if !NETWORK_RANGES.iter().any(|r| address.within(r)) {
        return Err(invalid(format!(
            "{address_text} isn't in a private range a network may use (10.0.0.0/8, 100.64.0.0/10, 192.168.0.0/16)"
        )));
    }
    let subnet = address.network();
    if address.ip == subnet.ip || address.ip == address.broadcast() {
        return Err(invalid(format!(
            "{address_text} is the network's own address, not one for a machine"
        )));
    }

    let listen_port = spec
        .listen_port
        .filter(|p| *p > 0)
        .ok_or_else(|| invalid("bringing a network up needs a UDP listen port"))?;

    if spec.peers.len() > MAX_PEERS {
        return Err(invalid(format!("a network has at most {MAX_PEERS} peers")));
    }
    let mut keys = HashSet::new();
    let mut addresses = HashSet::new();
    let mut peers = Vec::with_capacity(spec.peers.len());
    for peer in &spec.peers {
        if !valid_public_key(&peer.public_key) {
            return Err(invalid(format!(
                "{:?} isn't a WireGuard public key",
                peer.public_key
            )));
        }
        let peer_address = parse_peer_address(&peer.address).ok_or_else(|| {
            invalid(format!(
                "{:?} isn't a peer address: one IPv4 address, like 10.88.3.3/32",
                peer.address
            ))
        })?;
        if !subnet.contains(peer_address)
            || peer_address == subnet.ip
            || peer_address == address.broadcast()
        {
            return Err(invalid(format!(
                "peer {peer_address} isn't on the network {subnet}"
            )));
        }
        if peer_address == address.ip {
            return Err(invalid(format!(
                "peer {peer_address} has this machine's own address"
            )));
        }
        if let Some(endpoint) = &peer.endpoint {
            if !valid_endpoint(endpoint) {
                return Err(invalid(format!(
                    "{endpoint:?} isn't an endpoint: host:port"
                )));
            }
        }
        if !keys.insert(peer.public_key.as_str()) {
            return Err(invalid(format!(
                "peer {} is listed more than once",
                peer.public_key
            )));
        }
        if !addresses.insert(peer_address) {
            return Err(invalid(format!(
                "{peer_address} is given to more than one peer"
            )));
        }
        peers.push(PeerPlan {
            public_key: peer.public_key.clone(),
            address: peer_address,
            endpoint: peer.endpoint.clone(),
        });
    }

    if spec.expose.len() > MAX_EXPOSE {
        return Err(invalid(format!(
            "a network offers at most {MAX_EXPOSE} ports"
        )));
    }
    let mut ports = HashSet::new();
    let mut expose = Vec::with_capacity(spec.expose.len());
    for entry in &spec.expose {
        if entry.port == 0 {
            return Err(invalid("port 0 can't be offered"));
        }
        if !ports.insert(entry.port) {
            return Err(invalid(format!(
                "port {} is offered more than once",
                entry.port
            )));
        }
        let target = parse_target(&entry.target).ok_or_else(|| {
            invalid(format!(
                "{:?} can't be offered: forward only to loopback (127.0.0.0/8) or the Docker bridge (172.16.0.0/12), as ip:port",
                entry.target
            ))
        })?;
        expose.push(ExposePlan {
            port: entry.port,
            target,
        });
    }

    Ok(Plan {
        interface: interface_name(&spec.network),
        network: spec.network.clone(),
        address,
        listen_port,
        peers,
        expose,
    })
}

/// 32 bytes in standard base64, as `wg` prints them.
pub fn valid_public_key(key: &str) -> bool {
    key.len() == 44
        && base64::engine::general_purpose::STANDARD
            .decode(key)
            .is_ok_and(|bytes| bytes.len() == 32)
}

fn parse_peer_address(text: &str) -> Option<Ipv4Addr> {
    match text.split_once('/') {
        Some((ip, "32")) => ip.parse().ok(),
        Some(_) => None,
        None => text.parse().ok(),
    }
}

fn valid_endpoint(endpoint: &str) -> bool {
    if endpoint.parse::<SocketAddr>().is_ok_and(|a| a.port() > 0) {
        return true;
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return false;
    };
    let port_ok = port.parse::<u16>().is_ok_and(|p| p > 0);
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['-', '.'])
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    port_ok && host_ok
}

fn parse_target(text: &str) -> Option<SocketAddrV4> {
    let target: SocketAddr = text.parse().ok()?;
    let SocketAddr::V4(target) = target else {
        return None;
    };
    let allowed = LOOPBACK_RANGE.contains(*target.ip()) || DOCKER_RANGE.contains(*target.ip());
    (allowed && target.port() > 0).then_some(target)
}

/// Who may connect to an exposed port: peers on the network, local
/// containers, and the machine itself.
pub fn may_connect(network: &Cidr, from: IpAddr) -> bool {
    match from {
        IpAddr::V4(ip) => {
            network.contains(ip) || DOCKER_RANGE.contains(ip) || LOOPBACK_RANGE.contains(ip)
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.to_ipv4_mapped().is_some_and(|v4| {
                    network.contains(v4) || DOCKER_RANGE.contains(v4) || LOOPBACK_RANGE.contains(v4)
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use daemon_protocol::{NetworkAction, NetworkExpose, NetworkPeer};

    use super::*;

    const KEY_A: &str = "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=";
    const KEY_B: &str = "d29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGU=";

    fn spec() -> NetworkSpec {
        NetworkSpec {
            network: "p7k2q9".into(),
            action: NetworkAction::Up,
            address: Some("10.88.3.2/24".into()),
            listen_port: Some(51831),
            peers: vec![
                NetworkPeer {
                    public_key: KEY_A.into(),
                    address: "10.88.3.3/32".into(),
                    endpoint: Some("203.0.113.5:51831".into()),
                },
                NetworkPeer {
                    public_key: KEY_B.into(),
                    address: "10.88.3.4".into(),
                    endpoint: None,
                },
            ],
            expose: vec![NetworkExpose {
                port: 5432,
                target: "127.0.0.1:5432".into(),
            }],
        }
    }

    fn refused(edit: impl FnOnce(&mut NetworkSpec)) -> String {
        let mut s = spec();
        edit(&mut s);
        let failure = plan(&s).expect_err("should be refused");
        assert_eq!(failure.phase, "validate");
        failure.message
    }

    #[test]
    fn a_good_spec_plans() {
        let planned = plan(&spec()).unwrap();
        assert_eq!(planned.interface, "sosp7k2q9");
        assert_eq!(planned.address.to_string(), "10.88.3.2/24");
        assert_eq!(planned.address.network().to_string(), "10.88.3.0/24");
        assert_eq!(planned.listen_port, 51831);
        assert_eq!(planned.peers[1].address, Ipv4Addr::new(10, 88, 3, 4));
        assert_eq!(planned.expose[0].target.to_string(), "127.0.0.1:5432");
    }

    #[test]
    fn interface_names_fit_the_kernel_limit() {
        assert_eq!(interface_name("p7k2q9"), "sosp7k2q9");
        assert_eq!(interface_name("abcdefghijkl").len(), 15);
    }

    #[test]
    fn network_ids_are_short_lowercase_and_plain() {
        assert!(valid_network_id("p7k2q9"));
        assert!(valid_network_id("a"));
        assert!(valid_network_id("abcdefghijkl"));
        for bad in [
            "",
            "abcdefghijklm",
            "P7K2Q9",
            "p7-k2",
            "p7k2q9\n",
            "../etc",
            "p7k 2",
            "ñ",
        ] {
            assert!(!valid_network_id(bad), "{bad:?} passed");
            assert!(check_network_id(bad).is_err());
        }
        assert!(refused(|s| s.network = "Bad".into()).contains("network id"));
    }

    #[test]
    fn up_needs_an_address_and_a_port() {
        assert!(refused(|s| s.address = None).contains("address"));
        assert!(refused(|s| s.listen_port = None).contains("port"));
        assert!(refused(|s| s.listen_port = Some(0)).contains("port"));
    }

    #[test]
    fn bad_addresses_are_refused() {
        for bad in [
            "10.88.3.2",
            "10.88.3.2/",
            "10.88.3.2/33",
            "10.88.3.2/+4",
            "10.88.3/24",
            "fd00::2/64",
            "10.88.3.2/31",
            "10.88.3.2/4",
            "8.8.8.8/24",
            "172.17.0.2/24",
            "10.88.3.0/24",
            "10.88.3.255/24",
        ] {
            let mut s = spec();
            s.address = Some(bad.into());
            s.peers.clear();
            assert!(plan(&s).is_err(), "{bad} passed");
        }
        let mut s = spec();
        s.address = Some("192.168.50.1/24".into());
        s.peers.clear();
        assert!(plan(&s).is_ok());
    }

    #[test]
    fn bad_peers_are_refused() {
        assert!(refused(|s| s.peers[0].public_key = "short".into()).contains("public key"));
        assert!(refused(|s| s.peers[0].address = "10.88.4.3/32".into()).contains("isn't on"));
        assert!(refused(|s| s.peers[0].address = "10.88.3.0/24".into()).contains("peer address"));
        assert!(refused(|s| s.peers[0].address = "10.88.3.2/32".into()).contains("own address"));
        assert!(refused(|s| s.peers[1].public_key = KEY_A.into()).contains("more than once"));
        assert!(refused(|s| s.peers[1].address = "10.88.3.3".into()).contains("more than one"));
        assert!(refused(|s| s.peers[0].endpoint = Some("203.0.113.5".into())).contains("endpoint"));
        assert!(
            refused(|s| s.peers[0].endpoint = Some("host;rm:51820".into())).contains("endpoint")
        );

        let mut s = spec();
        s.peers[0].endpoint = Some("[2001:db8::5]:51831".into());
        s.peers[1].endpoint = Some("box.example.com:51831".into());
        assert!(plan(&s).is_ok());
    }

    #[test]
    fn exposed_ports_only_forward_to_loopback_or_docker() {
        for bad in [
            "10.88.3.3:5432",
            "8.8.8.8:53",
            "192.168.1.10:80",
            "[::1]:5432",
            "localhost:5432",
            "127.0.0.1",
            "127.0.0.1:0",
        ] {
            let message = refused(|s| s.expose[0].target = bad.into());
            assert!(message.contains("can't be offered"), "{bad}: {message}");
        }
        assert!(refused(|s| s.expose[0].port = 0).contains("port 0"));
        assert!(refused(|s| s.expose.push(s.expose[0].clone())).contains("more than once"));

        let mut s = spec();
        s.expose[0].target = "172.17.0.4:9000".into();
        assert!(plan(&s).is_ok());
    }

    #[test]
    fn only_the_network_containers_and_loopback_may_connect() {
        let net = Cidr::parse("10.88.3.0/24").unwrap();
        assert!(may_connect(&net, "10.88.3.9".parse().unwrap()));
        assert!(may_connect(&net, "172.18.0.2".parse().unwrap()));
        assert!(may_connect(&net, "127.0.0.1".parse().unwrap()));
        assert!(may_connect(&net, "::1".parse().unwrap()));
        assert!(!may_connect(&net, "10.88.4.9".parse().unwrap()));
        assert!(!may_connect(&net, "203.0.113.5".parse().unwrap()));
    }
}
