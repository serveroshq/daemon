//! The subnets of this machine's Docker bridges (docker0, docker_gwbridge,
//! br-{id}), so a forwarder can tell a local container from anything else
//! with a 172.16.0.0/12 address.

use std::net::Ipv4Addr;

use super::render::BRIDGES;
use super::spec::Cidr;

/// Whether an interface is one Docker's containers arrive on.
pub fn is_bridge(name: &str) -> bool {
    BRIDGES.iter().any(|b| name.starts_with(b.prefix()))
}

fn prefix_len(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// The IPv4 subnets on the machine's Docker bridges, read now (bridges come
/// and go with Docker networks).
pub fn bridge_subnets() -> Vec<Cidr> {
    let mut found = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list` with a linked list we only read, and
    // freeifaddrs releases it once; every pointer is null-checked first.
    unsafe {
        if libc::getifaddrs(&mut list) != 0 {
            return found;
        }
        let mut entry = list;
        while !entry.is_null() {
            let ifa = &*entry;
            entry = ifa.ifa_next;
            if ifa.ifa_addr.is_null()
                || ifa.ifa_netmask.is_null()
                || ifa.ifa_name.is_null()
                || i32::from((*ifa.ifa_addr).sa_family) != libc::AF_INET
            {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
            if !is_bridge(&name) {
                continue;
            }
            let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
            let mask = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let mask = Ipv4Addr::from(u32::from_be(mask.sin_addr.s_addr));
            found.push(
                Cidr {
                    ip,
                    prefix: prefix_len(mask),
                }
                .network(),
            );
        }
        libc::freeifaddrs(list);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_s_bridges_and_nothing_else() {
        assert!(is_bridge("docker0"));
        assert!(is_bridge("docker_gwbridge"));
        assert!(is_bridge("br-4f2a9c1d7e3b"));
        assert!(!is_bridge("eth0"));
        assert!(!is_bridge("ens5"));
        assert!(!is_bridge("sosp7k2q9"));
        assert!(!is_bridge("bridge0"));
        assert_eq!(prefix_len(Ipv4Addr::new(255, 255, 0, 0)), 16);
    }

    #[test]
    fn reading_the_machine_s_interfaces_does_not_fail() {
        // Whatever this machine has; the point is the walk is sound.
        for subnet in bridge_subnets() {
            assert!(subnet.prefix <= 32);
        }
    }
}
