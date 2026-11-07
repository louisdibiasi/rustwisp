//! Host and port allow/block lists. A non-empty allow list wins: only listed targets pass and the
//! block list is not consulted. With an empty allow list the block list applies.

use std::net::IpAddr;

use holywisp_config::{Cidr, Config};

pub fn host_port_ok(cfg: &Config, host: &str, port: u16) -> bool {
    if !cfg.allow_hosts.is_empty() {
        if !cfg.allow_hosts.matches(host) {
            return false;
        }
    } else if cfg.block_hosts.matches(host) {
        return false;
    }
    if !cfg.allow_ports.is_empty() {
        cfg.allow_ports.contains(port)
    } else {
        cfg.block_ports.is_empty() || !cfg.block_ports.contains(port)
    }
}

/// The client address policy applies to. When the socket peer is a trusted proxy, the headers it
/// forwards (in the configured order) are searched from the right for the first address that is
/// not itself a trusted hop; otherwise the peer is the client.
pub fn real_ip(peer: IpAddr, trusted: &[Cidr], header_values: &[&str]) -> IpAddr {
    let peer = peer.to_canonical();
    if trusted.is_empty() || !trusted.iter().any(|c| c.contains(peer)) {
        return peer;
    }
    for value in header_values {
        for token in value.rsplit(',') {
            let token = token.trim().trim_start_matches('[').trim_end_matches(']');
            if let Ok(ip) = token.parse::<IpAddr>() {
                let ip = ip.to_canonical();
                if !trusted.iter().any(|c| c.contains(ip)) {
                    return ip;
                }
            }
        }
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(f: impl FnOnce(&mut Config)) -> Config {
        let mut c = Config::default();
        f(&mut c);
        c
    }

    #[test]
    fn empty_lists_allow_everything() {
        assert!(host_port_ok(&Config::default(), "example.com", 443));
    }

    #[test]
    fn allow_list_wins_over_block_list() {
        let c = cfg(|c| {
            c.allow_hosts.add("good.example").unwrap();
            c.block_hosts.add("good.example").unwrap();
        });
        assert!(host_port_ok(&c, "good.example", 80));
        assert!(!host_port_ok(&c, "other.example", 80));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let c = cfg(|c| c.block_hosts.add("*.bad.test").unwrap());
        assert!(!host_port_ok(&c, "a.bad.test", 80));
        assert!(host_port_ok(&c, "bad.test", 80));
        assert!(host_port_ok(&c, "notbad.test", 80));
    }

    fn trusted() -> Vec<Cidr> {
        vec!["127.0.0.1".parse().unwrap(), "10.0.0.0/8".parse().unwrap()]
    }

    #[test]
    fn untrusted_peers_cannot_choose_their_address() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(real_ip(peer, &trusted(), &["1.2.3.4"]), peer);
        assert_eq!(real_ip(peer, &[], &["1.2.3.4"]), peer);
    }

    #[test]
    fn trusted_peers_pass_on_the_right_most_untrusted_hop() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let got = real_ip(peer, &trusted(), &["9.9.9.9, 198.51.100.7, 10.1.1.1"]);
        assert_eq!(got, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(
            real_ip(peer, &trusted(), &["10.2.2.2"]),
            peer,
            "only trusted hops"
        );
        assert_eq!(real_ip(peer, &trusted(), &[]), peer);
        assert_eq!(
            real_ip(peer, &trusted(), &["junk, [2001:db8::5]"]),
            "2001:db8::5".parse::<IpAddr>().unwrap()
        );
        let first = real_ip(peer, &trusted(), &["", "192.0.2.4"]);
        assert_eq!(
            first,
            "192.0.2.4".parse::<IpAddr>().unwrap(),
            "later header is tried when the first is empty"
        );
    }

    #[test]
    fn ports() {
        let c = cfg(|c| {
            c.block_ports.add_spec("25").unwrap();
            c.block_ports.add_spec("6000-6010").unwrap();
        });
        assert!(!host_port_ok(&c, "h", 25));
        assert!(!host_port_ok(&c, "h", 6005));
        assert!(host_port_ok(&c, "h", 443));
        let c = cfg(|c| {
            c.allow_ports.add_spec("80").unwrap();
            c.allow_ports.add_spec("443").unwrap();
        });
        assert!(host_port_ok(&c, "h", 443));
        assert!(!host_port_ok(&c, "h", 8080));
    }
}
