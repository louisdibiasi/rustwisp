#![no_main]
//! The small typed config values: proxy URLs, CIDRs, port sets and host lists.

use rustwisp_config::{Cidr, HostList, PortSet, ProxyUrl};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(p) = text.parse::<ProxyUrl>() {
        assert!(!p.host.is_empty() && p.port != 0);
        if p.pass.is_some() {
            // Debug output must not depend on the password at all.
            let mut other = p.clone();
            other.pass = Some("another password".to_string());
            assert_eq!(format!("{p:?}"), format!("{other:?}"));
        }
    }

    if let Ok(c) = text.parse::<Cidr>() {
        // containment must hold for the network's own address and never panic for others
        assert!(c.contains(c.addr));
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
        ] {
            let _ = c.contains(ip);
        }
    }

    let mut ports = PortSet::default();
    if ports.add_spec(text).is_ok() {
        assert!(!ports.is_empty());
        assert!(ports.len() <= usize::from(u16::MAX));
    }

    let mut hosts = HostList::default();
    if hosts.add(text).is_ok() {
        let _ = hosts.matches(text);
        assert!(hosts.len() == 1);
    }
});
