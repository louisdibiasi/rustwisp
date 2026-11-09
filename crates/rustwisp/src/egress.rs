//! Egress policy: which remote addresses a stream may be opened to. Anything that is not a public
//! unicast address is denied unless the operator opened that class up.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustwisp_config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrClass {
    Public,
    Loopback,
    Private,
    LinkLocal,
    Unspecified,
    Multicast,
    Reserved,
}

impl AddrClass {
    pub fn as_str(self) -> &'static str {
        match self {
            AddrClass::Public => "public",
            AddrClass::Loopback => "loopback",
            AddrClass::Private => "private",
            AddrClass::LinkLocal => "link-local",
            AddrClass::Unspecified => "unspecified",
            AddrClass::Multicast => "multicast",
            AddrClass::Reserved => "reserved",
        }
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddrClass {
    let [b0, b1, b2, _] = ip.octets();
    if u32::from(ip) == 0xFFFF_FFFF {
        return AddrClass::Multicast; // limited broadcast
    }
    match (b0, b1, b2) {
        (0, _, _) => AddrClass::Unspecified,
        (127, _, _) => AddrClass::Loopback,
        (10, _, _) => AddrClass::Private,
        (172, b, _) if b & 0xF0 == 16 => AddrClass::Private,
        (192, 168, _) => AddrClass::Private,
        (100, b, _) if b & 0xC0 == 64 => AddrClass::Private, // CGNAT
        (169, 254, _) => AddrClass::LinkLocal,
        (224..=239, _, _) => AddrClass::Multicast,
        (240..=255, _, _) => AddrClass::Reserved,
        (192, 0, 0) | (192, 0, 2) | (198, 51, 100) | (203, 0, 113) => AddrClass::Reserved,
        (198, 18 | 19, _) => AddrClass::Reserved, // benchmarking
        _ => AddrClass::Public,
    }
}

/// An IPv4 address tunnelled inside an IPv6 one may never count as public.
fn wrapped_v4(class: AddrClass) -> AddrClass {
    if class == AddrClass::Public {
        AddrClass::Reserved
    } else {
        class
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddrClass {
    let a = ip.octets();
    if a[..15].iter().all(|&b| b == 0) {
        return if a[15] == 1 {
            AddrClass::Loopback
        } else {
            AddrClass::Unspecified
        };
    }
    let embedded = |at: usize| Ipv4Addr::new(a[at], a[at + 1], a[at + 2], a[at + 3]);
    let zeros = |r: std::ops::Range<usize>| a[r].iter().all(|&b| b == 0);
    // ::ffff:a.b.c.d is an IPv4 address in v6 clothes and keeps its own class.
    if zeros(0..10) && a[10] == 0xff && a[11] == 0xff {
        return classify_v4(embedded(12));
    }
    // ::ffff:0:a.b.c.d (SIIT), 64:ff9b::/96 (NAT64) and ::a.b.c.d (deprecated IPv4-compatible)
    // all wrap an IPv4 address that must never make the whole address count as public.
    let siit = zeros(0..8) && a[8] == 0xff && a[9] == 0xff && a[10] == 0 && a[11] == 0;
    let nat64 = a[..4] == [0, 0x64, 0xff, 0x9b] && zeros(4..12);
    if siit || nat64 || zeros(0..12) {
        return wrapped_v4(classify_v4(embedded(12)));
    }
    if a[0] == 0xff {
        return AddrClass::Multicast;
    }
    if a[0] & 0xfe == 0xfc {
        return AddrClass::Private; // fc00::/7 unique local
    }
    if a[0] == 0xfe {
        return match a[1] & 0xc0 {
            0x80 => AddrClass::LinkLocal,
            _ => AddrClass::Reserved, // fec0::/10 site-local and the rest of fe00::/8
        };
    }
    // Only 2000::/3 is global unicast; everything else is unassigned or special-purpose.
    if a[0] & 0xe0 != 0x20 {
        return AddrClass::Reserved;
    }
    if a[0] == 0x20 && a[1] == 0x02 {
        return wrapped_v4(classify_v4(embedded(2))); // 6to4
    }
    let special = (a[0] == 0x20 && a[1] == 0x01 && a[2] < 0x02) // 2001::/23 IETF, Teredo, ORCHID...
        || a[..4] == [0x20, 0x01, 0x0d, 0xb8] // documentation
        || (a[0] == 0x3f && a[1] == 0xff && a[2] < 0x10); // 3fff::/20 documentation
    if special {
        AddrClass::Reserved
    } else {
        AddrClass::Public
    }
}

pub fn classify(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// `Ok(())` when the policy lets a stream reach `ip`, otherwise the class that was refused.
pub fn check(cfg: &Config, ip: IpAddr) -> Result<(), AddrClass> {
    let class = classify(ip);
    let ok = match class {
        AddrClass::Public => true,
        AddrClass::Loopback => cfg.allow_loopback,
        AddrClass::Private => cfg.allow_private,
        AddrClass::LinkLocal => cfg.allow_link_local,
        AddrClass::Unspecified | AddrClass::Multicast | AddrClass::Reserved => false,
    };
    if ok { Ok(()) } else { Err(class) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> AddrClass {
        classify(s.parse().unwrap())
    }

    #[test]
    fn v4_classes() {
        assert_eq!(c("8.8.8.8"), AddrClass::Public);
        assert_eq!(c("127.0.0.1"), AddrClass::Loopback);
        assert_eq!(c("10.1.2.3"), AddrClass::Private);
        assert_eq!(c("172.16.0.1"), AddrClass::Private);
        assert_eq!(c("172.32.0.1"), AddrClass::Public);
        assert_eq!(c("192.168.1.1"), AddrClass::Private);
        assert_eq!(c("100.64.0.1"), AddrClass::Private);
        assert_eq!(c("100.128.0.1"), AddrClass::Public);
        assert_eq!(c("169.254.1.1"), AddrClass::LinkLocal);
        assert_eq!(c("0.0.0.0"), AddrClass::Unspecified);
        assert_eq!(c("224.0.0.1"), AddrClass::Multicast);
        assert_eq!(c("255.255.255.255"), AddrClass::Multicast);
        assert_eq!(c("240.0.0.1"), AddrClass::Reserved);
        assert_eq!(c("192.0.2.5"), AddrClass::Reserved);
        assert_eq!(c("198.19.0.1"), AddrClass::Reserved);
    }

    #[test]
    fn v6_classes() {
        assert_eq!(c("::1"), AddrClass::Loopback);
        assert_eq!(c("::"), AddrClass::Unspecified);
        assert_eq!(c("fd00::1"), AddrClass::Private);
        assert_eq!(c("fe80::1"), AddrClass::LinkLocal);
        assert_eq!(c("ff02::1"), AddrClass::Multicast);
        assert_eq!(c("2001:db8::1"), AddrClass::Reserved);
        assert_eq!(c("2606:4700::1111"), AddrClass::Public);
        assert_eq!(c("4000::1"), AddrClass::Reserved, "outside 2000::/3");
        assert_eq!(c("2001:0:4136:e378::1"), AddrClass::Reserved, "Teredo");
        assert_eq!(
            c("2001:20::1"),
            AddrClass::Reserved,
            "ORCHIDv2, inside 2001::/23"
        );
        assert_eq!(c("3fff::1"), AddrClass::Reserved);
        assert_eq!(c("64:ff9b:1::1"), AddrClass::Reserved, "local-use NAT64");
    }

    #[test]
    fn wrapped_v4_cannot_bypass_the_policy() {
        assert_eq!(c("::ffff:127.0.0.1"), AddrClass::Loopback);
        assert_eq!(c("::ffff:10.0.0.1"), AddrClass::Private);
        assert_eq!(c("::ffff:8.8.8.8"), AddrClass::Public);
        assert_eq!(c("64:ff9b::7f00:1"), AddrClass::Loopback);
        assert_eq!(c("64:ff9b::808:808"), AddrClass::Reserved);
        assert_eq!(c("2002:7f00:1::"), AddrClass::Loopback);
        assert_eq!(c("2002:0808:0808::"), AddrClass::Reserved);
        assert_eq!(c("::10.0.0.1"), AddrClass::Private);
        assert_eq!(c("::ffff:0:10.0.0.1"), AddrClass::Private, "SIIT");
        assert_eq!(c("::ffff:0:8.8.8.8"), AddrClass::Reserved);
    }

    #[test]
    fn switches_open_only_their_own_class() {
        let mut cfg = Config::default();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let lan: IpAddr = "192.168.0.9".parse().unwrap();
        assert_eq!(check(&cfg, lo), Err(AddrClass::Loopback));
        cfg.allow_loopback = true;
        assert_eq!(check(&cfg, lo), Ok(()));
        assert_eq!(check(&cfg, lan), Err(AddrClass::Private));
        cfg.allow_private = true;
        assert_eq!(check(&cfg, lan), Ok(()));
        let mc: IpAddr = "224.1.1.1".parse().unwrap();
        assert_eq!(check(&cfg, mc), Err(AddrClass::Multicast));
    }
}
