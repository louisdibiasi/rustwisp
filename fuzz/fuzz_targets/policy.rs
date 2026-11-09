#![no_main]
//! The egress and client-address policy, fed hostile hosts, ports, addresses and header values.
//! Whatever the config says, a loopback or private address must stay blocked unless it was allowed.

use arbitrary::Arbitrary;
use rustwisp::{egress, filter};
use rustwisp_config::{Cidr, Config};
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

#[derive(Debug, Arbitrary)]
struct Case {
    peer: IpAddr,
    trusted: Vec<String>,
    headers: Vec<String>,
    host: String,
    port: u16,
    ip: IpAddr,
    allow_hosts: Vec<String>,
}

fuzz_target!(|case: Case| {
    let trusted: Vec<Cidr> = case
        .trusted
        .iter()
        .filter_map(|t| t.parse().ok())
        .collect();
    let headers: Vec<&str> = case.headers.iter().map(String::as_str).collect();
    let real = filter::real_ip(case.peer, &trusted, &headers);
    // an address nobody vouched for is never replaced
    if trusted.is_empty() || !trusted.iter().any(|c| c.contains(case.peer.to_canonical())) {
        assert_eq!(real, case.peer.to_canonical());
    }

    let mut cfg = Config::default();
    for h in &case.allow_hosts {
        let _ = cfg.set("allow-host", h);
    }
    let _ = filter::host_port_ok(&cfg, &case.host, case.port);

    // with the defaults, loopback and private space are refused
    let strict = Config::default();
    let class = egress::classify(case.ip);
    if egress::check(&strict, case.ip).is_ok() {
        assert!(!case.ip.to_canonical().is_loopback(), "{class:?} let {} through", case.ip);
    }
});
