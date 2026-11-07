#![cfg(target_os = "linux")]
//! Flood protection, per-IP limits, trusted-proxy addresses and bandwidth, against a live server.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::*;
use holywisp_config::{Config, FloodConfig};
use holywisp_proto::wisp::{close, ptype};

fn flood(f: impl FnOnce(&mut FloodConfig)) -> FloodConfig {
    let mut fc = FloodConfig {
        enabled: true,
        ..test_config().flood
    };
    f(&mut fc);
    fc
}

/// The status line of a WebSocket upgrade attempt with optional extra headers.
fn upgrade_status(port: u16, extra: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    write!(
        s,
        "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
    .unwrap();
    let mut buf = [0u8; 256];
    let n = s.read(&mut buf).unwrap();
    String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Read until the server closes the socket, returning everything it said.
fn read_to_close(c: &mut Client) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];
    c.sock.set_read_timeout(Some(TIMEOUT)).unwrap();
    loop {
        match c.sock.read(&mut tmp) {
            Ok(0) => return out,
            Ok(n) => out.extend_from_slice(&tmp[..n]),
            // Closing with client bytes still unread sends a reset instead of a clean end.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return out,
            Err(e) => panic!("expected the connection to be closed: {e}"),
        }
    }
}

#[test]
fn per_ip_connection_rate_returns_429() {
    let cfg = Config {
        connections_limit_per_ip: 2,
        connection_window_s: 10,
        ..test_config()
    };
    let h = start(cfg);
    assert!(upgrade_status(h.port(), "").contains("101"));
    assert!(upgrade_status(h.port(), "").contains("101"));
    assert!(upgrade_status(h.port(), "").contains("429"));
    h.stop_and_join();
}

#[test]
fn concurrent_connection_cap_returns_503_and_frees_slots() {
    let cfg = Config {
        flood: flood(|f| f.max_concurrent_connections = 1),
        ..test_config()
    };
    let h = start(cfg);
    let held = Client::v1(h.port());
    assert!(upgrade_status(h.port(), "").contains("503"));
    drop(held);
    // The slot comes back once the server notices the close.
    let mut ok = false;
    for _ in 0..50 {
        if upgrade_status(h.port(), "").contains("101") {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ok, "slot was never released");
    h.stop_and_join();
}

#[test]
fn trusted_proxy_headers_pick_the_limited_address() {
    let cfg = Config {
        connections_limit_per_ip: 1,
        connection_window_s: 10,
        trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
        ..test_config()
    };
    let h = start(cfg);
    let xff = |ip: &str| format!("X-Forwarded-For: {ip}\r\n");
    assert!(upgrade_status(h.port(), &xff("198.51.100.1")).contains("101"));
    assert!(upgrade_status(h.port(), &xff("198.51.100.2")).contains("101"));
    assert!(upgrade_status(h.port(), &xff("198.51.100.1")).contains("429"));
    h.stop_and_join();

    // Without a trusted proxy the header is ignored and everyone is 127.0.0.1.
    let cfg = Config {
        connections_limit_per_ip: 1,
        connection_window_s: 10,
        ..test_config()
    };
    let h = start(cfg);
    assert!(upgrade_status(h.port(), &xff("198.51.100.1")).contains("101"));
    assert!(upgrade_status(h.port(), &xff("198.51.100.2")).contains("429"));
    h.stop_and_join();
}

#[test]
fn per_source_connect_rate_throttles_with_0x49() {
    let echo = echo_server();
    let cfg = Config {
        flood: flood(|f| f.max_connects_per_source_per_second = 3),
        ..test_config()
    };
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    for sid in 1..=3 {
        c.tcp(sid, echo);
    }
    c.tcp(4, echo);
    c.expect_close(4, close::THROTTLED);
    h.stop_and_join();
}

#[test]
fn per_destination_connect_rate_throttles_with_0x49() {
    let echo = echo_server();
    let cfg = Config {
        flood: flood(|f| f.max_connects_per_dest_per_second = 2),
        ..test_config()
    };
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    c.tcp(2, echo);
    c.tcp(3, echo);
    c.expect_close(3, close::THROTTLED);
    h.stop_and_join();
}

#[test]
fn repeated_violations_close_the_websocket() {
    let echo = echo_server();
    let cfg = Config {
        flood: flood(|f| {
            f.max_connects_per_source_per_second = 1;
            f.ws_close_after_violations = 3;
        }),
        ..test_config()
    };
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    for sid in 1..=6 {
        c.tcp(sid, echo);
    }
    read_to_close(&mut c);
    h.stop_and_join();
}

#[test]
fn syn_flood_signature_closes_the_connection() {
    let dead = closed_port();
    let cfg = Config {
        flood: flood(|f| {
            f.syn_signature_min_samples = 5;
            f.syn_signature_failed_ratio = 0.5;
            f.max_connects_per_source_per_second = 0;
            f.max_connects_per_dest_per_second = 0;
            f.max_connects_per_dest_per_minute = 0;
        }),
        ..test_config()
    };
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    for sid in 1..=10 {
        c.tcp(sid, dead);
    }
    let said = read_to_close(&mut c);
    // Each refused stream is answered with a 12-byte CLOSE frame; the signature ends the
    // connection before all ten can be.
    assert!(said.len() < 10 * 12, "{} bytes", said.len());
    h.stop_and_join();
}

#[test]
fn bandwidth_limit_paces_a_transfer_without_losing_bytes() {
    let echo = echo_server();
    let cfg = Config {
        bandwidth_limit_kbps: 8_000, // 1 MB/s, one free second
        ..test_config()
    };
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    let data = random_bytes(99, 1_500_000);
    let start_at = Instant::now();
    for part in data.chunks(60_000) {
        c.send_packet(ptype::DATA, 1, part);
    }
    let got = c.read_data(1, data.len());
    assert_eq!(checksum(&got), checksum(&data));
    assert!(
        start_at.elapsed() > Duration::from_millis(1200),
        "3 MB charged at 1 MB/s with a 1 s burst takes at least 2 s, took {:?}",
        start_at.elapsed()
    );
    h.stop_and_join();
}

fn reputation_cfg(warn: u32, throttle: u32, strict: u32, store: &str) -> Config {
    let base = test_config();
    Config {
        reputation_enabled: true,
        reputation: holywisp_config::ReputationConfig {
            store_path: store.into(),
            warn,
            throttle,
            strict,
            ..base.reputation.clone()
        },
        ..base
    }
}

#[test]
fn a_source_that_keeps_probing_private_space_gets_refused() {
    let h = start(reputation_cfg(0, 0, 25, ""));
    let mut c = Client::v1(h.port());
    // Two blocked private connects: 15 points each.
    c.connect_stream(1, holywisp_proto::wisp::stream_type::TCP, "10.0.0.5", 80);
    c.expect_close(1, close::BLOCKED);
    c.connect_stream(2, holywisp_proto::wisp::stream_type::TCP, "10.0.0.6", 80);
    c.expect_close(2, close::BLOCKED);
    assert!(upgrade_status(h.port(), "").contains("403"));
    h.stop_and_join();
}

#[test]
fn the_throttle_tier_caps_streams_per_connection() {
    let echo = echo_server();
    let h = start(reputation_cfg(0, 10, 0, ""));
    let mut c = Client::v1(h.port());
    c.connect_stream(1, holywisp_proto::wisp::stream_type::TCP, "10.0.0.5", 80);
    c.expect_close(1, close::BLOCKED);
    // 15 points puts this address in the throttle tier for new connections.
    let mut c = Client::v1(h.port());
    for sid in 1..=16 {
        c.tcp(sid, echo);
    }
    c.tcp(17, echo);
    c.expect_close(17, close::THROTTLED);
    h.stop_and_join();
}

#[test]
fn reputation_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("hw-e2e-rep-{}", std::process::id()));
    let store = dir.join("rep.json");
    let store = store.to_string_lossy().into_owned();
    let h = start(reputation_cfg(0, 0, 25, &store));
    let mut c = Client::v1(h.port());
    for sid in [1, 2] {
        c.connect_stream(sid, holywisp_proto::wisp::stream_type::TCP, "10.0.0.5", 80);
        c.expect_close(sid, close::BLOCKED);
    }
    h.stop_and_join();

    let h = start(reputation_cfg(0, 0, 25, &store));
    assert!(
        upgrade_status(h.port(), "").contains("403"),
        "score was loaded"
    );
    h.stop_and_join();
    let _ = std::fs::remove_dir_all(&dir);
}
