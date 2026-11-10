#![cfg(target_os = "linux")]
//! The same scripted sessions against the C server and this one, compared packet for packet.
//!
//! Skipped unless `HOLYWISP_C_BIN` names a C `holywisp` binary:
//! `HOLYWISP_C_BIN=~/src/holywisp-c/build/release/holywisp cargo test -p rustwisp --test differential`

mod common;

#[test]
fn hardened_parser_cases_are_compared_with_the_reference() {
    let Ok(bin) = std::env::var("HOLYWISP_C_BIN") else {
        return;
    };
    let reference = start_c(&bin);
    let h = common::start(common::test_config());
    let base = rustwisp_proto::http::upgrade_request(
        "127.0.0.1",
        80,
        "/",
        "dGhlIHNhbXBsZSBub25jZQ==",
        "p",
        "",
    );
    for (name, request) in [
        ("version suffix", base.replace("HTTP/1.1", "HTTP/1.1junk")),
        ("folded header", base.replace("Host:", " Host:")),
        ("control byte", base.replace("Host:", "Host: x\0")),
        (
            "invalid key",
            base.replace("dGhlIHNhbXBsZSBub25jZQ==", "bad"),
        ),
        (
            "duplicate key",
            base.replace(
                "Sec-WebSocket-Key:",
                "Sec-WebSocket-Key: x\r\nSec-WebSocket-Key:",
            ),
        ),
    ] {
        let status = |port| {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket.set_read_timeout(Some(TIMEOUT)).unwrap();
            socket.write_all(request.as_bytes()).unwrap();
            let mut buf = [0; 1024];
            let n = socket.read(&mut buf).unwrap();
            String::from_utf8_lossy(&buf[..n])
                .lines()
                .next()
                .unwrap()
                .to_string()
        };
        let from_c = status(reference.port);
        let from_rust = status(h.port());
        println!("{name}: C={from_c}; Rust={from_rust}");
        assert!(from_c.starts_with("HTTP/1."));
        assert!(from_rust.starts_with("HTTP/1.1 400"));
    }
    let mut c = Client::v1(reference.port);
    c.send_frame(opcode::CLOSE, true, &0u16.to_be_bytes());
    let from_c = c.recv_frame();
    let mut c = Client::v1(h.port());
    c.send_frame(opcode::CLOSE, true, &0u16.to_be_bytes());
    let from_rust = c.recv_frame();
    println!("invalid close: C={from_c:?}; Rust={from_rust:?}");
    assert_eq!(from_rust, (opcode::CLOSE, 1002u16.to_be_bytes().to_vec()));
    h.stop_and_join();
}

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::*;
use rustwisp_proto::wisp::{self, ptype, stream_type};
use rustwisp_proto::ws::opcode;

struct CServer {
    child: Child,
    port: u16,
}

impl Drop for CServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[allow(clippy::zombie_processes)] // CServer::drop kills and waits
fn start_c(bin: &str) -> CServer {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new(bin)
        .args(["--host", "127.0.0.1", "--workers", "2"])
        .args(["--port", &port.to_string()])
        .args([
            "--non-ws-response",
            &rustwisp_config::Config::default().non_ws_response,
        ])
        .args([
            "--allow-loopback=on",
            "--allow-direct-ip=on",
            "--flood-protection=off",
            "--reputation=off",
            "--connections-limit-per-ip=0",
            "--connection-window-s=0",
            "--log-level=error",
            "--buffer-remaining=4",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the C server");
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return CServer { child, port };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the C server never listened");
}

fn http(port: u16, request: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    // The web client page is large and has the same bytes on both; keep its head only.
    out.lines().take(8).collect::<Vec<_>>().join("|")
}

fn describe(p: &Packet) -> String {
    format!(
        "{} sid={} {:02x?}",
        wisp::type_str(p.ptype),
        p.sid,
        &p.payload[..p.payload.len().min(16)]
    )
}

/// Everything the server says for a fixed script. Ports are the only thing that differs.
fn transcript(port: u16, echo: u16, udp: u16, dead: u16) -> Vec<String> {
    let mut t = Vec::new();
    for (name, req) in [
        ("health", "GET /health HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("stats-head", "GET /stats HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("banner", "GET /nothing HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("garbage", "\u{1}\u{2} nope\r\n\r\n"),
    ] {
        let r = http(port, req);
        // /stats has live numbers; compare the status line and content type only.
        let r = if name == "stats-head" {
            r.split('|').take(2).collect::<Vec<_>>().join("|")
        } else {
            r
        };
        t.push(format!("{name}: {r}"));
    }

    let mut c = Client::connect(port, "");
    t.push(format!("v1 hello: {}", describe(&c.recv_packet())));

    c.tcp(1, echo);
    c.send_packet(ptype::DATA, 1, b"hello");
    t.push(format!("echo: {:?}", c.read_data(1, 5)));
    c.tcp(2, dead);
    t.push(format!("refused: {}", describe(&c.recv_non_continue())));
    c.connect_stream(3, stream_type::TCP, "10.1.2.3", 80);
    t.push(format!("private: {}", describe(&c.recv_non_continue())));
    c.connect_stream(4, stream_type::TCP, "127.0.0.1", 0);
    t.push(format!("port0: {}", describe(&c.recv_non_continue())));
    c.connect_stream(5, stream_type::TCP, "1.2.3", 80);
    t.push(format!("bad literal: {}", describe(&c.recv_non_continue())));
    c.connect_stream(6, 0x55, "127.0.0.1", echo);
    t.push(format!("bad type: {}", describe(&c.recv_non_continue())));
    c.tcp(1, echo);
    t.push(format!("duplicate: {}", describe(&c.recv_non_continue())));
    c.connect_stream(7, stream_type::UDP, "127.0.0.1", udp);
    c.send_packet(ptype::DATA, 7, b"datagram");
    t.push(format!("udp: {:?}", c.read_data(7, 8)));
    c.send_frame(opcode::PING, true, b"pp");
    t.push(format!("pong: {:?}", c.recv_frame()));
    c.send_packet(ptype::CLOSE, 1, &[2]);
    c.tcp(1, echo);
    c.send_packet(ptype::DATA, 1, b"again");
    t.push(format!("reuse: {:?}", c.read_data(1, 5)));
    c.send_frame(opcode::TEXT, true, b"x");
    t.push(format!("text: {:?}", c.recv_frame()));

    let mut c = Client::v1(port);
    c.send_raw(&[0x82, 0x02, 1, 2]);
    t.push(format!("unmasked: {:?}", c.recv_frame()));
    let mut c = Client::v1(port);
    c.send_frame(opcode::CONTINUATION, true, b"x");
    t.push(format!("stray continuation: {:?}", c.recv_frame()));
    let mut c = Client::v1(port);
    c.send_frame(opcode::CLOSE, true, &1001u16.to_be_bytes());
    t.push(format!("close echo: {:?}", c.recv_frame()));

    let mut c = Client::connect(port, "wisp-v2");
    let info = c.recv_packet();
    t.push(format!("v2 info: {}", describe(&info)));
    c.send_packet(ptype::INFO, 0, &[wisp::MAJOR, wisp::MINOR]);
    t.push(format!("v2 continue: {}", describe(&c.recv_packet())));
    let mut c = Client::connect(port, "wisp-v2");
    let _ = c.recv_packet();
    c.send_packet(ptype::INFO, 0, &[1, 0]);
    t.push(format!("v2 wrong major: {}", describe(&c.recv_packet())));
    t
}

#[test]
fn the_rust_server_says_what_the_c_server_says() {
    let Ok(bin) = std::env::var("HOLYWISP_C_BIN") else {
        eprintln!("HOLYWISP_C_BIN is not set: skipping the differential test");
        return;
    };
    let echo = echo_server();
    let udp = udp_echo_server();
    let dead = closed_port();

    let c = start_c(&bin);
    let from_c = transcript(c.port, echo, udp, dead);

    let mut cfg = test_config();
    cfg.buffer_remaining = 4;
    let h = start(cfg);
    let from_rust = transcript(h.port(), echo, udp, dead);
    h.stop_and_join();

    assert_eq!(from_c.len(), from_rust.len());
    let mut diffs = Vec::new();
    for (a, b) in from_c.iter().zip(&from_rust) {
        if a != b {
            diffs.push(format!("C:    {a}\nRust: {b}"));
        }
    }
    assert!(diffs.is_empty(), "sessions differ:\n{}", diffs.join("\n"));
}
