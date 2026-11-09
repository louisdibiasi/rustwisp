#![cfg(target_os = "linux")]
//! HTTP endpoints, the WebSocket layer and the Wisp handshakes, against a live server.

mod common;

#[test]
fn websocket_close_payloads_are_validated() {
    let h = common::start(common::test_config());
    for code in [0u16, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, 65535] {
        let mut c = common::Client::v1(h.port());
        c.send_frame(rustwisp_proto::ws::opcode::CLOSE, true, &code.to_be_bytes());
        assert_eq!(
            c.recv_frame(),
            (
                rustwisp_proto::ws::opcode::CLOSE,
                1002u16.to_be_bytes().to_vec()
            ),
            "{code}"
        );
    }
    let mut c = common::Client::v1(h.port());
    c.send_frame(rustwisp_proto::ws::opcode::CLOSE, true, &[3, 232, 0xff]);
    assert_eq!(
        c.recv_frame(),
        (
            rustwisp_proto::ws::opcode::CLOSE,
            1007u16.to_be_bytes().to_vec()
        )
    );
    for code in [
        1000u16, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 4999,
    ] {
        let mut c = common::Client::v1(h.port());
        c.send_frame(rustwisp_proto::ws::opcode::CLOSE, true, &code.to_be_bytes());
        assert_eq!(
            c.recv_frame(),
            (
                rustwisp_proto::ws::opcode::CLOSE,
                code.to_be_bytes().to_vec()
            )
        );
    }
    h.stop_and_join();
}

#[test]
fn malformed_upgrade_is_rejected_before_switching_protocols() {
    let h = common::start(common::test_config());
    for extra in [
        "Sec-WebSocket-Key: other\r\n",
        " Sec-WebSocket-Protocol: p\r\n",
        "X-Control: a\0b\r\n",
    ] {
        let mut sock = std::net::TcpStream::connect(("127.0.0.1", h.port())).unwrap();
        sock.set_read_timeout(Some(common::TIMEOUT)).unwrap();
        let request = rustwisp_proto::http::upgrade_request(
            "127.0.0.1",
            h.port(),
            "/",
            "dGhlIHNhbXBsZSBub25jZQ==",
            "p",
            extra,
        );
        std::io::Write::write_all(&mut sock, request.as_bytes()).unwrap();
        let mut response = [0; 512];
        let n = std::io::Read::read(&mut sock, &mut response).unwrap();
        assert!(response[..n].starts_with(b"HTTP/1.1 400"), "{response:?}");
    }
    h.stop_and_join();
}

use std::io::{Read, Write};
use std::net::TcpStream;

use common::*;
use rustwisp_proto::wisp::{self, close, ext, ptype};
use rustwisp_proto::ws::opcode;

fn http_get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn health_and_stats_endpoints() {
    let h = start(test_config());
    let r = http_get(h.port(), "/health");
    assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
    assert!(r.ends_with("{\"status\":\"ok\"}\n"));
    let r = http_get(h.port(), "/stats");
    assert!(r.contains("\"uptimeSeconds\":"), "{r}");
    assert!(r.contains("\"connections\":{\"total\":"));
    h.stop_and_join();
}

#[test]
fn plain_request_gets_the_banner_and_the_web_client_is_served() {
    let h = start(test_config());
    let r = http_get(h.port(), "/nothing");
    assert!(r.contains("rustwisp: a Wisp server."), "{r}");
    let r = http_get(h.port(), "/");
    assert!(r.contains("text/html"), "{r}");
    assert!(r.contains("</html>"));
    h.stop_and_join();

    let mut cfg = test_config();
    cfg.serve_webclient = false;
    let h = start(cfg);
    let r = http_get(h.port(), "/");
    assert!(
        r.contains("rustwisp: a Wisp server."),
        "banner replaces the page: {r}"
    );
    h.stop_and_join();

    let mut cfg = test_config();
    cfg.non_ws_response.clear();
    let h = start(cfg);
    assert!(http_get(h.port(), "/x").starts_with("HTTP/1.1 426"));
    h.stop_and_join();
}

#[test]
fn webclient_url_is_injected() {
    let mut cfg = test_config();
    cfg.webclient_wisp_url = "wss://example.test/wisp/".into();
    let h = start(cfg);
    let r = http_get(h.port(), "/");
    assert!(r.contains("wss://example.test/wisp/"));
    h.stop_and_join();
}

#[test]
fn garbage_request_gets_400() {
    let h = start(test_config());
    let mut s = TcpStream::connect(("127.0.0.1", h.port())).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    s.write_all(b"\x16\x03\x01 not http at all\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    h.stop_and_join();
}

#[test]
fn v1_handshake_sends_continue_for_stream_zero() {
    let h = start(test_config());
    let mut c = Client::connect(h.port(), "");
    let p = c.recv_packet();
    assert_eq!((p.ptype, p.sid), (ptype::CONTINUE, 0));
    let window = u32::from_le_bytes(p.payload[..4].try_into().unwrap());
    assert_eq!(
        window, 8,
        "default 1 MiB packets cap the window by stream-queue-max"
    );
    h.stop_and_join();
}

#[test]
fn window_follows_buffer_remaining_when_packets_are_small() {
    let mut cfg = test_config();
    cfg.max_message_size = 65_541;
    let h = start(cfg);
    let mut c = Client::connect(h.port(), "");
    let p = c.recv_packet();
    assert_eq!(u32::from_le_bytes(p.payload[..4].try_into().unwrap()), 128);
    h.stop_and_join();
}

#[test]
fn v2_handshake_advertises_extensions_then_continues() {
    let mut cfg = test_config();
    cfg.motd = "hello there".into();
    let h = start(cfg);
    let mut c = Client::connect(h.port(), "wisp-v2");
    let info = c.recv_packet();
    assert_eq!((info.ptype, info.sid), (ptype::INFO, 0));
    assert_eq!(&info.payload[..2], &[wisp::MAJOR, wisp::MINOR]);
    let mut ids = Vec::new();
    let mut rest = &info.payload[2..];
    while rest.len() >= 5 {
        let len = u32::from_le_bytes(rest[1..5].try_into().unwrap()) as usize;
        ids.push((rest[0], rest[5..5 + len].to_vec()));
        rest = &rest[5 + len..];
    }
    assert!(ids.iter().any(|(id, _)| *id == ext::UDP));
    assert!(
        ids.iter()
            .any(|(id, m)| *id == ext::MOTD && m == b"hello there")
    );
    assert!(!ids.iter().any(|(id, _)| *id == ext::PASSWORD));

    // Nothing else comes until the client answers with its own INFO.
    c.send_packet(ptype::INFO, 0, &[wisp::MAJOR, wisp::MINOR]);
    let p = c.recv_packet();
    assert_eq!((p.ptype, p.sid), (ptype::CONTINUE, 0));
    h.stop_and_join();
}

#[test]
fn v2_with_wrong_major_is_incompatible() {
    let h = start(test_config());
    let mut c = Client::connect(h.port(), "anything-goes");
    let _ = c.recv_packet();
    c.send_packet(ptype::INFO, 0, &[1, 0]);
    c.expect_close(0, close::INCOMPATIBLE);
    h.stop_and_join();
}

#[test]
fn password_auth() {
    let mut cfg = test_config();
    cfg.users.push(rustwisp_config::User {
        name: "alice".into(),
        secret: "s3cret".into(),
    });
    cfg.password_required = true;
    let h = start(cfg);

    // v1 clients cannot authenticate: refused at the HTTP layer.
    let mut s = TcpStream::connect(("127.0.0.1", h.port())).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    write!(
        s,
        "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 426"), "{out}");

    // The server announces that a password is required.
    let mut c = Client::connect(h.port(), "p");
    let info = c.recv_packet();
    assert!(
        info.payload
            .windows(6)
            .any(|w| w == [ext::PASSWORD, 1, 0, 0, 0, 1])
    );

    // Wrong password.
    let creds = |user: &str, pass: &str| {
        let mut m = vec![ext::PASSWORD];
        let mut meta = vec![user.len() as u8];
        meta.extend_from_slice(&(pass.len() as u16).to_le_bytes());
        meta.extend_from_slice(user.as_bytes());
        meta.extend_from_slice(pass.as_bytes());
        m.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        m.extend_from_slice(&meta);
        m
    };
    let mut body = vec![wisp::MAJOR, wisp::MINOR];
    body.extend(creds("alice", "wrong"));
    c.send_packet(ptype::INFO, 0, &body);
    c.expect_close(0, close::AUTH_BAD_PASSWORD);

    // Missing credentials.
    let mut c = Client::connect(h.port(), "p");
    let _ = c.recv_packet();
    c.send_packet(ptype::INFO, 0, &[wisp::MAJOR, wisp::MINOR]);
    c.expect_close(0, close::AUTH_REQUIRED);

    // Right password.
    let mut c = Client::connect(h.port(), "p");
    let _ = c.recv_packet();
    let mut body = vec![wisp::MAJOR, wisp::MINOR];
    body.extend(creds("alice", "s3cret"));
    c.send_packet(ptype::INFO, 0, &body);
    let p = c.recv_packet();
    assert_eq!((p.ptype, p.sid), (ptype::CONTINUE, 0));
    h.stop_and_join();
}

#[test]
fn ping_gets_a_pong_with_the_same_payload() {
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.send_frame(opcode::PING, true, b"are you there");
    let (op, payload) = c.recv_frame();
    assert_eq!(op, opcode::PONG);
    assert_eq!(payload, b"are you there");
    h.stop_and_join();
}

#[test]
fn a_ping_between_fragments_is_answered_and_the_message_survives() {
    let echo = echo_server();
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    // CONNECT split in two fragments with a ping in the middle.
    let mut pl = vec![wisp::stream_type::TCP];
    pl.extend_from_slice(&echo.to_le_bytes());
    pl.extend_from_slice(b"127.0.0.1");
    let mut msg = vec![ptype::CONNECT, 1, 0, 0, 0];
    msg.extend(pl);
    let (a, b) = msg.split_at(6);
    c.send_frame(opcode::BINARY, false, a);
    c.send_frame(opcode::PING, true, b"mid");
    c.send_frame(opcode::CONTINUATION, true, b);
    let (op, p) = c.recv_frame();
    assert_eq!((op, p.as_slice()), (opcode::PONG, &b"mid"[..]));
    c.send_packet(ptype::DATA, 1, b"after fragments");
    assert_eq!(c.read_data(1, 15), b"after fragments");
    h.stop_and_join();
}

#[test]
fn unmasked_client_frame_is_a_protocol_error() {
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.send_raw(&[0x82, 0x05, 1, 2, 3, 4, 5]);
    let (op, p) = c.recv_frame();
    assert_eq!(op, opcode::CLOSE);
    assert_eq!(p, 1002u16.to_be_bytes());
    c.expect_eof();
    h.stop_and_join();
}

#[test]
fn text_frame_is_refused_with_1003() {
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.send_frame(opcode::TEXT, true, b"hi");
    let (op, p) = c.recv_frame();
    assert_eq!((op, p), (opcode::CLOSE, 1003u16.to_be_bytes().to_vec()));
    h.stop_and_join();
}

#[test]
fn oversize_frame_is_refused_with_1009() {
    let mut cfg = test_config();
    cfg.max_message_size = 1024;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.send_frame(opcode::BINARY, true, &vec![0u8; 2000]);
    let (op, p) = c.recv_frame();
    assert_eq!((op, p), (opcode::CLOSE, 1009u16.to_be_bytes().to_vec()));
    h.stop_and_join();
}

#[test]
fn fragments_that_add_up_past_the_limit_are_refused_with_1009() {
    let mut cfg = test_config();
    cfg.max_message_size = 1024;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.send_frame(opcode::BINARY, false, &[0u8; 700]);
    c.send_frame(opcode::CONTINUATION, true, &[0u8; 700]);
    let (op, p) = c.recv_frame();
    assert_eq!((op, p), (opcode::CLOSE, 1009u16.to_be_bytes().to_vec()));
    h.stop_and_join();
}

#[test]
fn continuation_without_a_start_is_a_protocol_error() {
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.send_frame(opcode::CONTINUATION, true, b"x");
    let (op, p) = c.recv_frame();
    assert_eq!((op, p), (opcode::CLOSE, 1002u16.to_be_bytes().to_vec()));
    h.stop_and_join();
}

#[test]
fn client_close_frame_is_echoed_and_the_socket_closes() {
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.send_frame(opcode::CLOSE, true, &1000u16.to_be_bytes());
    let (op, p) = c.recv_frame();
    assert_eq!((op, p), (opcode::CLOSE, 1000u16.to_be_bytes().to_vec()));
    c.expect_eof();
    h.stop_and_join();
}

#[test]
fn close_for_stream_zero_ends_the_connection() {
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.send_packet(ptype::CLOSE, 0, &[close::VOLUNTARY]);
    c.expect_eof();
    h.stop_and_join();
}

#[test]
fn handshake_timeout_drops_idle_connections() {
    let mut cfg = test_config();
    cfg.handshake_timeout_ms = 200;
    let h = start(cfg);
    let mut s = TcpStream::connect(("127.0.0.1", h.port())).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut b = [0u8; 1];
    assert_eq!(s.read(&mut b).unwrap(), 0, "closed without a word");
    h.stop_and_join();
}

#[test]
fn eager_client_frames_after_the_upgrade_are_not_lost() {
    let echo = echo_server();
    let h = start(test_config());
    let mut s = TcpStream::connect(("127.0.0.1", h.port())).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    // The upgrade request and the first frames in one write.
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let mut bytes = rustwisp_proto::http::upgrade_request("x", 1, "/", key, "", "").into_bytes();
    let mut helper = Client::connect(h.port(), "");
    let mut pl = vec![wisp::stream_type::TCP];
    pl.extend_from_slice(&echo.to_le_bytes());
    pl.extend_from_slice(b"127.0.0.1");
    let mut msg = vec![ptype::CONNECT, 3, 0, 0, 0];
    msg.extend(pl);
    bytes.extend(helper.frame_bytes(opcode::BINARY, true, &msg));
    let mut data = vec![ptype::DATA, 3, 0, 0, 0];
    data.extend_from_slice(b"early bird");
    bytes.extend(helper.frame_bytes(opcode::BINARY, true, &data));
    s.write_all(&bytes).unwrap();
    let mut got = Vec::new();
    let mut tmp = [0u8; 4096];
    while !got.windows(10).any(|w| w == b"early bird") {
        let n = s.read(&mut tmp).unwrap();
        assert!(n > 0);
        got.extend_from_slice(&tmp[..n]);
    }
    h.stop_and_join();
}

#[test]
fn a_client_that_pings_without_reading_is_dropped() {
    let cfg = rustwisp_config::Config {
        ws_write_high_water: 64 * 1024,
        ..test_config()
    };
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    let ping = c.frame_bytes(opcode::PING, true, &[7u8; 125]);
    // Never read. The kernel buffers some megabytes of pongs, then the server's own queue grows
    // past its cap and the connection is closed, which shows up as a failed write.
    let mut failed = false;
    for _ in 0..2_000_000 {
        if c.sock.write_all(&ping).is_err() {
            failed = true;
            break;
        }
    }
    assert!(
        failed,
        "the server kept an unbounded queue for a client that never reads"
    );
    h.stop_and_join();
}
