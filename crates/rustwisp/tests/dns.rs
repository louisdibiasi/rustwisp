#![cfg(target_os = "linux")]
mod common;
use common::*;
use rustwisp_proto::wisp::ptype;
use std::net::UdpSocket;

#[test]
fn empty_udp_datagram_survives_pending_name_resolution() {
    use std::io::Write;
    let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
    dns.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut cfg = test_config();
    cfg.dns_servers = vec![dns.local_addr().unwrap().to_string()];
    let resolver = std::thread::spawn(move || {
        for _ in 0..2 {
            let mut buf = [0; 512];
            let (n, peer) = dns.recv_from(&mut buf).unwrap();
            let mut reply = buf[..n].to_vec();
            reply[2] = 0x81;
            reply[3] = 0x80;
            if buf[n - 3] == 1 {
                reply[7] = 1;
                reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            }
            dns.send_to(&reply, peer).unwrap();
        }
    });
    let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
    remote
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    let mut connect = [0; 128];
    let n = rustwisp_proto::wisp::build_connect(
        &mut connect,
        1,
        2,
        remote.local_addr().unwrap().port(),
        b"some.test",
    )
    .unwrap();
    let mut wire = c.frame_bytes(rustwisp_proto::ws::opcode::BINARY, true, &connect[..n]);
    wire.extend(c.frame_bytes(
        rustwisp_proto::ws::opcode::BINARY,
        true,
        &[ptype::DATA, 1, 0, 0, 0],
    ));
    c.sock.write_all(&wire).unwrap();
    assert_eq!(remote.recv_from(&mut [0; 1]).unwrap().0, 0);
    h.stop_and_join();
    resolver.join().unwrap();
}

#[test]
fn unrelated_dns_answer_cannot_redirect_a_stream() {
    let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
    dns.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut cfg = test_config();
    cfg.dns_servers = vec![dns.local_addr().unwrap().to_string()];
    let responder = std::thread::spawn(move || {
        for _ in 0..2 {
            let mut buf = [0; 512];
            let (n, peer) = dns.recv_from(&mut buf).unwrap();
            let mut answer = buf[..n].to_vec();
            answer[2] = 0x81;
            answer[3] = 0x80;
            if buf[n - 3] == 1 {
                answer[7] = 1;
                answer.extend_from_slice(b"\x05other\x04test\0");
                answer.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            }
            dns.send_to(&answer, peer).unwrap();
        }
    });
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    echo.set_nonblocking(true).unwrap();
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.connect_stream(1, 1, "some.test", echo.local_addr().unwrap().port());
    c.send_packet(ptype::DATA, 1, b"probe");
    c.expect_close(1, rustwisp_proto::wisp::close::UNREACHABLE);
    assert!(echo.accept().is_err());
    h.stop_and_join();
    responder.join().unwrap();
}

#[test]
fn stale_dns_reply_cannot_connect_a_reused_stream_id() {
    use std::net::TcpListener;
    use std::time::{Duration, Instant};
    let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
    dns.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut cfg = test_config();
    cfg.resolver_threads = 2;
    cfg.dns_servers = vec![dns.local_addr().unwrap().to_string()];
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    echo.set_nonblocking(true).unwrap();
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    let receive = || {
        let mut buf = [0; 512];
        let (n, peer) = dns.recv_from(&mut buf).unwrap();
        (buf[..n].to_vec(), peer)
    };
    let reply = |mut query: Vec<u8>, peer, address: bool| {
        query[2] = 0x81;
        query[3] = if address { 0x80 } else { 0x83 };
        if address {
            query[7] = 1;
            query.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
        }
        dns.send_to(&query, peer).unwrap();
    };
    c.connect_stream(1, 1, "old.test", echo.local_addr().unwrap().port());
    let old = receive();
    c.send_packet(ptype::CLOSE, 1, &[0]);
    c.connect_stream(1, 1, "new.test", echo.local_addr().unwrap().port());
    let new = receive();
    reply(old.0, old.1, true);
    let old_v6 = receive();
    reply(old_v6.0, old_v6.1, false);
    let deadline = Instant::now() + Duration::from_millis(400);
    while Instant::now() < deadline {
        assert!(
            echo.accept().is_err(),
            "stale reply connected the replacement stream"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    reply(new.0, new.1, false);
    let new_v6 = receive();
    reply(new_v6.0, new_v6.1, false);
    c.expect_close(1, rustwisp_proto::wisp::close::UNREACHABLE);
    h.stop_and_join();
}

#[test]
fn custom_resolver_reaches_local_echo() {
    for (ttl, allow) in [(0, true), (60, true), (120, true), (60, false)] {
        let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
        dns.set_read_timeout(Some(TIMEOUT)).unwrap();
        let mut cfg = test_config();
        cfg.dns_ttl_s = ttl;
        cfg.allow_loopback = allow;
        cfg.dns_servers = vec![dns.local_addr().unwrap().to_string()];
        let responder = std::thread::spawn(move || {
            for _ in 0..if allow && (ttl == 0 || ttl == 120) {
                4
            } else {
                2
            } {
                let mut buf = [0u8; 4096];
                let (n, peer) = dns.recv_from(&mut buf).unwrap();
                let mut answer = buf[..n].to_vec();
                answer[2] = 0x81;
                answer[3] = 0x80;
                if buf[n - 3] == 1 {
                    answer[7] = 1;
                    answer.extend_from_slice(&[
                        0xc0,
                        12,
                        0,
                        1,
                        0,
                        1,
                        0,
                        0,
                        0,
                        if ttl == 120 { 1 } else { 60 },
                        0,
                        4,
                        127,
                        0,
                        0,
                        1,
                    ]);
                }
                dns.send_to(&answer, peer).unwrap();
            }
        });
        let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = echo.local_addr().unwrap().port();
        let h = start(cfg);
        let mut c = Client::v1(h.port());
        echo.set_nonblocking(true).unwrap();
        use std::io::{Read, Write};
        for (sid, host) in [(1, "some.test"), (2, "SOME.TEST.")] {
            if sid == 2 && ttl == 120 {
                std::thread::sleep(std::time::Duration::from_millis(1100));
            }
            c.connect_stream(sid, 1, host, port);
            if !allow {
                let packet = c.recv_packet();
                assert_eq!(packet.ptype, ptype::CLOSE);
                assert_eq!(packet.payload, [rustwisp_proto::wisp::close::BLOCKED]);
                break;
            }
            c.send_packet(ptype::DATA, sid, b"hello");
            let deadline = std::time::Instant::now() + TIMEOUT;
            let (mut remote, _) = loop {
                if let Ok(pair) = echo.accept() {
                    break pair;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "custom resolver was not used"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            remote.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut data = [0; 5];
            remote.read_exact(&mut data).unwrap();
            remote.write_all(&data).unwrap();
            let packet = c.recv_packet();
            assert_eq!(packet.payload, b"hello");
            c.send_packet(ptype::CLOSE, sid, &[0]);
        }
        h.stop_and_join();
        responder.join().unwrap();
    }
}
