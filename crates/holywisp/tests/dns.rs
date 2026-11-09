#![cfg(target_os = "linux")]
mod common;
use common::*;
use holywisp_proto::wisp::ptype;
use std::net::UdpSocket;

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
                assert_eq!(packet.payload, [holywisp_proto::wisp::close::BLOCKED]);
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
