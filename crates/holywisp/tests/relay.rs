#![cfg(target_os = "linux")]
//! TCP and UDP relaying, flow control, close reasons and egress policy, against a live server.

mod common;

use common::*;
use holywisp::SpliceMode;
use holywisp_proto::wisp::{self, close, ptype, stream_type};

#[test]
fn tcp_echo_roundtrip() {
    let echo = echo_server();
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    c.send_packet(ptype::DATA, 1, b"hello wisp");
    assert_eq!(c.read_data(1, 10), b"hello wisp");
    c.send_packet(ptype::CLOSE, 1, &[close::VOLUNTARY]);
    h.stop_and_join();
}

#[test]
fn data_sent_right_after_connect_is_not_lost() {
    let echo = echo_server();
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    // CONNECT and DATA back to back, before the remote connection is necessarily up.
    c.tcp(5, echo);
    c.send_packet(ptype::DATA, 5, b"first");
    c.send_packet(ptype::DATA, 5, b"second");
    assert_eq!(c.read_data(5, 11), b"firstsecond");
    h.stop_and_join();
}

fn big_roundtrip(mode: SpliceMode, streams: u32, bytes_each: usize) {
    let echo = echo_server();
    let h = start_with(test_config(), mode);
    let mut c = Client::v1(h.port());
    let payloads: Vec<Vec<u8>> = (0..streams)
        .map(|i| random_bytes(0x1234 + u64::from(i), bytes_each))
        .collect();
    for i in 0..streams {
        c.tcp(i + 1, echo);
    }
    // Send everything in 60 KiB DATA packets, round robin, reading as we go so the echo's
    // output never backs up against our own writes.
    let mut sent = vec![0usize; streams as usize];
    let mut received: Vec<Vec<u8>> = vec![Vec::new(); streams as usize];
    let total = bytes_each * streams as usize;
    let mut got = 0usize;
    while got < total {
        for i in 0..streams as usize {
            if sent[i] < bytes_each {
                let n = (60 * 1024).min(bytes_each - sent[i]);
                c.send_packet(
                    ptype::DATA,
                    i as u32 + 1,
                    &payloads[i][sent[i]..sent[i] + n],
                );
                sent[i] += n;
            }
        }
        // Drain whatever is ready without deadlocking when nothing is.
        let drain_until = got + 1;
        while got < drain_until && got < total {
            let p = c.recv_non_continue();
            assert_eq!(p.ptype, ptype::DATA);
            got += p.payload.len();
            received[p.sid as usize - 1].extend_from_slice(&p.payload);
        }
    }
    for i in 0..streams as usize {
        assert_eq!(received[i].len(), payloads[i].len(), "stream {i} length");
        assert_eq!(
            checksum(&received[i]),
            checksum(&payloads[i]),
            "stream {i} checksum"
        );
    }
    h.stop_and_join();
}

#[test]
fn random_data_roundtrips_byte_for_byte_with_splice_off() {
    big_roundtrip(SpliceMode::Off, 1, 8 * 1024 * 1024);
}

#[test]
fn random_data_roundtrips_byte_for_byte_with_splice_always() {
    big_roundtrip(SpliceMode::Always, 1, 8 * 1024 * 1024);
}

#[test]
fn random_data_roundtrips_byte_for_byte_adaptive_ten_streams() {
    big_roundtrip(SpliceMode::Auto, 10, 2 * 1024 * 1024);
}

fn firehose(mode: SpliceMode) {
    const TOTAL: usize = 24 * 1024 * 1024;
    let port = firehose_server(TOTAL);
    let h = start_with(test_config(), mode);
    let mut c = Client::v1(h.port());
    c.tcp(1, port);
    let mut next = 0usize;
    while next < TOTAL {
        let p = c.recv_non_continue();
        assert_eq!((p.ptype, p.sid), (ptype::DATA, 1));
        for (i, b) in p.payload.iter().enumerate() {
            assert_eq!(*b, pattern(next + i), "byte {} differs", next + i);
        }
        next += p.payload.len();
    }
    c.expect_close(1, close::VOLUNTARY);
    h.stop_and_join();
}

#[test]
fn server_to_client_stream_is_intact_through_the_copy_path() {
    firehose(SpliceMode::Off);
}

#[test]
fn server_to_client_stream_is_intact_through_splice() {
    firehose(SpliceMode::Always);
}

#[test]
fn server_to_client_stream_is_intact_adaptive() {
    firehose(SpliceMode::Auto);
}

#[test]
fn a_slow_client_does_not_corrupt_spliced_data() {
    // Read slowly so the server's socket fills and the splice path has to fall back to its queue.
    const TOTAL: usize = 16 * 1024 * 1024;
    let port = firehose_server(TOTAL);
    let h = start_with(test_config(), SpliceMode::Always);
    let mut c = Client::v1(h.port());
    c.tcp(1, port);
    let mut next = 0usize;
    let mut n = 0;
    while next < TOTAL {
        let p = c.recv_non_continue();
        assert_eq!(p.ptype, ptype::DATA);
        for (i, b) in p.payload.iter().enumerate() {
            assert_eq!(*b, pattern(next + i), "byte {} differs", next + i);
        }
        next += p.payload.len();
        n += 1;
        if n % 8 == 0 {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    h.stop_and_join();
}

#[test]
fn remote_close_sends_voluntary_after_the_data() {
    let port = greeter_server(b"bye".to_vec());
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.tcp(2, port);
    assert_eq!(c.read_data(2, 3), b"bye");
    c.expect_close(2, close::VOLUNTARY);
    h.stop_and_join();
}

#[test]
fn refused_connection_reports_0x44() {
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.tcp(1, closed_port());
    c.expect_close(1, close::REFUSED);
    h.stop_and_join();
}

#[test]
fn loopback_is_blocked_by_default() {
    let echo = echo_server();
    let mut cfg = test_config();
    cfg.allow_loopback = false;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    c.expect_close(1, close::BLOCKED);
    h.stop_and_join();
}

#[test]
fn direct_ip_targets_are_blocked_unless_allowed() {
    let echo = echo_server();
    let mut cfg = test_config();
    cfg.allow_direct_ip = false;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    c.expect_close(1, close::BLOCKED);
    h.stop_and_join();
}

#[test]
fn private_ranges_and_wrapped_addresses_are_blocked() {
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    for (sid, host) in [
        (1, "10.0.0.5"),
        (2, "192.168.1.1"),
        (3, "169.254.169.254"),
        (4, "[::ffff:10.0.0.1]"),
        (5, "[64:ff9b::a00:1]"),
        (6, "224.0.0.1"),
        (7, "0.0.0.0"),
    ] {
        c.connect_stream(sid, stream_type::TCP, host, 80);
        c.expect_close(sid, close::BLOCKED);
    }
    h.stop_and_join();
}

#[test]
fn hostnames_resolve_and_are_checked_after_resolution() {
    let echo = echo_server();
    // localhost resolves to loopback, which is blocked by default.
    let mut cfg = test_config();
    cfg.allow_loopback = false;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.connect_stream(1, stream_type::TCP, "localhost", echo);
    c.expect_close(1, close::BLOCKED);
    h.stop_and_join();

    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.connect_stream(1, stream_type::TCP, "localhost", echo);
    c.send_packet(ptype::DATA, 1, b"via a name");
    assert_eq!(c.read_data(1, 10), b"via a name");
    h.stop_and_join();
}

#[test]
fn unresolvable_names_report_unreachable() {
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.connect_stream(1, stream_type::TCP, "no-such-host.invalid", 80);
    c.expect_close(1, close::UNREACHABLE);
    h.stop_and_join();
}

#[test]
fn host_and_port_filters_block_with_0x48() {
    let echo = echo_server();
    let mut cfg = test_config();
    cfg.block_ports.add_spec(&echo.to_string()).unwrap();
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    c.expect_close(1, close::BLOCKED);
    h.stop_and_join();

    let mut cfg = test_config();
    cfg.allow_hosts.add("only.example").unwrap();
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    c.expect_close(1, close::BLOCKED);
    h.stop_and_join();
}

#[test]
fn tcp_and_udp_can_each_be_switched_off() {
    let echo = echo_server();
    let mut cfg = test_config();
    cfg.allow_tcp = false;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    c.expect_close(1, close::BLOCKED);
    h.stop_and_join();

    let mut cfg = test_config();
    cfg.allow_udp = false;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.connect_stream(1, stream_type::UDP, "127.0.0.1", 9);
    c.expect_close(1, close::BLOCKED);
    h.stop_and_join();
}

#[test]
fn malformed_connects_report_0x41() {
    let echo = echo_server();
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.connect_stream(1, stream_type::TCP, "127.0.0.1", 0);
    c.expect_close(1, close::INVALID_INFO);
    c.connect_stream(2, stream_type::TCP, "", echo);
    c.expect_close(2, close::INVALID_INFO);
    c.connect_stream(3, stream_type::TCP, "1.2.3", echo);
    c.expect_close(3, close::INVALID_INFO);
    c.connect_stream(4, 0x77, "127.0.0.1", echo);
    c.expect_close(4, close::INVALID_INFO);
    let long = "a".repeat(300);
    c.connect_stream(5, stream_type::TCP, &long, echo);
    c.expect_close(5, close::INVALID_INFO);
    c.send_packet(ptype::CONNECT, 6, &[1, 80]); // too short to hold a hostname
    c.expect_close(6, close::INVALID_INFO);
    h.stop_and_join();
}

#[test]
fn duplicate_stream_id_is_refused_and_the_first_keeps_working() {
    let echo = echo_server();
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    c.tcp(1, echo);
    c.expect_close(1, close::INVALID_INFO);
    c.send_packet(ptype::DATA, 1, b"still here");
    assert_eq!(c.read_data(1, 10), b"still here");
    h.stop_and_join();
}

#[test]
fn connect_on_stream_zero_gets_no_reply() {
    let echo = echo_server();
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.tcp(0, echo);
    c.tcp(1, echo);
    c.send_packet(ptype::DATA, 1, b"ok");
    assert_eq!(c.read_data(1, 2), b"ok");
    h.stop_and_join();
}

#[test]
fn stream_cap_throttles_with_0x49() {
    let echo = echo_server();
    let mut cfg = test_config();
    cfg.max_streams_per_conn = 2;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    c.tcp(2, echo);
    c.tcp(3, echo);
    c.expect_close(3, close::THROTTLED);
    h.stop_and_join();
}

#[test]
fn data_for_an_unknown_stream_is_ignored() {
    let echo = echo_server();
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.send_packet(ptype::DATA, 99, b"nobody home");
    c.tcp(1, echo);
    c.send_packet(ptype::DATA, 1, b"x");
    assert_eq!(c.read_data(1, 1), b"x");
    h.stop_and_join();
}

#[test]
fn client_close_tears_the_remote_down() {
    let echo = echo_server();
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    c.send_packet(ptype::DATA, 1, b"x");
    assert_eq!(c.read_data(1, 1), b"x");
    c.send_packet(ptype::CLOSE, 1, &[close::VOLUNTARY]);
    // The stream id can be reused afterwards.
    c.tcp(1, echo);
    c.send_packet(ptype::DATA, 1, b"y");
    assert_eq!(c.read_data(1, 1), b"y");
    h.stop_and_join();
}

#[test]
fn continue_is_sent_once_per_window_of_packets() {
    let echo = echo_server();
    let mut cfg = test_config();
    cfg.max_message_size = 65_541;
    cfg.buffer_remaining = 4;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    let mut continues = 0;
    // Wait until the stream is open so no packet is queued behind the connect.
    c.send_packet(ptype::DATA, 1, b"z");
    assert_eq!(c.read_data(1, 1), b"z");
    for _ in 0..12 {
        c.send_packet(ptype::DATA, 1, b"z");
    }
    let mut data = 0;
    while data < 12 || continues < 3 {
        let p = c.recv_packet();
        match p.ptype {
            ptype::CONTINUE => {
                assert_eq!(p.sid, 1);
                assert_eq!(u32::from_le_bytes(p.payload[..4].try_into().unwrap()), 4);
                continues += 1;
            }
            ptype::DATA => data += p.payload.len(),
            t => panic!("unexpected packet {t}"),
        }
    }
    assert_eq!(continues, 3, "12 packets with a window of 4");
    h.stop_and_join();
}

#[test]
fn stream_confirm_extension_gets_a_continue_when_the_stream_opens() {
    let echo = echo_server();
    let h = start(test_config());
    let mut c = Client::connect(h.port(), "p");
    let _info = c.recv_packet();
    // Client INFO with the stream-confirm extension (id 0x05, empty).
    let body = [
        wisp::MAJOR,
        wisp::MINOR,
        wisp::ext::STREAM_CONFIRM,
        0,
        0,
        0,
        0,
    ];
    c.send_packet(ptype::INFO, 0, &body);
    let p = c.recv_packet();
    assert_eq!((p.ptype, p.sid), (ptype::CONTINUE, 0));
    c.tcp(1, echo);
    let p = c.recv_packet();
    assert_eq!((p.ptype, p.sid), (ptype::CONTINUE, 1), "confirmation");
    h.stop_and_join();
}

#[test]
fn a_remote_that_never_reads_gets_throttled_with_0x49() {
    let sink = sink_server();
    let mut cfg = test_config();
    cfg.stream_queue_max = 256 * 1024;
    cfg.max_message_size = 65_541;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.tcp(1, sink);
    let chunk = vec![0xAB; 60_000];
    // The kernel buffers a few MiB before the server's queue starts to grow; keep sending until
    // the server gives up on the stream.
    let mut reason = None;
    'outer: for _ in 0..4000 {
        c.send_packet(ptype::DATA, 1, &chunk);
        for p in c.poll_packets() {
            if p.ptype == ptype::CLOSE {
                reason = Some((p.sid, p.payload));
                break 'outer;
            }
        }
    }
    assert_eq!(reason, Some((1, vec![close::THROTTLED])));
    h.stop_and_join();
}

#[test]
fn udp_datagrams_keep_their_boundaries() {
    let udp = udp_echo_server();
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.connect_stream(1, stream_type::UDP, "127.0.0.1", udp);
    for msg in [&b"one"[..], b"second datagram", b"3"] {
        c.send_packet(ptype::DATA, 1, msg);
        assert_eq!(c.read_data(1, msg.len()), msg);
    }
    // A zero-length datagram is still a datagram.
    c.send_packet(ptype::DATA, 1, b"");
    let p = c.recv_non_continue();
    assert_eq!((p.ptype, p.sid, p.payload.len()), (ptype::DATA, 1, 0));
    h.stop_and_join();
}

#[test]
fn many_connections_at_once_all_work() {
    let echo = echo_server();
    let h = start(test_config());
    let port = h.port();
    let threads: Vec<_> = (0..24)
        .map(|i| {
            std::thread::spawn(move || {
                let mut c = Client::v1(port);
                c.tcp(1, echo);
                let data = random_bytes(i, 100_000);
                c.send_packet(ptype::DATA, 1, &data);
                assert_eq!(checksum(&c.read_data(1, data.len())), checksum(&data));
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    h.stop_and_join();
}

#[test]
fn stats_count_traffic() {
    let echo = echo_server();
    let h = start(test_config());
    let mut c = Client::v1(h.port());
    c.tcp(1, echo);
    c.send_packet(ptype::DATA, 1, &[7u8; 1000]);
    c.read_data(1, 1000);
    let mut s = std::net::TcpStream::connect(("127.0.0.1", h.port())).unwrap();
    use std::io::{Read, Write};
    s.write_all(b"GET /stats HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    s.read_to_string(&mut out).unwrap();
    assert!(
        out.contains("\"bytes\":{\"in\":1000,\"out\":1000}"),
        "{out}"
    );
    assert!(
        out.contains("\"streams\":{\"total\":1,\"active\":1}"),
        "{out}"
    );
    h.stop_and_join();
}

#[test]
fn numeric_looking_hostnames_cannot_sneak_past_the_direct_ip_switch() {
    let echo = echo_server();
    let cfg = holywisp_config::Config {
        allow_direct_ip: false,
        ..test_config()
    };
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    for (sid, host) in [
        (1, "0x7f.0.0.1"),
        (2, "127.1"),
        (3, "2130706433"),
        (4, "0177.0.0.1"),
    ] {
        c.connect_stream(sid, stream_type::TCP, host, echo);
        c.expect_close(sid, close::INVALID_INFO);
    }
    h.stop_and_join();
}

#[test]
fn spliced_frames_never_exceed_max_message_size() {
    const TOTAL: usize = 8 * 1024 * 1024;
    let port = firehose_server(TOTAL);
    let cfg = holywisp_config::Config {
        max_message_size: 20_005,
        ..test_config()
    };
    let h = start_with(cfg, SpliceMode::Always);
    let mut c = Client::v1(h.port());
    c.tcp(1, port);
    let mut next = 0usize;
    while next < TOTAL {
        let p = c.recv_non_continue();
        assert_eq!(p.ptype, ptype::DATA);
        assert!(
            p.payload.len() <= 20_000,
            "frame of {} bytes",
            p.payload.len()
        );
        for (i, b) in p.payload.iter().enumerate() {
            assert_eq!(*b, pattern(next + i));
        }
        next += p.payload.len();
    }
    h.stop_and_join();
}
