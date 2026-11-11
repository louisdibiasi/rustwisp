#![cfg(target_os = "linux")]

mod common;

use common::*;
use rustwisp_proto::wisp::ptype;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

#[test]
fn a_large_data_frame_reaches_the_remote_before_its_final_piece() {
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut cfg = test_config();
    cfg.buffer_remaining = 2;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.tcp(1, sink.local_addr().unwrap().port());
    let (mut remote, _) = sink.accept().unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut body = vec![0x5a; (1 << 20) + 5];
    let mut wh = [0; 5];
    rustwisp_proto::wisp::write_header(&mut wh, ptype::DATA, 1);
    body[..5].copy_from_slice(&wh);
    let mask = [1, 2, 3, 4];
    rustwisp_proto::simd::unmask(&mut body, mask, 0);
    let mut header = [0; rustwisp_proto::ws::MAX_HEADER];
    let len = rustwisp_proto::ws::write_header(
        &mut header,
        true,
        rustwisp_proto::ws::opcode::BINARY,
        body.len() as u64,
        Some(mask),
    );
    c.sock.write_all(&header[..len]).unwrap();
    c.sock.write_all(&body[..5 + 32_771]).unwrap();
    let mut first = vec![0; 32_771];
    remote
        .read_exact(&mut first)
        .expect("partial DATA was held until the frame completed");
    assert!(first.iter().all(|&b| b == 0x5a));
    assert!(
        c.poll_packets().is_empty(),
        "one partial packet exhausted a two-packet window"
    );
    c.sock.write_all(&body[5 + 32_771..]).unwrap();
    let mut rest = vec![0; (1 << 20) - 32_771];
    remote.read_exact(&mut rest).unwrap();
    assert!(rest.iter().all(|&b| b == 0x5a));
    c.send_packet(ptype::DATA, 1, b"tail");
    let mut tail = [0; 4];
    remote.read_exact(&mut tail).unwrap();
    assert_eq!(&tail, b"tail");
    let credit = c.recv_packet();
    assert_eq!((credit.ptype, credit.sid), (ptype::CONTINUE, 1));
    assert_eq!(
        u32::from_le_bytes(credit.payload[..4].try_into().unwrap()),
        2
    );
    assert!(c.poll_packets().is_empty());
    h.stop_and_join();
}

#[test]
fn concurrent_bulk_streams_keep_frame_and_payload_order_for_a_slow_client() {
    let echo = echo_server();
    let h = start_with(test_config(), rustwisp::SpliceMode::Always);
    let mut c = Client::v1(h.port());
    for sid in 1..=3 {
        c.tcp(sid, echo);
    }
    for _ in 0..16 {
        for sid in 1..=3 {
            c.send_packet(ptype::DATA, sid, &vec![sid as u8; 512 << 10]);
        }
    }
    std::thread::sleep(Duration::from_millis(300));
    let mut got = [0; 3];
    while got.iter().any(|&n| n < 8 << 20) {
        let p = c.recv_non_continue();
        assert_eq!(p.ptype, ptype::DATA);
        assert!((1..=3).contains(&p.sid));
        assert!(p.payload.iter().all(|&b| b == p.sid as u8));
        got[p.sid as usize - 1] += p.payload.len();
        assert!(got[p.sid as usize - 1] <= 8 << 20);
    }
    h.stop_and_join();
}

#[test]
fn connection_upload_budget_pauses_then_delivers_every_stream() {
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    rustix::net::sockopt::set_socket_recv_buffer_size(&sink, 65_536).unwrap();
    let port = sink.local_addr().unwrap().port();
    let mut cfg = test_config();
    cfg.stream_queue_max = 4 << 20;
    cfg.conn_queue_max = 4 << 20;
    cfg.max_message_size = 65_541;
    cfg.ws_write_high_water = 24 << 20;
    cfg.socket_buffer_size = 65_536;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    rustix::net::sockopt::set_socket_send_buffer_size(&c.sock, 65_536).unwrap();
    c.sock.set_write_timeout(Some(TIMEOUT)).unwrap();
    let mut sinks = Vec::new();
    for sid in 1..=3 {
        c.tcp(sid, port);
        let (s, _) = sink.accept().unwrap();
        s.set_read_timeout(Some(TIMEOUT)).unwrap();
        sinks.push(s);
    }
    let sent = Arc::new(AtomicUsize::new(0));
    let count = sent.clone();
    let sender = std::thread::spawn(move || {
        for _ in 0..64 {
            for sid in 1..=3 {
                c.send_packet(ptype::DATA, sid, &vec![sid as u8; 65_536]);
                count.fetch_add(1, Ordering::SeqCst);
            }
        }
        c
    });
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        sent.load(Ordering::SeqCst) < 192,
        "sender was not backpressured"
    );
    let drains: Vec<_> = sinks
        .into_iter()
        .enumerate()
        .map(|(i, mut s)| {
            std::thread::spawn(move || {
                let mut data = vec![0; 4 << 20];
                s.read_exact(&mut data).unwrap();
                assert!(data.iter().all(|&b| b == (i + 1) as u8));
                s
            })
        })
        .collect();
    let mut c = sender.join().unwrap();
    let _sinks: Vec<_> = drains
        .into_iter()
        .map(|drain| drain.join().unwrap())
        .collect();
    // A later packet proves buffered input and socket interest both recover.
    let echo = echo_server();
    c.tcp(4, echo);
    c.send_packet(ptype::DATA, 4, b"resumed");
    assert_eq!(c.read_data(4, 7), b"resumed");
    h.stop_and_join();
}
