#![cfg(target_os = "linux")]

mod common;

use common::*;
use rustwisp_proto::wisp::ptype;
use std::io::Read;
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

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
