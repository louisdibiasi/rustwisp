use super::*;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

/// A scripted server end: speaks just enough HTTP and WebSocket to drive the client.
struct Peer {
    sock: TcpStream,
    buf: Vec<u8>,
}

impl Peer {
    /// Accept one connection, answer the upgrade and echo the client's subprotocol.
    fn accept(listener: &TcpListener) -> (Peer, String) {
        let (mut sock, _) = listener.accept().unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            sock.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let text = String::from_utf8(head).unwrap();
        let header = |name: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(name))
                .map(|v| v.trim().to_string())
                .unwrap_or_default()
        };
        let protocol = header("Sec-WebSocket-Protocol:");
        let reply = http::upgrade_response(&header("Sec-WebSocket-Key:"), &protocol);
        sock.write_all(reply.as_bytes()).unwrap();
        (
            Peer {
                sock,
                buf: Vec::new(),
            },
            protocol,
        )
    }

    fn send_frame(&mut self, fin: bool, opcode: u8, payload: &[u8]) {
        let mut head = [0u8; ws::MAX_HEADER];
        let n = ws::write_header(&mut head, fin, opcode, payload.len() as u64, None);
        self.sock.write_all(&head[..n]).unwrap();
        self.sock.write_all(payload).unwrap();
    }

    fn send_packet(&mut self, ptype: u8, stream: u32, payload: &[u8]) {
        let mut head = [0u8; HEADER_LEN];
        wisp::write_header(&mut head, ptype, stream);
        let mut msg = head.to_vec();
        msg.extend_from_slice(payload);
        self.send_frame(true, ws::opcode::BINARY, &msg);
    }

    fn send_info(&mut self, exts: &[(u8, &[u8])]) {
        let mut msg = wisp::build_info(2, 0).to_vec();
        for (id, meta) in exts {
            push_extension(&mut msg, *id, meta);
        }
        self.send_frame(true, ws::opcode::BINARY, &msg);
    }

    /// Next client frame as (opcode, unmasked payload).
    fn read_frame(&mut self) -> (u8, Vec<u8>) {
        loop {
            match ws::parse_header(&self.buf) {
                Ok(h) => {
                    let total = h.header_len + h.payload_len as usize;
                    if self.buf.len() >= total {
                        assert!(h.masked, "client frames must be masked");
                        let mut payload = self.buf[h.header_len..total].to_vec();
                        simd::unmask(&mut payload, h.mask, 0);
                        self.buf.drain(..total);
                        return (h.opcode, payload);
                    }
                }
                Err(ProtoError::Again) => {}
                Err(e) => panic!("bad client frame: {e}"),
            }
            let mut chunk = [0u8; 4096];
            let n = self.sock.read(&mut chunk).unwrap();
            assert!(n > 0, "client hung up");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Next Wisp packet from the client as (type, stream, payload).
    fn read_packet(&mut self) -> (u8, u32, Vec<u8>) {
        loop {
            let (op, payload) = self.read_frame();
            if op != ws::opcode::BINARY {
                continue;
            }
            let p = wisp::parse(&payload).unwrap();
            return (p.ptype, p.stream_id, p.payload.to_vec());
        }
    }
}

fn listen() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://127.0.0.1:{}/", listener.local_addr().unwrap().port());
    (listener, url)
}

#[test]
fn v2_handshake_open_send_and_echo() {
    let (listener, url) = listen();
    let server = thread::spawn(move || {
        let (mut peer, protocol) = Peer::accept(&listener);
        assert_eq!(protocol, "wisp-v2");
        peer.send_info(&[(ext::MOTD, b"hello there"), (ext::UDP, b"")]);
        let (kind, stream, payload) = peer.read_packet();
        assert_eq!((kind, stream), (ptype::INFO, 0));
        let mut msg = vec![kind, 0, 0, 0, 0];
        msg.extend_from_slice(&payload);
        let info = wisp::parse_info(&wisp::parse(&msg).unwrap()).unwrap();
        assert!(info.has_udp);
        let (kind, stream, payload) = peer.read_packet();
        assert_eq!((kind, stream), (ptype::CONNECT, 1));
        assert_eq!(payload, [1, 0x50, 0x00, b'e', b'x', b'.', b'o', b'r', b'g']);
        let (kind, _, data) = peer.read_packet();
        assert_eq!((kind, data.as_slice()), (ptype::DATA, &b"ping"[..]));
        peer.send_packet(ptype::DATA, 1, b"pong");
        peer.send_packet(ptype::CLOSE, 1, &[wisp::close::VOLUNTARY]);
    });

    let (handle, mut reader) = connect(&url, &Options::default()).unwrap();
    assert!(handle.is_v2());
    let id = handle.open_tcp("ex.org", 80).unwrap();
    assert_eq!(id, 1);
    handle.send(id, b"ping").unwrap();
    assert_eq!(
        reader.next_event().unwrap(),
        Event::Data {
            stream: 1,
            data: b"pong".to_vec()
        }
    );
    assert_eq!(
        reader.next_event().unwrap(),
        Event::Close {
            stream: 1,
            reason: wisp::close::VOLUNTARY
        }
    );
    assert_eq!(handle.motd().as_deref(), Some("hello there"));
    assert_eq!(
        handle.send(id, b"late").unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    server.join().unwrap();
}

#[test]
fn sending_waits_for_credit() {
    let (listener, url) = listen();
    let server = thread::spawn(move || {
        let (mut peer, _) = Peer::accept(&listener);
        peer.send_info(&[]);
        peer.read_packet(); // client INFO
        peer.send_packet(ptype::CONTINUE, 0, &1u32.to_le_bytes());
        let (kind, stream, _) = peer.read_packet();
        assert_eq!((kind, stream), (ptype::CONNECT, 1));
        peer.read_packet(); // first DATA uses the only credit
        thread::sleep(Duration::from_millis(150));
        peer.send_packet(ptype::CONTINUE, 1, &1u32.to_le_bytes());
        let (kind, _, data) = peer.read_packet();
        assert_eq!((kind, data.as_slice()), (ptype::DATA, &b"two"[..]));
        peer.send_packet(ptype::CLOSE, 1, &[wisp::close::VOLUNTARY]);
    });

    let (handle, mut reader) = connect(&url, &Options::default()).unwrap();
    let (tx, rx) = mpsc::channel();
    let pump = thread::spawn(move || {
        while let Ok(event) = reader.next_event() {
            let _ = tx.send(event);
        }
    });
    // let the stream-0 CONTINUE land so the default credit is 1
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Event::Continue {
            stream: 0,
            remaining: 1
        }
    );
    let id = handle.open_tcp("h", 1).unwrap();
    let started = std::time::Instant::now();
    handle.send(id, b"one").unwrap();
    handle.send(id, b"two").unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(100),
        "the second send should have waited"
    );
    server.join().unwrap();
    pump.join().unwrap();
}

#[test]
fn control_frames_and_fragments() {
    let (listener, url) = listen();
    let server = thread::spawn(move || {
        let (mut peer, _) = Peer::accept(&listener);
        peer.send_info(&[]);
        peer.read_packet();
        peer.send_frame(true, ws::opcode::PING, b"are you there");
        let (op, payload) = peer.read_frame();
        assert_eq!(
            (op, payload.as_slice()),
            (ws::opcode::PONG, &b"are you there"[..])
        );
        let mut msg = vec![ptype::DATA, 9, 0, 0, 0];
        msg.extend_from_slice(b"split ");
        peer.send_frame(false, ws::opcode::BINARY, &msg);
        peer.send_frame(true, ws::opcode::CONTINUATION, b"message");
        peer.send_frame(true, ws::opcode::CLOSE, &[]);
    });

    let (_handle, mut reader) = connect(&url, &Options::default()).unwrap();
    assert_eq!(
        reader.next_event().unwrap(),
        Event::Data {
            stream: 9,
            data: b"split message".to_vec()
        }
    );
    let e = reader.next_event().unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::ConnectionAborted);
    server.join().unwrap();
}

#[test]
fn password_is_sent_in_the_spec_layout() {
    let (listener, url) = listen();
    let server = thread::spawn(move || {
        let (mut peer, _) = Peer::accept(&listener);
        peer.send_info(&[(ext::PASSWORD, &[1])]);
        let (_, _, payload) = peer.read_packet();
        let mut msg = vec![ptype::INFO, 0, 0, 0, 0];
        msg.extend_from_slice(&payload);
        let info = wisp::parse_info(&wisp::parse(&msg).unwrap()).unwrap();
        assert_eq!(info.user, Some(&b"alice"[..]));
        assert_eq!(info.pass, Some(&b"s3cret"[..]));
    });
    let opts = Options {
        username: Some("alice".into()),
        password: Some("s3cret".into()),
        ..Options::default()
    };
    connect(&url, &opts).unwrap();
    server.join().unwrap();
}

#[test]
fn a_required_password_without_credentials_is_refused_locally() {
    let (listener, url) = listen();
    let server = thread::spawn(move || {
        let (mut peer, _) = Peer::accept(&listener);
        peer.send_info(&[(ext::PASSWORD, &[1])]);
    });
    let e = connect(&url, &Options::default()).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    server.join().unwrap();
}

#[test]
fn v1_skips_the_info_exchange() {
    let (listener, url) = listen();
    let server = thread::spawn(move || {
        let (mut peer, protocol) = Peer::accept(&listener);
        assert_eq!(protocol, "");
        peer.send_packet(ptype::CONTINUE, 0, &64u32.to_le_bytes());
    });
    let opts = Options {
        v2: false,
        ..Options::default()
    };
    let (handle, mut reader) = connect(&url, &opts).unwrap();
    assert!(!handle.is_v2());
    assert_eq!(
        reader.next_event().unwrap(),
        Event::Continue {
            stream: 0,
            remaining: 64
        }
    );
    server.join().unwrap();
}

#[test]
fn a_bad_upgrade_is_an_error() {
    let (listener, url) = listen();
    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut chunk = [0u8; 1024];
        let _ = sock.read(&mut chunk);
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    let e = connect(&url, &Options::default()).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    server.join().unwrap();
}

#[test]
fn wss_is_rejected_up_front() {
    let e = connect("wss://example.com/", &Options::default()).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
}
