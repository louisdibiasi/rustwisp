#![cfg(target_os = "linux")]
mod common;
use common::*;
use rustwisp_config::User;
use rustwisp_proto::wisp::{self, close, ext, ptype, stream_type};

fn config() -> rustwisp_config::Config {
    let mut cfg = test_config();
    cfg.enable_twisp = true;
    cfg.users = vec![User {
        name: "terminal".into(),
        secret: "test-secret".into(),
    }];
    cfg
}
fn login(port: u16, authenticate: bool) -> Client {
    let mut c = Client::connect(port, "p");
    let _ = c.recv_packet();
    let mut body = vec![wisp::MAJOR, wisp::MINOR];
    if authenticate {
        let mut password = vec![8, 11, 0];
        password.extend_from_slice(b"terminaltest-secret");
        body.push(ext::PASSWORD);
        body.extend_from_slice(&(password.len() as u32).to_le_bytes());
        body.extend_from_slice(&password);
    }
    c.send_packet(ptype::INFO, 0, &body);
    let _ = c.recv_packet();
    c
}
#[test]
fn terminal_gates_refuse_access() {
    let _serial = SERIAL.lock().unwrap();
    for (enabled, v2, auth) in [
        (false, true, true),
        (true, false, false),
        (true, true, false),
    ] {
        let mut cfg = config();
        cfg.enable_twisp = enabled;
        cfg.reputation_enabled = true;
        let store = std::env::temp_dir().join(format!(
            "rustwisp-term-{}-{enabled}-{v2}-{auth}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&store);
        cfg.reputation.store_path = store.to_string_lossy().into_owned();
        let h = start(cfg);
        let mut c = if v2 {
            login(h.port(), auth)
        } else {
            Client::v1(h.port())
        };
        c.connect_stream(1, stream_type::TERM, "cat", 0);
        let p = c.recv_packet();
        assert_eq!((p.ptype, p.payload), (ptype::CLOSE, vec![close::BLOCKED]));
        h.stop_and_join();
        let saved = std::fs::read_to_string(&store).unwrap();
        assert!(saved.contains("\"twispNoAuth\":1"), "{saved}");
        std::fs::remove_file(store).unwrap();
    }
}
#[cfg(not(feature = "twisp"))]
#[test]
fn default_build_refuses_authenticated_terminals() {
    let _serial = SERIAL.lock().unwrap();
    let h = start(config());
    let mut c = login(h.port(), true);
    c.connect_stream(1, stream_type::TERM, "cat", 0);
    assert_eq!(c.recv_packet().payload, [close::BLOCKED]);
    h.stop_and_join();
}
#[cfg(feature = "twisp")]
fn data(c: &mut Client) -> Vec<u8> {
    let p = c.recv_packet();
    assert_eq!(p.ptype, ptype::DATA, "{:?}", p.payload);
    p.payload
}
#[cfg(feature = "twisp")]
#[test]
fn authenticated_terminal_runs_command() {
    let _serial = SERIAL.lock().unwrap();
    let h = start(config());
    let mut c = login(h.port(), true);
    c.connect_stream(
        1,
        stream_type::TERM,
        &format!("sh -c 'printf terminal-ok; : {}'", "x".repeat(300)),
        0,
    );
    assert!(String::from_utf8_lossy(&output(&mut c, 1)).contains("terminal-ok"));
    h.stop_and_join();
}

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(feature = "twisp")]
#[test]
fn terminal_children_only_start_with_standard_descriptors() {
    let _serial = SERIAL.lock().unwrap();
    let h = start(config());
    let mut c = login(h.port(), true);
    c.connect_stream(1, stream_type::TERM,
        "sh -c 'for f in /proc/self/fd/*; do if test -e \"$f\"; then printf \"%s\\n\" \"$f\"; fi; done'", 0);
    let descriptors = String::from_utf8(output(&mut c, 1)).unwrap();
    let mut descriptors: Vec<_> = descriptors.lines().map(str::trim).collect();
    descriptors.sort_unstable();
    assert_eq!(
        descriptors,
        ["/proc/self/fd/0", "/proc/self/fd/1", "/proc/self/fd/2"]
    );
    h.stop_and_join();
}

#[cfg(feature = "twisp")]
#[test]
fn early_terminal_requests_are_not_replayed_after_login() {
    use std::io::Write;
    let _serial = SERIAL.lock().unwrap();
    let mut cfg = config();
    cfg.users[0].secret = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW".into();
    let h = start(cfg);
    for valid in [true, false] {
        let mut c = Client::connect(h.port(), "p");
        assert_eq!(c.recv_packet().ptype, ptype::INFO);
        c.connect_stream(1, stream_type::TERM, "printf early", 0);
        let password = if valid { "U*U" } else { "bad" };
        let mut meta = vec![8, 3, 0];
        meta.extend_from_slice(b"terminal");
        meta.extend_from_slice(password.as_bytes());
        let mut info = vec![wisp::MAJOR, wisp::MINOR, ext::PASSWORD];
        info.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        info.extend_from_slice(&meta);
        let mut packet = wisp::build_info(wisp::MAJOR, wisp::MINOR).to_vec();
        packet.truncate(5);
        packet.extend_from_slice(&info);
        let mut wire = c.frame_bytes(rustwisp_proto::ws::opcode::BINARY, true, &packet);
        let mut connect = [0; 128];
        let n =
            wisp::build_connect(&mut connect, 2, stream_type::TERM, 0, b"printf pending").unwrap();
        wire.extend(c.frame_bytes(rustwisp_proto::ws::opcode::BINARY, true, &connect[..n]));
        c.sock.write_all(&wire).unwrap();
        let result = c.recv_packet();
        if valid {
            assert_eq!((result.ptype, result.sid), (ptype::CONTINUE, 0));
            c.connect_stream(3, stream_type::TERM, "printf allowed", 0);
            assert_eq!(output(&mut c, 3), b"allowed");
        } else {
            assert_eq!(
                (result.ptype, result.sid, result.payload),
                (ptype::CLOSE, 0, vec![close::AUTH_BAD_PASSWORD])
            );
            c.expect_eof();
        }
    }
    h.stop_and_join();
}

#[cfg(feature = "twisp")]
#[test]
fn command_boundaries_and_resize_payloads_remain_bounded() {
    let _serial = SERIAL.lock().unwrap();
    let mut cfg = config();
    cfg.max_streams_per_conn = 1;
    let h = start(cfg);
    let mut c = login(h.port(), true);
    for (sid, len) in [(1, 4095), (2, 4096)] {
        let mut command = "printf ok".to_string();
        command.push_str(&" ".repeat(len - command.len()));
        c.connect_stream(sid, stream_type::TERM, &command, 0);
        assert_eq!(output(&mut c, sid), b"ok");
    }
    for (sid, command) in [
        (3, "x".repeat(4097)),
        (4, "printf a\0b".into()),
        (5, "cat '".into()),
        (6, "x ".repeat(65)),
    ] {
        c.connect_stream(sid, stream_type::TERM, &command, 0);
        c.expect_close(sid, close::INVALID_INFO);
    }
    c.send_packet(ptype::CONNECT, 7, &[stream_type::TERM, 0, 0, 0xff]);
    c.expect_close(7, close::INVALID_INFO);
    c.connect_stream(8, stream_type::TERM, "sh -c 'read x; stty size'", 0);
    for payload in [
        &[][..],
        &[0],
        &[0, 0, 0],
        &[0, 0, 0, 0],
        &[255, 255, 255, 255],
        &[37, 0, 91, 0, 0],
    ] {
        c.send_packet(wisp::TWISP_RESIZE, 8, payload);
    }
    c.connect_stream(9, stream_type::TERM, "printf over-cap", 0);
    c.expect_close(9, close::THROTTLED);
    c.send_packet(ptype::DATA, 8, b"go\n");
    assert!(String::from_utf8_lossy(&output(&mut c, 8)).contains("37 91"));
    h.stop_and_join();
}

#[cfg(feature = "twisp")]
#[test]
fn stubborn_and_detached_terminal_descriptors_are_cleaned_up() {
    let _serial = SERIAL.lock().unwrap();
    let h = start(config());
    let mut c = login(h.port(), true);
    c.connect_stream(
        1,
        stream_type::TERM,
        "sh -c 'trap \"\" HUP; echo $$; exec sleep 5'",
        0,
    );
    let child = pid(&mut c);
    c.send_packet(ptype::CLOSE, 1, &[close::VOLUNTARY]);
    wait_reaped(&[child]);
    c.connect_stream(
        2,
        stream_type::TERM,
        "sh -c 'echo $$; exec 0<&- 1>&- 2>&-; exec sleep 5'",
        0,
    );
    let child = pid(&mut c);
    c.expect_close(2, close::VOLUNTARY);
    wait_reaped(&[child]);
    h.stop_and_join();
}

#[cfg(feature = "twisp")]
fn output(c: &mut Client, sid: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let p = c.recv_packet();
        assert_eq!(p.sid, sid);
        if p.ptype == ptype::CLOSE {
            assert_eq!(p.payload, [close::VOLUNTARY]);
            return bytes;
        }
        if p.ptype == ptype::DATA {
            bytes.extend(p.payload);
        }
    }
}
#[cfg(feature = "twisp")]
fn pid(c: &mut Client) -> u32 {
    let mut bytes = Vec::new();
    while !bytes.contains(&b'\n') {
        bytes.extend(data(c));
    }
    String::from_utf8(bytes).unwrap().trim().parse().unwrap()
}
#[cfg(feature = "twisp")]
fn wait_reaped(pids: &[u32]) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while pids
        .iter()
        .any(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
    {
        assert!(
            std::time::Instant::now() < deadline,
            "children remain: {pids:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
#[cfg(feature = "twisp")]
#[test]
fn resize_bidirectional_relay_and_invalid_commands() {
    let _serial = SERIAL.lock().unwrap();
    let h = start(config());
    let mut c = login(h.port(), true);
    c.connect_stream(1, stream_type::TERM, "sh -c 'read x; stty size'", 0);
    c.send_packet(wisp::TWISP_RESIZE, 1, &[37, 0, 91, 0]);
    c.send_packet(wisp::TWISP_RESIZE, 1, &[1]);
    c.send_packet(wisp::TWISP_RESIZE, 99, &[1, 0, 1, 0]);
    c.send_packet(ptype::DATA, 1, b"go\n");
    assert!(String::from_utf8_lossy(&output(&mut c, 1)).contains("37 91"));
    c.connect_stream(
        2,
        stream_type::TERM,
        "sh -c 'stty -echo; printf ready; cat'",
        0,
    );
    assert_eq!(data(&mut c), b"ready");
    c.send_packet(ptype::DATA, 2, b"payload\n");
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\n") {
        bytes.extend(data(&mut c));
    }
    assert_eq!(bytes, b"payload\r\n");
    c.send_packet(ptype::CLOSE, 2, &[close::VOLUNTARY]);
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    c.tcp(10, echo.local_addr().unwrap().port());
    let (mut remote, _) = echo.accept().unwrap();
    remote.set_read_timeout(Some(TIMEOUT)).unwrap();
    c.send_packet(wisp::TWISP_RESIZE, 10, &[1, 0, 1, 0]);
    c.send_packet(ptype::DATA, 10, b"tcp");
    let mut bytes = [0; 3];
    std::io::Read::read_exact(&mut remote, &mut bytes).unwrap();
    assert_eq!(&bytes, b"tcp");
    c.send_packet(ptype::CLOSE, 10, &[close::VOLUNTARY]);
    for (sid, command) in [(3, "cat '"), (4, "missing-terminal-command-7812")] {
        c.connect_stream(sid, stream_type::TERM, command, 0);
        let p = c.recv_packet();
        assert_eq!(p.ptype, ptype::CLOSE);
        assert_eq!(
            p.payload,
            [if sid == 3 {
                close::INVALID_INFO
            } else {
                close::NETWORK_ERROR
            }]
        );
    }
    h.stop_and_join();
}
#[cfg(feature = "twisp")]
#[test]
fn closing_reaps_children_and_cycles_do_not_leak() {
    let _serial = SERIAL.lock().unwrap();
    let h = start(config());
    let mut c = login(h.port(), true);
    let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let before = descriptors();
    for batch in 0..10 {
        let mut children = Vec::new();
        for offset in 0..10 {
            let sid = 1 + batch * 10 + offset;
            c.connect_stream(sid, stream_type::TERM, "sh -c 'echo $$; exec sleep 100'", 0);
            children.push(pid(&mut c));
            c.send_packet(ptype::CLOSE, sid, &[close::VOLUNTARY]);
        }
        wait_reaped(&children);
    }
    assert_eq!(descriptors(), before);
    c.connect_stream(101, stream_type::TERM, "sh -c 'echo $$; exec sleep 100'", 0);
    let child = pid(&mut c);
    drop(c);
    wait_reaped(&[child]);
    let mut c = login(h.port(), true);
    c.connect_stream(1, stream_type::TERM, "sh -c 'echo $$; exec sleep 100'", 0);
    let child = pid(&mut c);
    h.stop_and_join();
    wait_reaped(&[child]);
}
#[cfg(feature = "twisp")]
#[test]
fn terminal_descriptor_inheritance_and_global_cap() {
    let _serial = SERIAL.lock().unwrap();
    let h = start(config());
    let mut c = login(h.port(), true);
    c.connect_stream(
        1,
        stream_type::TERM,
        "sh -c 'for f in /proc/self/fd/*; do readlink \"$f\"; done'",
        0,
    );
    let listing = String::from_utf8(output(&mut c, 1)).unwrap();
    assert!(
        !listing.contains("socket:")
            && !listing.contains("anon_inode:")
            && !listing.contains("pipe:"),
        "{listing}"
    );
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let mut children = Vec::new();
    for sid in 2..34 {
        c.connect_stream(sid, stream_type::TERM, "sh -c 'echo $$; exec sleep 100'", 0);
        children.push(pid(&mut c));
    }
    c.connect_stream(34, stream_type::TERM, "cat", 0);
    assert_eq!(c.recv_packet().payload, [close::THROTTLED]);
    drop(c);
    wait_reaped(&children);
    h.stop_and_join();
}

#[cfg(feature = "twisp")]
#[test]
fn terminal_flow_control_and_queue_limit() {
    let _serial = SERIAL.lock().unwrap();
    let mut cfg = config();
    cfg.buffer_remaining = 2;
    cfg.max_message_size = 4096;
    cfg.stream_queue_max = 16384;
    let h = start(cfg);
    let mut c = login(h.port(), true);
    c.connect_stream(
        1,
        stream_type::TERM,
        "sh -c 'stty -echo -icanon; printf ready; cat'",
        0,
    );
    assert_eq!(data(&mut c), b"ready");
    c.send_packet(ptype::DATA, 1, b"abcd");
    c.send_packet(ptype::DATA, 1, b"efgh");
    let mut credit = false;
    let mut bytes = Vec::new();
    while !credit || bytes.len() < 8 {
        let p = c.recv_packet();
        match p.ptype {
            ptype::CONTINUE => {
                assert_eq!(p.payload, 2u32.to_le_bytes());
                credit = true;
            }
            ptype::DATA => bytes.extend(p.payload),
            _ => panic!("unexpected terminal packet {}", p.ptype),
        }
    }
    assert_eq!(bytes, b"abcdefgh");
    c.send_packet(ptype::CLOSE, 1, &[close::VOLUNTARY]);
    c.connect_stream(
        2,
        stream_type::TERM,
        "sh -c 'stty -echo -icanon; printf ready; exec sleep 100'",
        0,
    );
    assert_eq!(data(&mut c), b"ready");
    for _ in 0..16 {
        c.send_packet(ptype::DATA, 2, &[b'x'; 4000]);
    }
    loop {
        let p = c.recv_packet();
        if p.ptype == ptype::CLOSE {
            assert_eq!(p.payload, [close::THROTTLED]);
            break;
        }
    }
    h.stop_and_join();
}
