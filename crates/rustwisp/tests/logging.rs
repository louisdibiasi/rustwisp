#![cfg(target_os = "linux")]
mod common;

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn configured_levels_filter_real_connection_logs() {
    for level in ["error", "warn", "info", "debug", "none"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut child = Command::new(env!("CARGO_BIN_EXE_rustwisp"))
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--workers",
                "1",
                "--log-level",
                level,
                "--password-user",
                "private-user:private-password",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "server did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut client = common::Client::v1(port);
        client.connect_stream(1, 1, "127.0.0.1", 80);
        let _ = client.recv_packet();
        drop(client);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    let mut c =
                        common::Client::connect_with(port, "", "X-Private: private-header\r\n");
                    let _ = c.recv_packet();
                });
            }
        });
        child.kill().unwrap();
        child.wait().unwrap();
        let mut logs = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut logs)
            .unwrap();
        assert_eq!(
            logs.contains("[info]"),
            matches!(level, "info" | "debug"),
            "{level}: {logs}"
        );
        assert_eq!(
            logs.contains("[debug] conn:"),
            level == "debug",
            "{level}: {logs}"
        );
        for secret in ["private-user", "private-password", "private-header"] {
            assert!(!logs.contains(secret), "{logs}");
        }
        if level == "none" {
            assert!(logs.is_empty(), "{logs}");
        }
        for line in logs.lines() {
            assert!(line.contains("Z ["), "{line}");
        }
    }
}

#[test]
fn failed_dials_are_logged_only_when_requested() {
    for enabled in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = closed.local_addr().unwrap().port();
        drop(closed);
        let mut child = Command::new(env!("CARGO_BIN_EXE_rustwisp"))
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--workers",
                "1",
                "--log-level",
                "info",
                "--allow-loopback",
                "on",
                "--allow-direct-ip",
                "on",
                "--log-blocked-dials",
                if enabled { "on" } else { "off" },
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut client = common::Client::v1(port);
        client.tcp(1, target);
        assert_eq!(
            client.recv_packet().ptype,
            rustwisp_proto::wisp::ptype::CLOSE
        );
        drop(client);
        child.kill().unwrap();
        child.wait().unwrap();
        let mut logs = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut logs)
            .unwrap();
        assert_eq!(logs.contains("[info] flood:"), enabled, "{logs}");
    }
}
