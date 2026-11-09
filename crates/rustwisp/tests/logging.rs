#![cfg(target_os = "linux")]
mod common;

use std::io::Read;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

/// The two tests start servers that listen with SO_REUSEPORT. A server started on port 0 can be
/// given a port another SO_REUSEPORT listener already holds, and then the kernel spreads new
/// connections over both servers, so one test's client lands on the other test's server. Running
/// the tests one at a time means there is only ever one server.
static ONE_SERVER_AT_A_TIME: Mutex<()> = Mutex::new(());

/// A TCP port nothing listens on right now, used as a dial target that must be refused.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// The port `child` is listening on. The server is started on port 0 and the kernel picks the
/// port, so nothing else can take it between choosing it and binding it, which a guessed port
/// could (a connection to a port another test had just picked failed now and then). The socket
/// is found through /proc: its inode is among the child's descriptors and in its TCP table.
fn listening_port(child: &Child) -> u16 {
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let inodes: Vec<String> = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| std::fs::read_link(e.path()).ok())
            .filter_map(|l| {
                let l = l.to_string_lossy().into_owned();
                l.strip_prefix("socket:[")?
                    .strip_suffix(']')
                    .map(String::from)
            })
            .collect();
        for table in ["tcp", "tcp6"] {
            let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/net/{table}")) else {
                continue;
            };
            for row in text.lines().skip(1) {
                let cols: Vec<&str> = row.split_whitespace().collect();
                let listening = cols.get(3) == Some(&"0A");
                if listening && cols.get(9).is_some_and(|i| inodes.iter().any(|n| n == i)) {
                    let port = cols[1].rsplit(':').next().unwrap();
                    return u16::from_str_radix(port, 16).unwrap();
                }
            }
        }
        assert!(Instant::now() < deadline, "server did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn configured_levels_filter_real_connection_logs() {
    let _serial = ONE_SERVER_AT_A_TIME
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for level in ["error", "warn", "info", "debug", "none"] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rustwisp"))
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                "0",
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
        let port = listening_port(&child);
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
    let _serial = ONE_SERVER_AT_A_TIME
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for enabled in [false, true] {
        let target = closed_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_rustwisp"))
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                "0",
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
        let port = listening_port(&child);
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
