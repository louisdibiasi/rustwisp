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

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn an_unread_log_pipe_does_not_block_a_worker() {
    let _serial = ONE_SERVER_AT_A_TIME
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let server = Running(
        Command::new(env!("CARGO_BIN_EXE_rustwisp"))
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                "0",
                "--workers",
                "1",
                "--log-level",
                "info",
                "--flood-protection",
                "off",
                "--reputation",
                "off",
                "--connections-limit-per-ip",
                "0",
                "--connection-window-s",
                "0",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let port = listening_port(&server.0);
    let mut writer = common::Client::v1(port);
    let mut probe = common::Client::v1(port);
    probe
        .sock
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    for sid in 1..=2048 {
        writer.connect_stream(sid, 1, "127.0.0.1", 80);
    }
    probe.send_frame(rustwisp_proto::ws::opcode::PING, true, b"alive");
    assert_eq!(
        probe.recv_frame(),
        (rustwisp_proto::ws::opcode::PONG, b"alive".to_vec())
    );
}

#[test]
fn closing_the_log_reader_does_not_terminate_the_server() {
    let _serial = ONE_SERVER_AT_A_TIME
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut server = Running(
        Command::new(env!("CARGO_BIN_EXE_rustwisp"))
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                "0",
                "--workers",
                "1",
                "--log-level",
                "debug",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let port = listening_port(&server.0);
    drop(server.0.stderr.take());
    let mut probe = common::Client::v1(port);
    probe.connect_stream(1, 1, "127.0.0.1", 80);
    probe.expect_close(1, rustwisp_proto::wisp::close::BLOCKED);
}

#[test]
fn a_closed_standard_error_descriptor_does_not_stop_connections() {
    let _serial = ONE_SERVER_AT_A_TIME
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let server = Running(
        Command::new("sh")
            .args([
                "-c",
                "exec 2>&-; exec \"$@\"",
                "sh",
                env!("CARGO_BIN_EXE_rustwisp"),
                "--host",
                "127.0.0.1",
                "--port",
                "0",
                "--workers",
                "1",
                "--log-level",
                "debug",
            ])
            .spawn()
            .unwrap(),
    );
    let port = listening_port(&server.0);
    let mut client = common::Client::v1(port);
    client.connect_stream(1, 1, "127.0.0.1", 80);
    client.expect_close(1, rustwisp_proto::wisp::close::BLOCKED);
    client.send_frame(rustwisp_proto::ws::opcode::PING, true, b"alive");
    assert_eq!(
        client.recv_frame(),
        (rustwisp_proto::ws::opcode::PONG, b"alive".to_vec())
    );
}

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
                "--allow-host",
                "allowed.test",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let port = listening_port(&child);
        let mut client = common::Client::v1(port);
        client.connect_stream(1, 1, "127.0.0.1", 80);
        let _ = client.recv_packet();
        client.connect_stream(2, 1, "line\nbreak\r\t\u{1b}[31m.test", 80);
        client.expect_close(2, rustwisp_proto::wisp::close::BLOCKED);
        drop(client);
        let mut login = common::Client::connect(port, "p");
        let _ = login.recv_packet();
        let user = b"private-user";
        let password = b"private-password";
        let mut meta = vec![user.len() as u8];
        meta.extend_from_slice(&(password.len() as u16).to_le_bytes());
        meta.extend_from_slice(user);
        meta.extend_from_slice(password);
        let mut body = vec![
            rustwisp_proto::wisp::MAJOR,
            rustwisp_proto::wisp::MINOR,
            rustwisp_proto::wisp::ext::PASSWORD,
        ];
        body.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        body.extend_from_slice(&meta);
        login.send_packet(rustwisp_proto::wisp::ptype::INFO, 0, &body);
        assert_eq!(
            login.recv_packet().ptype,
            rustwisp_proto::wisp::ptype::CONTINUE
        );
        drop(login);
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
            assert!(line.chars().all(|ch| !ch.is_control()), "{line:?}");
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

#[test]
fn malformed_credentials_are_not_printed_by_startup_errors() {
    let marker = "credential-marker-7319";
    for argument in [
        format!("--password-user=:{marker}"),
        format!("--password-user=:{}", marker.repeat(10)),
        format!("--proxy=http://user:{}@127.0.0.1:0", marker.repeat(10)),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rustwisp"))
            .args(["--host", "127.0.0.1", &argument, "--help"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains(marker),
            "startup printed a credential"
        );
    }
}

#[test]
fn startup_failures_drain_their_diagnostic_before_exiting() {
    for _ in 0..4 {
        let mut server = Running(
            Command::new(env!("CARGO_BIN_EXE_rustwisp"))
                .args([
                    "--host",
                    "127.0.0.1",
                    "--password-user",
                    "user:$y$invalid",
                    "--log-level",
                    "error",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = server.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "invalid configuration did not exit"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(status.code(), Some(1));
        let mut error = String::new();
        server
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut error)
            .unwrap();
        assert!(
            error.contains("yescrypt"),
            "startup diagnostic was lost: {error:?}"
        );
    }
}
