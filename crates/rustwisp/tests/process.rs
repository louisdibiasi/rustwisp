#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(eof: bool) -> Running {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustwisp"))
        .args([
            "--host=127.0.0.1",
            "--port=0",
            "--workers=1",
            "--reputation=off",
            "--busy-poll-us=50",
        ])
        .args(if eof {
            vec!["--stop-on-stdin-eof=on"]
        } else {
            vec![]
        })
        .stdin(if eof { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (ready, wait) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.contains("listening on") {
                let _ = ready.send(());
            }
        }
    });
    let child = Running(child);
    wait.recv_timeout(Duration::from_secs(10)).unwrap();
    child
}

fn wait_success(child: &mut Running) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "{status}");
            return;
        }
        assert!(Instant::now() < deadline, "server did not shut down");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn stdin_bytes_are_ignored_but_eof_stops_the_child() {
    let mut child = spawn(true);
    child
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"ignored\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(child.0.try_wait().unwrap().is_none());
    drop(child.0.stdin.take());
    wait_success(&mut child);
}

#[test]
fn default_stdin_eof_does_not_stop_the_server() {
    let mut child = spawn(false);
    std::thread::sleep(Duration::from_millis(100));
    assert!(child.0.try_wait().unwrap().is_none());
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    wait_success(&mut child);
}

#[test]
fn simultaneous_signal_and_stdin_eof_shut_down_cleanly() {
    let mut child = spawn(true);
    drop(child.0.stdin.take());
    let _ = Command::new("kill")
        .args(["-TERM", &child.0.id().to_string()])
        .status();
    wait_success(&mut child);
}
