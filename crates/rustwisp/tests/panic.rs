#![cfg(all(target_os = "linux", feature = "worker-panic-test"))]

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn a_worker_panic_terminates_the_process() {
    for blocked_sink in [false, true] {
        let mut held_reader = None;
        let sink = if blocked_sink {
            let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::NONBLOCK).unwrap();
            while rustix::io::write(&write, &[b'x'; 4096]).is_ok() {}
            rustix::fs::fcntl_setfl(&write, rustix::fs::OFlags::empty()).unwrap();
            held_reader = Some(read);
            Stdio::from(write)
        } else {
            Stdio::piped()
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_rustwisp"))
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                "0",
                "--workers",
                "2",
                "--log-level",
                "none",
                "--reputation",
                "off",
            ])
            .env("RUSTWISP_TEST_WORKER_PANIC", "1")
            .stderr(sink)
            .spawn()
            .unwrap();
        let reader = child.stderr.take().map(|mut stderr| {
            std::thread::spawn(move || {
                let mut log = String::new();
                stderr.read_to_string(&mut log).unwrap();
                log
            })
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("server survived its worker panic");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(!status.success());
        if let Some(reader) = reader {
            let log = reader.join().unwrap();
            assert!(log.contains("[error] panic:"), "{log}");
            assert!(log.contains("hw-worker"), "{log}");
            assert!(!log.contains("worker panic fixture"), "{log}");
        }
        drop(held_reader);
    }
}
