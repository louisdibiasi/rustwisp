//! The counting echo service every scenario aims at. It prints `nanoseconds bytes connections`
//! every 100 ms, so the byte count comes from the destination and not from the client that
//! generated the traffic.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
struct Counters {
    bytes: AtomicU64,
    conns: AtomicU64,
}

fn serve(mut s: TcpStream, counters: &Counters) {
    let _ = s.set_nodelay(true);
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                counters.bytes.fetch_add(n as u64, Ordering::Relaxed);
                if s.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        }
    }
}

/// Listen on `port` for ever.
pub fn run(port: u16) -> Result<(), String> {
    let listener =
        TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("bind {port}: {e}"))?;
    let counters = Arc::new(Counters::default());
    {
        let counters = Arc::clone(&counters);
        thread::spawn(move || {
            let started = Instant::now();
            let stdout = std::io::stdout();
            loop {
                thread::sleep(Duration::from_millis(100));
                let line = format!(
                    "{} {} {}\n",
                    started.elapsed().as_nanos(),
                    counters.bytes.load(Ordering::Relaxed),
                    counters.conns.load(Ordering::Relaxed)
                );
                let mut out = stdout.lock();
                if out
                    .write_all(line.as_bytes())
                    .and_then(|()| out.flush())
                    .is_err()
                {
                    std::process::exit(0); // the runner is gone
                }
            }
        });
    }
    for s in listener.incoming().flatten() {
        counters.conns.fetch_add(1, Ordering::Relaxed);
        let counters = Arc::clone(&counters);
        thread::spawn(move || serve(s, &counters));
    }
    Ok(())
}
