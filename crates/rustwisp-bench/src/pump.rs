//! The load generator. `tp` keeps streams full until it is killed, `rtt` times one small message
//! at a time, `churn` opens a stream, echoes one byte and closes it, over and over. `rtt` and
//! `churn` print one `key=value` line when they finish.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rustwisp_client::{EventRef, Handle, Options, Reader, connect};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Throughput,
    Rtt,
    Churn,
}

#[derive(Debug)]
pub struct Args {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub mode: Mode,
    pub conns: usize,
    pub streams: usize,
    pub chunk: usize,
    pub secs: u64,
}

pub fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args {
        url: String::new(),
        host: String::new(),
        port: 0,
        mode: Mode::Throughput,
        conns: 1,
        streams: 1,
        chunk: 65536,
        secs: 5,
    };
    let mut positional = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut val = |n: &str| it.next().cloned().ok_or(format!("{n} needs a value"));
        let num = |n: &str, v: String| v.parse::<usize>().map_err(|_| format!("bad {n}"));
        match arg.as_str() {
            "--server" => a.url = val("--server")?,
            "--mode" => {
                a.mode = match val("--mode")?.as_str() {
                    "tp" => Mode::Throughput,
                    "rtt" => Mode::Rtt,
                    "churn" => Mode::Churn,
                    other => return Err(format!("unknown mode '{other}'")),
                }
            }
            "--conns" => a.conns = num("--conns", val("--conns")?)?.max(1),
            "--streams" => a.streams = num("--streams", val("--streams")?)?.max(1),
            "--chunk" => a.chunk = num("--chunk", val("--chunk")?)?.max(1),
            "--secs" => a.secs = num("--secs", val("--secs")?)? as u64,
            s if s.starts_with("--") => return Err(format!("unknown option '{s}'")),
            _ => positional.push(arg.clone()),
        }
    }
    let [host, port] = <[String; 2]>::try_from(positional)
        .map_err(|_| "expected HOST PORT after the options".to_string())?;
    a.host = host;
    a.port = port.parse().map_err(|_| "bad port".to_string())?;
    if a.url.is_empty() {
        return Err("--server ws://... is required".into());
    }
    Ok(a)
}

pub fn run(a: Args) -> Result<(), String> {
    match a.mode {
        Mode::Throughput => throughput(&a),
        Mode::Rtt => rtt(&a),
        Mode::Churn => churn(&a),
    }
}

fn open(a: &Args) -> Result<(Handle, Reader), String> {
    connect(&a.url, &Options::default()).map_err(|e| format!("connect: {e}"))
}

/// Keep `conns * streams` streams full until the process is killed.
fn throughput(a: &Args) -> Result<(), String> {
    let received = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    for _ in 0..a.conns {
        let (handle, mut reader) = open(a)?;
        let received = Arc::clone(&received);
        workers.push(thread::spawn(move || {
            // Drain what the echo sends back without copying it.
            while let Ok(ev) = reader.next_ref() {
                if let EventRef::Data { data, .. } = ev {
                    received.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
            eprintln!("pump: connection lost");
            std::process::exit(1);
        }));
        for _ in 0..a.streams {
            let id = handle
                .open_tcp(&a.host, a.port)
                .map_err(|e| format!("open: {e}"))?;
            let (handle, chunk) = (handle.clone(), a.chunk);
            workers.push(thread::spawn(move || {
                let data = vec![0x5au8; chunk];
                while handle.send_with(id, &data, chunk).is_ok() {}
            }));
        }
    }
    for w in workers {
        let _ = w.join();
    }
    Ok(())
}

fn percentile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

/// Read until `want` bytes of DATA have arrived on any stream.
fn read_bytes(reader: &mut Reader, want: usize) -> Result<(), String> {
    let mut got = 0;
    while got < want {
        match reader.next_ref().map_err(|e| format!("read: {e}"))? {
            EventRef::Data { data, .. } => got += data.len(),
            EventRef::Close { reason, .. } => return Err(format!("closed, reason {reason:#x}")),
            EventRef::Continue { .. } => {}
        }
    }
    Ok(())
}

/// One message in flight on one stream: round-trip time through server and echo.
fn rtt(a: &Args) -> Result<(), String> {
    let (handle, mut reader) = open(a)?;
    let id = handle
        .open_tcp(&a.host, a.port)
        .map_err(|e| format!("open: {e}"))?;
    let msg = vec![0xa5u8; a.chunk.min(65536)];
    let mut samples: Vec<u64> = Vec::new();
    let end = Instant::now() + Duration::from_secs(a.secs);
    let mut n = 0u64;
    while Instant::now() < end {
        let t = Instant::now();
        handle.send(id, &msg).map_err(|e| format!("send: {e}"))?;
        read_bytes(&mut reader, msg.len())?;
        n += 1;
        if n > 500 {
            samples.push(t.elapsed().as_nanos() as u64); // the first rounds are warm-up
        }
    }
    samples.sort_unstable();
    println!(
        "rtt n={} p50={} p99={} p999={} max={}",
        samples.len(),
        percentile(&samples, 0.50),
        percentile(&samples, 0.99),
        percentile(&samples, 0.999),
        samples.last().copied().unwrap_or(0)
    );
    Ok(())
}

/// Open a stream, echo one byte, close it, again and again.
fn churn(a: &Args) -> Result<(), String> {
    let (handle, mut reader) = open(a)?;
    let started = Instant::now();
    let end = started + Duration::from_secs(a.secs);
    let mut ops = 0u64;
    while Instant::now() < end {
        let id = handle
            .open_tcp(&a.host, a.port)
            .map_err(|e| format!("open: {e}"))?;
        handle.send(id, b"x").map_err(|e| format!("send: {e}"))?;
        read_bytes(&mut reader, 1)?;
        handle.close(id, 0x02).map_err(|e| format!("close: {e}"))?;
        ops += 1;
    }
    let secs = started.elapsed().as_secs_f64();
    println!("churn ops={ops} per_sec={:.0}", ops as f64 / secs);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn percentiles_pick_the_expected_rank() {
        let v: Vec<u64> = (1..=1000).collect();
        assert_eq!(percentile(&v, 0.5), 501);
        assert_eq!(percentile(&v, 0.99), 990);
        assert_eq!(percentile(&v, 1.0), 1000);
        assert_eq!(percentile(&[], 0.5), 0);
    }

    #[test]
    fn arguments_are_checked() {
        let ok = parse(&a(&[
            "--server",
            "ws://h/",
            "--mode",
            "rtt",
            "--secs",
            "2",
            "127.0.0.1",
            "80",
        ]))
        .unwrap();
        assert_eq!((ok.mode, ok.port, ok.secs), (Mode::Rtt, 80, 2));
        assert!(parse(&a(&["127.0.0.1", "80"])).is_err()); // no --server
        assert!(parse(&a(&["--server", "ws://h/", "127.0.0.1"])).is_err());
        assert!(parse(&a(&["--server", "ws://h/", "--mode", "x", "h", "1"])).is_err());
        assert!(parse(&a(&["--server", "ws://h/", "--bogus", "h", "1"])).is_err());
    }
}
