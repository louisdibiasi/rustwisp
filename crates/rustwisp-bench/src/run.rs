//! The runner: starts a server and the echo service, drives one scenario at a time, and reads the
//! server's CPU, memory and context switches from `/proc` over the measured window.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::procstat;

/// Flags that make any holyWisp-compatible server reachable from the bench: loopback targets
/// allowed, every limiter off, no logging.
const SERVER_FLAGS: [&str; 8] = [
    "--allow-loopback=on",
    "--allow-direct-ip=on",
    "--flood-protection=off",
    "--reputation=off",
    "--connections-limit-per-ip=0",
    "--connection-window-s=0",
    "--serve-webclient=off",
    "--log-level=error",
];

#[derive(Debug, Clone)]
pub struct Server {
    pub label: String,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Throughput {
        conns: usize,
        streams: usize,
        chunk: usize,
    },
    Rtt {
        size: usize,
    },
    Churn,
}

#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    pub name: &'static str,
    pub kind: Kind,
}

/// The scenarios of the upstream benchmark, so numbers line up with theirs.
pub const SCENARIOS: [Scenario; 7] = [
    Scenario {
        name: "native-1",
        kind: Kind::Throughput {
            conns: 1,
            streams: 1,
            chunk: 65536,
        },
    },
    Scenario {
        name: "native-10",
        kind: Kind::Throughput {
            conns: 1,
            streams: 10,
            chunk: 65536,
        },
    },
    Scenario {
        name: "native-10-1m",
        kind: Kind::Throughput {
            conns: 1,
            streams: 10,
            chunk: 1 << 20,
        },
    },
    Scenario {
        name: "conns-8x4",
        kind: Kind::Throughput {
            conns: 8,
            streams: 4,
            chunk: 65536,
        },
    },
    Scenario {
        name: "conns-16x4",
        kind: Kind::Throughput {
            conns: 16,
            streams: 4,
            chunk: 65536,
        },
    },
    Scenario {
        name: "rtt-64",
        kind: Kind::Rtt { size: 64 },
    },
    Scenario {
        name: "churn",
        kind: Kind::Churn,
    },
];

#[derive(Debug, Clone)]
pub struct Options {
    pub servers: Vec<Server>,
    pub scenarios: Vec<Scenario>,
    pub secs: u64,
    pub warmup: u64,
    pub reps: usize,
    pub base_port: u16,
}

/// Named numbers from one repetition.
pub type Metrics = BTreeMap<&'static str, f64>;

/// Repetitions per (scenario, server).
pub type Results = BTreeMap<(String, String), Vec<Metrics>>;

/// A child process that is killed when dropped, so an error never leaves a server running.
struct Owned(Child);

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl std::ops::Deref for Owned {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl std::ops::DerefMut for Owned {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

fn wait_listening(port: u16) -> Result<(), String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(format!("nothing listening on port {port} after 10 s"))
}

fn start_server(server: &Server, port: u16) -> Result<Child, String> {
    let (program, args) = server.command.split_first().ok_or("empty server command")?;
    Command::new(program)
        .args(args)
        .args(["--port", &port.to_string()])
        .args(SERVER_FLAGS)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start {program}: {e}"))
}

/// Run the echo service and keep its latest `(nanoseconds, bytes)` line in the returned cell.
/// The echo service's latest `(nanoseconds, bytes)` report.
type Latest = Arc<Mutex<(u64, u64)>>;

fn start_echo(exe: &std::path::Path, port: u16) -> Result<(Child, Latest), String> {
    let mut child = Command::new(exe)
        .args(["echo", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start the echo service: {e}"))?;
    let latest = Arc::new(Mutex::new((0u64, 0u64)));
    let out = child.stdout.take().ok_or("no echo output")?;
    let cell = Arc::clone(&latest);
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let mut f = line
                .split_whitespace()
                .map(|t| t.parse::<u64>().unwrap_or(0));
            if let (Some(ns), Some(bytes)) = (f.next(), f.next())
                && let Ok(mut c) = cell.lock()
            {
                *c = (ns, bytes);
            }
        }
    });
    Ok((child, latest))
}

fn pump_args(url: &str, echo_port: u16, scenario: &Scenario, secs: u64) -> Vec<String> {
    let mut a: Vec<String> = ["pump", "--server", url].map(String::from).to_vec();
    match scenario.kind {
        Kind::Throughput {
            conns,
            streams,
            chunk,
        } => a.extend(
            [
                "--mode",
                "tp",
                "--conns",
                &conns.to_string(),
                "--streams",
                &streams.to_string(),
                "--chunk",
                &chunk.to_string(),
            ]
            .map(String::from),
        ),
        Kind::Rtt { size } => a.extend(
            [
                "--mode",
                "rtt",
                "--chunk",
                &size.to_string(),
                "--secs",
                &secs.to_string(),
            ]
            .map(String::from),
        ),
        Kind::Churn => a.extend(["--mode", "churn", "--secs", &secs.to_string()].map(String::from)),
    }
    a.extend(["127.0.0.1".to_string(), echo_port.to_string()]);
    a
}

fn kv(line: &str, key: &str) -> Option<f64> {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
}

/// One repetition of one scenario against one server.
pub fn measure(server: &Server, scenario: &Scenario, o: &Options) -> Result<Metrics, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let (server_port, echo_port) = (o.base_port, o.base_port + 1);
    let url = format!("ws://127.0.0.1:{server_port}/");

    let (echo, latest) = start_echo(&exe, echo_port)?;
    let _echo = Owned(echo);
    wait_listening(echo_port)?;
    let srv = Owned(start_server(server, server_port)?);
    let srv_pid = srv.id();
    wait_listening(server_port)?;

    let mut pump = Owned(
        Command::new(&exe)
            .args(pump_args(&url, echo_port, scenario, o.secs))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot start the load generator: {e}"))?,
    );
    let mut m = Metrics::new();

    match scenario.kind {
        Kind::Throughput { .. } => {
            thread::sleep(Duration::from_secs(o.warmup));
            if let Ok(Some(status)) = pump.try_wait() {
                return Err(format!("the load generator quit early ({status})"));
            }
            let before = (
                *latest.lock().map_err(|e| e.to_string())?,
                procstat::cpu(srv_pid),
                procstat::context_switches(srv_pid),
                procstat::tcp_segments_out(),
            );
            thread::sleep(Duration::from_secs(o.secs));
            let after = (
                *latest.lock().map_err(|e| e.to_string())?,
                procstat::cpu(srv_pid),
                procstat::context_switches(srv_pid),
                procstat::tcp_segments_out(),
            );
            let alive = pump.try_wait().map_err(|e| e.to_string())?.is_none();
            let _ = pump.kill();
            let _ = pump.wait();
            if !alive {
                return Err("the load generator died during the measurement".into());
            }
            let secs = (after.0.0.saturating_sub(before.0.0)) as f64 / 1e9;
            let mib = (after.0.1.saturating_sub(before.0.1)) as f64 / 1_048_576.0;
            if mib <= 0.0 || secs <= 0.0 {
                return Err("no bytes reached the echo service".into());
            }
            m.insert("mibs", mib / secs);
            if let (Some(a), Some(b)) = (after.1, before.1) {
                let cpu = a.since(b);
                m.insert("srv_cpu", cpu.total());
                m.insert("srv_sys", cpu.system);
                m.insert("mib_per_cpu", mib / cpu.total().max(0.01));
            }
            m.insert(
                "ctx_per_mib",
                (after.2.saturating_sub(before.2)) as f64 / mib,
            );
            if let (Some(a), Some(b)) = (after.3, before.3) {
                m.insert("segs_per_mib", a.saturating_sub(b) as f64 / mib);
            }
        }
        Kind::Rtt { .. } | Kind::Churn => {
            let before = procstat::cpu(srv_pid);
            let mut text = String::new();
            if let Some(mut out) = pump.stdout.take() {
                let _ = out.read_to_string(&mut text);
            }
            let status = pump.wait().map_err(|e| e.to_string())?;
            let line = text.lines().last().unwrap_or("");
            if !status.success() || line.is_empty() {
                return Err(format!("the load generator failed ({status})"));
            }
            if let (Some(a), Some(b)) = (procstat::cpu(srv_pid), before) {
                m.insert("srv_cpu", a.since(b).total());
            }
            match scenario.kind {
                Kind::Rtt { .. } => {
                    for (key, name) in [
                        ("p50", "p50_us"),
                        ("p99", "p99_us"),
                        ("p999", "p999_us"),
                        ("max", "max_us"),
                    ] {
                        m.insert(name, kv(line, key).ok_or("no latency result")? / 1000.0);
                    }
                }
                _ => {
                    m.insert("ops_per_s", kv(line, "per_sec").ok_or("no churn result")?);
                }
            }
        }
    }
    if let Some(rss) = procstat::peak_rss_mib(srv_pid) {
        m.insert("rss_mib", rss);
    }
    drop(pump);
    drop(srv);
    drop(_echo);
    thread::sleep(Duration::from_millis(300)); // let the ports free up
    Ok(m)
}

/// Every scenario against every server, `reps` times, interleaved so slow drift hits all servers
/// alike.
pub fn run_all(o: &Options) -> Results {
    let mut results = Results::new();
    for rep in 1..=o.reps {
        for scenario in &o.scenarios {
            for server in &o.servers {
                eprint!(
                    "[{rep}/{}] {:<14} {:<12} ",
                    o.reps, scenario.name, server.label
                );
                match measure(server, scenario, o) {
                    Ok(m) => {
                        eprintln!("ok");
                        results
                            .entry((scenario.name.to_string(), server.label.clone()))
                            .or_default()
                            .push(m);
                    }
                    Err(e) => {
                        eprintln!("DNF: {e}");
                        results
                            .entry((scenario.name.to_string(), server.label.clone()))
                            .or_default();
                    }
                }
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_value_lines_are_read() {
        let line = "rtt n=10 p50=1500 p99=9000 p999=12345 max=99999";
        assert_eq!(kv(line, "p50"), Some(1500.0));
        assert_eq!(kv(line, "p99"), Some(9000.0)); // not confused with p999
        assert_eq!(kv(line, "p999"), Some(12345.0));
        assert_eq!(kv(line, "nope"), None);
    }

    #[test]
    fn scenario_names_are_unique() {
        let mut names: Vec<_> = SCENARIOS.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), SCENARIOS.len());
    }

    #[test]
    fn the_load_generator_gets_the_right_arguments() {
        let churn = pump_args("ws://x/", 9, &SCENARIOS[6], 4);
        assert_eq!(churn[..3], ["pump", "--server", "ws://x/"]);
        assert!(churn.windows(2).any(|w| w == ["--mode", "churn"]));
        assert_eq!(churn[churn.len() - 2..], ["127.0.0.1", "9"]);
        let tp = pump_args("ws://x/", 9, &SCENARIOS[3], 4);
        assert!(tp.windows(2).any(|w| w == ["--conns", "8"]));
        assert!(tp.windows(2).any(|w| w == ["--streams", "4"]));
    }
}
