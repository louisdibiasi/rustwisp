//! `holywisp-bench`: compares Wisp servers on throughput, latency and connection churn, and reports
//! what each costs in CPU and memory. It talks to servers over the network only, so the same run
//! can put the Rust server next to the C one (or any other Wisp server that takes the same flags).

#[cfg(target_os = "linux")]
mod echo;
#[cfg(target_os = "linux")]
mod procstat;
#[cfg(target_os = "linux")]
mod pump;
#[cfg(target_os = "linux")]
mod report;
#[cfg(target_os = "linux")]
mod run;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("holywisp-bench reads /proc and only runs on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
const USAGE: &str = "\
holywisp-bench - compare Wisp servers

usage:
  holywisp-bench run --server LABEL=COMMAND [--server LABEL=COMMAND ...] [options]
  holywisp-bench compare A.tsv B.tsv

run options:
  --server LABEL=COMMAND   a server to test; COMMAND is split on spaces and gets
                           --port and the permissive bench flags appended. The first
                           server is the baseline the others are compared with.
  --scenarios a,b,c        which scenarios (default: all)
  --secs N                 length of each measurement (default 5)
  --warmup N               seconds before measuring throughput (default 2)
  --reps N                 repetitions; the median is reported (default 3)
  --base-port N            server port; the echo service uses N+1 (default 16401)
  --out FILE               also write the medians to FILE (tab separated)
  --list                   show the scenarios and exit

compare:
  Prints how the first server in B did against the first server in A.

Example:
  holywisp-bench run --server c='build/release/holywisp' \\
      --server rust='target/release/holywisp' --out results.tsv

(The commands `echo` and `pump` are the helper processes `run` starts for itself.)";

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("echo") => helper(|| {
            let port = args
                .get(1)
                .and_then(|p| p.parse().ok())
                .ok_or("usage: echo PORT")?;
            echo::run(port)
        }),
        Some("pump") => helper(|| pump::run(pump::parse(&args[1..])?)),
        Some("run") => helper(|| cmd_run(&args[1..])),
        Some("compare") => helper(|| match args.as_slice() {
            [_, a, b] => report::compare(a, b),
            _ => Err("usage: compare A.tsv B.tsv".to_string()),
        }),
        Some("-h" | "--help") | None => {
            println!("{USAGE}");
            0
        }
        Some(other) => {
            eprintln!("holywisp-bench: unknown command '{other}' (try --help)");
            2
        }
    };
    std::process::exit(code);
}

#[cfg(target_os = "linux")]
fn helper(f: impl FnOnce() -> Result<(), String>) -> i32 {
    match f() {
        Ok(()) => 0,
        Err(m) => {
            eprintln!("holywisp-bench: {m}");
            1
        }
    }
}

#[cfg(target_os = "linux")]
fn cmd_run(args: &[String]) -> Result<(), String> {
    let mut servers = Vec::new();
    let mut names: Option<Vec<String>> = None;
    let mut o = run::Options {
        servers: Vec::new(),
        scenarios: Vec::new(),
        secs: 5,
        warmup: 2,
        reps: 3,
        base_port: 16401,
    };
    let mut out = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut val = |n: &str| it.next().cloned().ok_or(format!("{n} needs a value"));
        let num = |n: &str, v: String| v.parse::<u64>().map_err(|_| format!("{n} needs a number"));
        match arg.as_str() {
            "--server" => {
                let v = val("--server")?;
                let (label, cmd) = v.split_once('=').ok_or("--server wants LABEL=COMMAND")?;
                let command: Vec<String> = cmd.split_whitespace().map(String::from).collect();
                if label.is_empty() || command.is_empty() {
                    return Err("--server wants LABEL=COMMAND".into());
                }
                servers.push(run::Server {
                    label: label.to_string(),
                    command,
                });
            }
            "--scenarios" => {
                names = Some(val("--scenarios")?.split(',').map(String::from).collect())
            }
            "--secs" => o.secs = num("--secs", val("--secs")?)?.max(1),
            "--warmup" => o.warmup = num("--warmup", val("--warmup")?)?,
            "--reps" => o.reps = num("--reps", val("--reps")?)?.max(1) as usize,
            "--base-port" => {
                o.base_port = u16::try_from(num("--base-port", val("--base-port")?)?)
                    .ok()
                    .filter(|p| *p > 0 && *p < u16::MAX)
                    .ok_or("--base-port out of range")?;
            }
            "--out" => out = Some(val("--out")?),
            "--list" => {
                for s in run::SCENARIOS {
                    println!("{}", s.name);
                }
                return Ok(());
            }
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    if servers.is_empty() {
        return Err("give at least one --server LABEL=COMMAND (see --help)".into());
    }
    o.servers = servers;
    o.scenarios = match names {
        None => run::SCENARIOS.to_vec(),
        Some(list) => list
            .iter()
            .map(|n| {
                run::SCENARIOS
                    .iter()
                    .find(|s| s.name == n)
                    .copied()
                    .ok_or(format!("unknown scenario '{n}' (see --list)"))
            })
            .collect::<Result<_, _>>()?,
    };
    let results = run::run_all(&o);
    report::print(&o, &results);
    if let Some(path) = out {
        report::write_tsv(&path, &results).map_err(|e| format!("{path}: {e}"))?;
        eprintln!("wrote {path}");
    }
    Ok(())
}
