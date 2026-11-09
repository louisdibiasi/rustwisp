//! `rustwisp-cli`: a netcat that goes through a Wisp server.

use rustwisp_client::{Event, Handle, Options, connect};
use rustwisp_proto::wisp::{close, stream_type};
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const USAGE: &str = "\
rustwisp-cli - netcat through a Wisp server

usage: rustwisp-cli [options] WS_URL HOST PORT

  WS_URL            ws://server:port/ (wss:// is not supported)
  HOST PORT         where the server should connect to

options:
  -u, --udp         open a UDP stream instead of TCP
      --v1          speak Wisp v1 (no INFO exchange, no password)
      --user NAME   username for servers that need a password
      --pass TEXT   password for servers that need one
      --wait SECS   after stdin ends, wait this long for more output (default 3)
  -h, --help        show this help
  -V, --version     show the version

Reads standard input, writes what the remote sends to standard output.";

struct Args {
    url: String,
    host: String,
    port: u16,
    udp: bool,
    wait: Duration,
    options: Options,
}

enum Parsed {
    Run(Args),
    Done(&'static str),
}

fn parse_args(args: &[String]) -> Result<Parsed, String> {
    let mut options = Options::default();
    let mut udp = false;
    let mut wait = Duration::from_secs(3);
    let mut positional = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Ok(Parsed::Done(USAGE)),
            "-V" | "--version" => return Ok(Parsed::Done(env!("CARGO_PKG_VERSION"))),
            "-u" | "--udp" => udp = true,
            "--v1" => options.v2 = false,
            "--user" => options.username = Some(value("--user")?),
            "--pass" => options.password = Some(value("--pass")?),
            "--wait" => {
                let secs: f64 = value("--wait")?
                    .parse()
                    .map_err(|_| "--wait needs a number of seconds".to_string())?;
                if !(0.0..=3600.0).contains(&secs) {
                    return Err("--wait must be between 0 and 3600".into());
                }
                wait = Duration::from_secs_f64(secs);
            }
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("unknown option '{s}'")),
            _ => positional.push(arg.clone()),
        }
    }
    let [url, host, port] = <[String; 3]>::try_from(positional)
        .map_err(|_| "expected WS_URL HOST PORT (see --help)".to_string())?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("bad port '{port}'"))?;
    Ok(Parsed::Run(Args {
        url,
        host,
        port,
        udp,
        wait,
        options,
    }))
}

/// Text from the server, made safe to show in a terminal: control characters (escape sequences
/// included) become '?' and the length is capped.
fn printable(text: &str) -> String {
    const MAX_CHARS: usize = 500;
    text.chars()
        .take(MAX_CHARS)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Copy standard input to the stream until it ends or the stream goes away.
fn pump_stdin(handle: Handle, stream: u32, stdin_done: Arc<AtomicBool>) {
    let mut stdin = io::stdin().lock();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match stdin.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if handle.send(stream, &buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    stdin_done.store(true, Ordering::Release);
}

fn run(args: Args) -> Result<(), String> {
    let (handle, mut reader) =
        connect(&args.url, &args.options).map_err(|e| format!("connect: {e}"))?;
    if let Some(motd) = handle.motd() {
        eprintln!("motd: {}", printable(&motd));
    }
    let kind = if args.udp {
        stream_type::UDP
    } else {
        stream_type::TCP
    };
    let stream = handle
        .open(kind, &args.host, args.port)
        .map_err(|e| format!("open: {e}"))?;

    let stdin_done = Arc::new(AtomicBool::new(false));
    {
        let (handle, done) = (handle.clone(), Arc::clone(&stdin_done));
        thread::spawn(move || pump_stdin(handle, stream, done));
    }

    let mut out = io::stdout().lock();
    let mut idle_set = false;
    // wake up now and then to notice that stdin has ended
    reader.set_timeout(Some(Duration::from_millis(250))).ok();
    loop {
        if !idle_set && stdin_done.load(Ordering::Acquire) {
            reader
                .set_timeout(Some(args.wait.max(Duration::from_millis(1))))
                .ok();
            idle_set = true;
        }
        match reader.next_event() {
            Ok(Event::Data { stream: s, data }) if s == stream => {
                out.write_all(&data)
                    .and_then(|()| out.flush())
                    .map_err(|e| format!("stdout: {e}"))?;
            }
            Ok(Event::Close { stream: s, reason }) if s == stream => {
                if reason != close::VOLUNTARY {
                    return Err(format!("closed by the server, reason 0x{reason:02x}"));
                }
                return Ok(());
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if idle_set {
                    handle.close(stream, close::VOLUNTARY).ok();
                    return Ok(());
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::ConnectionAborted
                    || e.kind() == io::ErrorKind::UnexpectedEof =>
            {
                return Ok(());
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(Parsed::Done(text)) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Ok(Parsed::Run(a)) => match run(a) {
            Ok(()) => ExitCode::SUCCESS,
            Err(m) => {
                eprintln!("rustwisp-cli: {m}");
                ExitCode::from(1)
            }
        },
        Err(m) => {
            eprintln!("rustwisp-cli: {m}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::printable;

    #[test]
    fn terminal_escapes_in_server_text_are_defanged() {
        assert_eq!(printable("hi\u{1b}[2Jthere\r\n"), "hi?[2Jthere??");
        assert_eq!(printable(&"x".repeat(900)).len(), 500);
    }
}
