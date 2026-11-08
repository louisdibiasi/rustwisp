//! Configuration for the holyWisp server.
//!
//! Every key from the C server's `holywisp.conf` is accepted with the same name, meaning and
//! range, both as a `key = value` line and as a `--key value` / `--key=value` flag. Flags win over
//! the file; list keys (`allow-host`, `trusted-proxy`, ...) build up when repeated.

mod values;

use std::collections::BTreeMap;
use std::io;

pub use values::{Cidr, HostList, PortSet, ProxyKind, ProxyUrl, normalize_hostname};
use values::{MAX_CIDRS, MAX_DNS_SERVERS, MAX_STRING, MAX_TRUSTED_HEADERS, parse_bool};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reputation events a weight can be set for.
pub const REPUTATION_EVENTS: [&str; 8] = [
    "privateEgress",
    "synSignature",
    "twispNoAuth",
    "burstRate",
    "successfulStream",
    "requestKnownBadDest",
    "authFailure",
    "protocolViolation",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    None,
}

impl LogLevel {
    fn parse(v: &str) -> Option<Self> {
        Some(match v {
            "debug" => Self::Debug,
            "info" => Self::Info,
            "warn" => Self::Warn,
            "error" => Self::Error,
            "none" => Self::None,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOrder {
    Ipv4First,
    Ipv6First,
    Verbatim,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FloodConfig {
    pub enabled: bool,
    pub max_connects_per_source_per_second: u32,
    pub max_connects_per_dest_per_second: u32,
    pub max_connects_per_dest_per_minute: u32,
    pub max_in_flight_syns: u32,
    pub max_concurrent_connections: u32,
    pub syn_signature_enabled: bool,
    pub syn_signature_window_ms: u32,
    pub syn_signature_min_samples: u32,
    pub syn_signature_failed_ratio: f64,
    pub ws_close_after_violations: u32,
    pub log_blocked_dials: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReputationConfig {
    pub store_path: String,
    pub save_interval_s: u32,
    pub decay_per_hour: u32,
    pub evict_after_days: u32,
    pub warn: u32,
    pub throttle: u32,
    pub strict: u32,
    /// Overrides only; the reputation module owns the defaults.
    pub source_weights: BTreeMap<String, i32>,
    pub dest_weights: BTreeMap<String, i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    /// Plain text, or a crypt(3) hash (`$2b$`, `$6$`, `$y$`, ...).
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub workers: u32,
    pub log_level: LogLevel,

    pub allow_tcp: bool,
    pub allow_udp: bool,
    pub allow_direct_ip: bool,
    pub allow_private: bool,
    pub allow_loopback: bool,
    pub allow_link_local: bool,
    pub allow_hosts: HostList,
    pub block_hosts: HostList,
    pub allow_ports: PortSet,
    pub block_ports: PortSet,

    pub enable_v2: bool,
    pub enable_twisp: bool,
    pub motd: String,
    pub users: Vec<User>,
    pub password_required: bool,
    pub buffer_remaining: u32,

    pub parse_real_ip: bool,
    pub trusted_proxies: Vec<Cidr>,
    pub trusted_headers: Vec<String>,

    pub connections_limit_per_ip: u32,
    pub connection_window_s: u32,
    pub bandwidth_limit_kbps: u32,
    pub max_streams_per_conn: u32,

    pub flood: FloodConfig,
    pub reputation_enabled: bool,
    pub reputation: ReputationConfig,

    pub proxy: Option<ProxyUrl>,
    pub proxy_udp_direct: bool,
    pub dns_servers: Vec<String>,
    pub dns_ttl_s: u32,
    pub dns_negative_ttl_s: u32,
    pub dns_order: DnsOrder,
    pub dns_timeout_ms: u32,

    pub max_message_size: u32,
    pub ws_write_high_water: u32,
    pub stream_queue_max: u32,
    pub socket_buffer_size: u32,
    pub connect_timeout_ms: u32,
    pub handshake_timeout_ms: u32,
    pub resolver_threads: u32,
    pub tcp_nodelay: bool,
    pub tcp_quickack: bool,
    pub listen_backlog: u32,
    pub non_ws_response: String,
    pub serve_webclient: bool,
    pub webclient_wisp_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host: String::new(),
            port: 6001,
            workers: 0,
            log_level: LogLevel::Info,
            allow_tcp: true,
            allow_udp: true,
            allow_direct_ip: false,
            allow_private: false,
            allow_loopback: false,
            allow_link_local: false,
            allow_hosts: HostList::default(),
            block_hosts: HostList::default(),
            allow_ports: PortSet::default(),
            block_ports: PortSet::default(),
            enable_v2: true,
            enable_twisp: false,
            motd: String::new(),
            users: Vec::new(),
            password_required: false,
            buffer_remaining: 128,
            parse_real_ip: true,
            trusted_proxies: Vec::new(),
            trusted_headers: vec!["CF-Connecting-IP".into(), "X-Forwarded-For".into()],
            connections_limit_per_ip: 200,
            connection_window_s: 10,
            bandwidth_limit_kbps: 0,
            max_streams_per_conn: 2048,
            flood: FloodConfig {
                enabled: true,
                max_connects_per_source_per_second: 500,
                max_connects_per_dest_per_second: 100,
                max_connects_per_dest_per_minute: 3000,
                max_in_flight_syns: 4096,
                max_concurrent_connections: 50_000,
                syn_signature_enabled: true,
                syn_signature_window_ms: 2000,
                syn_signature_min_samples: 128,
                syn_signature_failed_ratio: 0.75,
                ws_close_after_violations: 64,
                log_blocked_dials: false,
            },
            reputation_enabled: true,
            reputation: ReputationConfig {
                store_path: "./data/reputation.json".into(),
                save_interval_s: 30,
                decay_per_hour: 1,
                evict_after_days: 7,
                warn: 21,
                throttle: 51,
                strict: 81,
                source_weights: BTreeMap::new(),
                dest_weights: BTreeMap::new(),
            },
            proxy: None,
            proxy_udp_direct: false,
            dns_servers: Vec::new(),
            dns_ttl_s: 120,
            dns_negative_ttl_s: 10,
            dns_order: DnsOrder::Ipv4First,
            dns_timeout_ms: 3000,
            max_message_size: 1024 * 1024 + 5,
            ws_write_high_water: 8 * 1024 * 1024,
            stream_queue_max: 16 * 1024 * 1024,
            socket_buffer_size: 0,
            connect_timeout_ms: 15_000,
            handshake_timeout_ms: 10_000,
            resolver_threads: 4,
            tcp_nodelay: true,
            tcp_quickack: true,
            listen_backlog: 1024,
            non_ws_response: "holyWisp: a Wisp server. Connect with a WebSocket client.\n".into(),
            serve_webclient: true,
            webclient_wisp_url: String::new(),
        }
    }
}

fn int(key: &str, v: &str, lo: u64, hi: u64) -> Result<u32, String> {
    let bad = || format!("bad value '{v}' for '{key}'");
    let n: u64 = v.parse().map_err(|_| bad())?;
    if n < lo || n > hi {
        return Err(bad());
    }
    u32::try_from(n).map_err(|_| bad())
}

fn boolean(key: &str, v: &str) -> Result<bool, String> {
    parse_bool(v).ok_or_else(|| format!("bad value '{v}' for '{key}'"))
}

fn string(key: &str, v: &str) -> Result<String, String> {
    if v.len() > MAX_STRING {
        return Err(format!(
            "bad value for '{key}': longer than {MAX_STRING} bytes"
        ));
    }
    Ok(v.to_string())
}

fn weight(key: &str, v: &str, map: &mut BTreeMap<String, i32>) -> Result<(), String> {
    let bad = || format!("bad value '{v}' for '{key}'");
    let (name, w) = v.rsplit_once(':').ok_or_else(bad)?;
    if !REPUTATION_EVENTS.contains(&name) {
        return Err(format!("{key}: unknown event '{name}'"));
    }
    let w: i32 = w.parse().map_err(|_| bad())?;
    if !(-100..=100).contains(&w) {
        return Err(bad());
    }
    map.insert(name.to_string(), w);
    Ok(())
}

impl Config {
    /// Apply one `key` / `value` pair. The error text matches what the C server prints.
    pub fn set(&mut self, key: &str, v: &str) -> Result<(), String> {
        const BIG: u64 = 1 << 24;
        match key {
            "host" => self.host = string(key, v)?,
            "port" => self.port = int(key, v, 0, 65_535)? as u16,
            "workers" => self.workers = int(key, v, 0, 1024)?,
            "log-level" => {
                self.log_level =
                    LogLevel::parse(v).ok_or_else(|| format!("bad value '{v}' for '{key}'"))?;
            }
            "allow-tcp" => self.allow_tcp = boolean(key, v)?,
            "allow-udp" => self.allow_udp = boolean(key, v)?,
            "allow-direct-ip" => self.allow_direct_ip = boolean(key, v)?,
            "allow-private" => self.allow_private = boolean(key, v)?,
            "allow-loopback" => self.allow_loopback = boolean(key, v)?,
            "allow-link-local" => self.allow_link_local = boolean(key, v)?,
            "allow-host" => self.allow_hosts.add(v).map_err(|e| format!("{key}: {e}"))?,
            "block-host" => self.block_hosts.add(v).map_err(|e| format!("{key}: {e}"))?,
            "allow-port" => self
                .allow_ports
                .add_spec(v)
                .map_err(|_| bad_value(key, v))?,
            "block-port" => self
                .block_ports
                .add_spec(v)
                .map_err(|_| bad_value(key, v))?,
            "enable-v2" => self.enable_v2 = boolean(key, v)?,
            "enable-twisp" => self.enable_twisp = boolean(key, v)?,
            "motd" => self.motd = string(key, v)?,
            "password-user" => {
                let (name, secret) = v.split_once(':').ok_or_else(|| bad_value(key, v))?;
                if name.is_empty() || name.len() >= 64 {
                    return Err(bad_value(key, v));
                }
                if self.users.len() >= 256 {
                    return Err("password-user: too many users".into());
                }
                self.users.push(User {
                    name: name.into(),
                    secret: string(key, secret)?,
                });
            }
            "password-required" => self.password_required = boolean(key, v)?,
            "buffer-remaining" => self.buffer_remaining = int(key, v, 1, BIG)?,
            "parse-real-ip" => self.parse_real_ip = boolean(key, v)?,
            "trusted-proxy" => {
                if self.trusted_proxies.len() >= MAX_CIDRS {
                    return Err("too many trusted-proxy entries".into());
                }
                self.trusted_proxies
                    .push(v.parse().map_err(|_| bad_value(key, v))?);
            }
            "trusted-header" => {
                if self.trusted_headers.len() >= MAX_TRUSTED_HEADERS {
                    return Err("too many trusted-header entries".into());
                }
                if v.is_empty() || v.len() >= 64 {
                    return Err(bad_value(key, v));
                }
                self.trusted_headers.push(v.to_string());
            }
            "trusted-headers-reset" => self.trusted_headers.clear(),
            "connections-limit-per-ip" => self.connections_limit_per_ip = int(key, v, 0, BIG)?,
            "connection-window-s" => self.connection_window_s = int(key, v, 0, 86_400)?,
            "bandwidth-limit-kbps" => self.bandwidth_limit_kbps = int(key, v, 0, 1_000_000_000)?,
            "max-streams-per-conn" => self.max_streams_per_conn = int(key, v, 0, 1 << 20)?,

            "flood-protection" => self.flood.enabled = boolean(key, v)?,
            "max-connects-per-source-per-second" => {
                self.flood.max_connects_per_source_per_second = int(key, v, 0, BIG)?;
            }
            "max-connects-per-dest-per-second" => {
                self.flood.max_connects_per_dest_per_second = int(key, v, 0, BIG)?;
            }
            "max-connects-per-dest-per-minute" => {
                self.flood.max_connects_per_dest_per_minute = int(key, v, 0, BIG)?;
            }
            "max-in-flight-syns" => self.flood.max_in_flight_syns = int(key, v, 0, BIG)?,
            "max-concurrent-connections" => {
                self.flood.max_concurrent_connections = int(key, v, 0, BIG)?;
            }
            "syn-signature" => self.flood.syn_signature_enabled = boolean(key, v)?,
            "syn-signature-window-ms" => {
                self.flood.syn_signature_window_ms = int(key, v, 1, 600_000)?;
            }
            "syn-signature-min-samples" => {
                self.flood.syn_signature_min_samples = int(key, v, 1, 256)?;
            }
            "syn-signature-failed-ratio" => {
                let r: f64 = v.parse().map_err(|_| bad_value(key, v))?;
                if !(0.0..=1.0).contains(&r) {
                    return Err(bad_value(key, v));
                }
                self.flood.syn_signature_failed_ratio = r;
            }
            "ws-close-after-violations" => {
                self.flood.ws_close_after_violations = int(key, v, 0, BIG)?;
            }
            "log-blocked-dials" => self.flood.log_blocked_dials = boolean(key, v)?,

            "reputation" => self.reputation_enabled = boolean(key, v)?,
            "reputation-store" => self.reputation.store_path = string(key, v)?,
            "reputation-save-interval-s" => {
                self.reputation.save_interval_s = int(key, v, 0, 86_400)?;
            }
            "reputation-decay-per-hour" => self.reputation.decay_per_hour = int(key, v, 0, 100)?,
            "reputation-evict-after-days" => {
                self.reputation.evict_after_days = int(key, v, 0, 3650)?;
            }
            "reputation-warn" => self.reputation.warn = int(key, v, 0, 100)?,
            "reputation-throttle" => self.reputation.throttle = int(key, v, 0, 100)?,
            "reputation-strict" => self.reputation.strict = int(key, v, 0, 100)?,
            "reputation-weight" => weight(key, v, &mut self.reputation.source_weights)?,
            "reputation-dest-weight" => weight(key, v, &mut self.reputation.dest_weights)?,

            "proxy" => {
                self.proxy = if v.is_empty() {
                    None
                } else {
                    Some(
                        v.parse()
                            .map_err(|e| format!("bad value for 'proxy': {e}"))?,
                    )
                };
            }
            "proxy-udp" => {
                self.proxy_udp_direct = match v {
                    "direct" => true,
                    "refuse" => false,
                    _ => return Err(bad_value(key, v)),
                };
            }
            "dns-server" => {
                if self.dns_servers.len() >= MAX_DNS_SERVERS {
                    return Err("too many dns-server entries".into());
                }
                if v.is_empty() || v.len() >= 64 {
                    return Err(bad_value(key, v));
                }
                self.dns_servers.push(v.to_string());
            }
            "dns-ttl-s" => self.dns_ttl_s = int(key, v, 0, 604_800)?,
            "dns-negative-ttl-s" => self.dns_negative_ttl_s = int(key, v, 0, 604_800)?,
            "dns-order" => {
                self.dns_order = match v {
                    "ipv4first" => DnsOrder::Ipv4First,
                    "ipv6first" => DnsOrder::Ipv6First,
                    "verbatim" => DnsOrder::Verbatim,
                    _ => return Err(bad_value(key, v)),
                };
            }
            "dns-timeout-ms" => self.dns_timeout_ms = int(key, v, 100, 60_000)?,

            "max-message-size" => self.max_message_size = int(key, v, 1024, 1 << 30)?,
            "ws-write-high-water" => self.ws_write_high_water = int(key, v, 4096, 1 << 31)?,
            "stream-queue-max" => self.stream_queue_max = int(key, v, 4096, 1 << 31)?,
            "socket-buffer-size" => self.socket_buffer_size = int(key, v, 0, 1 << 30)?,
            "connect-timeout-ms" => self.connect_timeout_ms = int(key, v, 100, 600_000)?,
            "handshake-timeout-ms" => self.handshake_timeout_ms = int(key, v, 100, 600_000)?,
            "resolver-threads" => self.resolver_threads = int(key, v, 1, 256)?,
            "tcp-nodelay" => self.tcp_nodelay = boolean(key, v)?,
            "tcp-quickack" => self.tcp_quickack = boolean(key, v)?,
            "listen-backlog" => self.listen_backlog = int(key, v, 1, 65_535)?,
            "non-ws-response" => self.non_ws_response = string(key, v)?,
            "serve-webclient" => self.serve_webclient = boolean(key, v)?,
            "webclient-wisp-url" => self.webclient_wisp_url = string(key, v)?,
            _ => return Err(format!("unknown option '{key}'")),
        }
        Ok(())
    }

    /// Apply a config file's text. `origin` is used in error messages (`origin:line: ...`).
    pub fn load_text(&mut self, origin: &str, text: &str) -> Result<(), String> {
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim_matches([' ', '\t', '\r', '\n']);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = |msg: String| format!("{origin}:{}: {msg}", i + 1);
            let (key, rest) = line
                .split_once('=')
                .ok_or_else(|| at("expected key = value".into()))?;
            let value = file_value(rest.trim_matches([' ', '\t']));
            self.set(key.trim_matches([' ', '\t']), &value)
                .map_err(at)?;
        }
        Ok(())
    }
}

fn bad_value(key: &str, v: &str) -> String {
    format!("bad value '{v}' for '{key}'")
}

/// A value from a config line: quoted text is kept verbatim up to the closing quote, anything
/// else loses an inline `# comment` (a `#` that starts the value or follows whitespace).
fn file_value(raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return rest[..end].to_string();
        }
        return raw.to_string();
    }
    let bytes = raw.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
            return raw[..i].trim_matches([' ', '\t']).to_string();
        }
    }
    raw.to_string()
}

/// What the command line asked for.
#[derive(Debug, PartialEq)]
pub enum Parsed {
    Run(Box<Config>),
    Help,
    Version,
}

pub const USAGE: &str = "\
usage: holywisp [--config FILE] [--KEY VALUE | --KEY=VALUE]...

A Wisp v1/v2 server. Every KEY is also a `KEY = VALUE` line in the config file; flags win.
See holywisp.conf.example for every key, its default and its range.

  --config FILE, -c FILE    read this config file (first, so flags override it)
  --help, -h                show this text
  --version, -V             show the version
";

/// Parse `args` (without the program name). `read_file` loads a config file's text, so tests
/// need no file system.
pub fn parse_args<S, F>(args: &[S], read_file: F) -> Result<Parsed, String>
where
    S: AsRef<str>,
    F: Fn(&str) -> io::Result<String>,
{
    let args: Vec<&str> = args.iter().map(AsRef::as_ref).collect();
    let mut cfg = Config::default();

    // First pass: --config, so flags given alongside it override the file whatever the order.
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        let path = if a == "--config" || a == "-c" {
            i += 1;
            Some(*args.get(i).ok_or("--config needs a path")?)
        } else {
            a.strip_prefix("--config=")
        };
        if let Some(path) = path {
            let text = read_file(path).map_err(|e| format!("{path}: {e}"))?;
            cfg.load_text(path, &text)?;
        }
        i += 1;
    }

    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        match a {
            "--help" | "-h" => return Ok(Parsed::Help),
            "--version" | "-V" => return Ok(Parsed::Version),
            "--config" | "-c" => {
                i += 2;
                continue;
            }
            _ if a.starts_with("--config=") => {
                i += 1;
                continue;
            }
            _ => {}
        }
        let flag = a
            .strip_prefix("--")
            .ok_or_else(|| format!("unexpected argument '{a}'"))?;
        if flag.len() >= 64 {
            return Err(format!("option too long: {a}"));
        }
        if let Some((key, value)) = flag.split_once('=') {
            cfg.set(key, value)?;
        } else {
            // A boolean flag may stand alone: `--allow-loopback` means true.
            match args.get(i + 1) {
                Some(next) if !next.starts_with("--") => {
                    cfg.set(flag, next)?;
                    i += 1;
                }
                _ => cfg.set(flag, "true")?,
            }
        }
        i += 1;
    }
    Ok(Parsed::Run(Box::new(cfg)))
}

#[cfg(test)]
mod tests;
