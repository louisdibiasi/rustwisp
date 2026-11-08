# holyWisp-rust guide

This guide covers building the server, running it, configuring it, putting it on a real machine, and using the client library. For a short overview start with the [README](../README.md).

## Contents

1. [Build](#build)
2. [Run](#run)
3. [Configuration](#configuration)
4. [What clients are allowed to reach](#what-clients-are-allowed-to-reach)
5. [Passwords](#passwords)
6. [Sending traffic through another proxy](#sending-traffic-through-another-proxy)
7. [Behind a reverse proxy](#behind-a-reverse-proxy)
8. [Running under systemd](#running-under-systemd)
9. [Health and stats](#health-and-stats)
10. [The command line client](#the-command-line-client)
11. [Using the library](#using-the-library)
12. [Close reasons](#close-reasons)
13. [Troubleshooting](#troubleshooting)
14. [Working on the code](#working-on-the-code)

## Build

You need a Linux machine and Rust 1.88 or newer (install it with [rustup](https://rustup.rs)).

```sh
cargo build --release
```

That produces `target/release/holywisp` (the server) and `target/release/holywisp-cli` (the client tool). The release profile uses fat LTO and a single codegen unit, so the first build takes a little while.

To make a tarball with both binaries, the example config and the systemd files, run `deploy/make-release.sh`. It writes the archive and a sha256 checksum to `dist/`.

## Run

```sh
holywisp                       # defaults: all interfaces, port 6001
holywisp --port 7000
holywisp --config /etc/holywisp/holywisp.conf
holywisp --help
```

Press Ctrl-C or send SIGTERM to stop it. Open connections are dropped and the reputation store is saved on the way out.

The server listens on one port for everything. A plain HTTP request gets the built-in browser client (or a one-line text reply if you turn that off), and a WebSocket upgrade starts a Wisp session.

## Configuration

Settings come from a config file, from command line flags, or both. Every key in the file is also a flag with two dashes in front: `port = 7000` in the file is `--port 7000` on the command line. When both set the same key, the flag wins, whatever order they appear in.

The file is plain `key = value` lines. A `#` starts a comment. Booleans accept `on`/`off`, `true`/`false`, `yes`/`no` and `1`/`0`. Keys that make lists (`allow-host`, `allow-port`, `trusted-proxy` and a few more) are repeated, one value per line. Wrap a value in double quotes if it contains spaces.

[`holywisp.conf.example`](../holywisp.conf.example) lists every key with its default and a note. The ones you will touch most:

| Key | Default | What it does |
| --- | --- | --- |
| `host`, `port` | all interfaces, `6001` | Where to listen. |
| `workers` | `0` (one per CPU) | Number of worker threads. |
| `allow-tcp`, `allow-udp` | on | Which stream types clients may open. |
| `allow-direct-ip` | off | Let clients connect to a literal IP instead of a name. |
| `allow-private`, `allow-loopback`, `allow-link-local` | off | Let clients reach those address ranges. |
| `allow-host`, `block-host` | empty | Host allow and block lists. `*.example.com` matches subdomains. |
| `allow-port`, `block-port` | empty | Port allow and block lists. `6000-6100` is a range. |
| `enable-v2` | on | Offer Wisp v2 to clients that ask for it. |
| `motd` | empty | Message of the day, sent to v2 clients. |
| `connections-limit-per-ip` | 200 | New WebSockets per IP per window. |
| `serve-webclient` | on | Serve the browser client on `GET /`. |

The server checks the config at startup and refuses to run if a value is out of range, with the file and line in the message. There is no reload: restart to apply changes.

## What clients are allowed to reach

A Wisp server is an open door to whatever network it runs on, so the defaults are strict.

- Loopback, private ranges (RFC 1918, carrier-grade NAT, `fc00::/7`) and link-local addresses are blocked.
- Literal IP addresses in a connect request are refused. Clients must send a hostname, and the server checks every address that name resolves to. A hostname that points at `127.0.0.1` is blocked just the same.
- `allow-host` turns the host list into an allowlist: once you set one entry, only matching names pass.

If you run the server for people you do not know, leave all of that alone. If you run it for yourself on a home network and want to reach a machine on the LAN, set `allow-private = on`, ideally together with an `allow-host` list so it is not open to everything on the LAN.

Flood protection, per-IP connection limits and the reputation store add a second layer. They are on by default and the thresholds are in the example config.

## Passwords

To require a login, set `password-required = on` and add users:

```
password-required = on
password-user = alice:correct horse
```

Only Wisp v2 clients can log in. A plain-text entry means the config file holds the password, so keep it readable only by the account that runs the server. Better, store a hash instead. These are accepted:

| Prefix | Scheme | Make one with |
| --- | --- | --- |
| `$2b$` (also `$2a$`, `$2x$`, `$2y$`) | bcrypt | `htpasswd -nbB -C 12 alice 'password'` (the part after the colon) |
| `$5$` | SHA-256 crypt | `mkpasswd -m sha-256` |
| `$6$` | SHA-512 crypt | `mkpasswd -m sha-512` |

```
password-user = alice:$2b$12$...your hash...
```

yescrypt (`$y$`) and MD5 (`$1$`) are not supported, and the server refuses to start with one in the config, naming the user, so nobody gets locked out by surprise.

Checking a hash is slow on purpose, so it runs on two helper threads and not on the connection's own thread. A bounded queue sits in front of them: if more than 64 checks are waiting, new logins are refused until it drains. A name that does not exist costs the same time as a wrong password, so response time does not reveal who has an account.

## Sending traffic through another proxy

If the server itself should reach the internet through a SOCKS5 or HTTP proxy (a VPN gateway, Tor, a corporate proxy), set `proxy`:

```
proxy = socks5://127.0.0.1:1080
# proxy = socks5://user:pass@host:1080     (special characters in the login as %40 and so on)
# proxy = http://host:3128                 (uses CONNECT)
```

Every outbound TCP stream then goes to the proxy, which makes the last hop. The destination name is resolved and checked against your rules here first, and the proxy is told to connect to the address that passed. It never sees the name, so it cannot be pointed somewhere your rules forbid by a name that resolves differently on its side.

Some setups want the proxy to see the name, for example to route by domain. Set `proxy-send-hostnames = on` for that. The proxy then resolves the name itself, and your address checks no longer bind it, so only do this if the proxy enforces its own egress rules.

UDP cannot go through these proxies. By default UDP streams are refused. `proxy-udp = direct` sends them straight out instead, bypassing the proxy, which may not be what you want if the proxy is there to hide the server's address.

The proxy's own address is resolved once at startup; the server will not start if it cannot. `https://` proxies (TLS to the proxy) are not supported. A failed proxy handshake closes the stream with the matching reason: refused, blocked, unreachable or timed out.

## Behind a reverse proxy

The server does not do TLS. For `wss://`, put nginx, Caddy or similar in front of it and let that handle the certificate.

The proxy has to pass WebSocket upgrades through. It also has to tell the server who the real client is, otherwise every client looks like the proxy and they all share one set of limits. List the proxy in `trusted-proxy`, and make sure it overwrites the header the server reads.

An nginx location that does both:

```nginx
location /wisp/ {
    proxy_pass http://127.0.0.1:6001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 1h;
}
```

with this in `holywisp.conf`:

```
host = 127.0.0.1
trusted-proxy = 127.0.0.1
trusted-header = X-Forwarded-For
```

The server only reads those headers from addresses listed in `trusted-proxy`, so a client cannot fake its address by sending the header itself. The default `trusted-header` list has `CF-Connecting-IP` first. If your proxy is not Cloudflare, reset the list with `trusted-headers-reset = x` and add only the header your proxy sets.

## Running under systemd

The tarball from `deploy/make-release.sh` contains a hardened unit file. It runs the server as a dedicated `wisp` user with no capabilities, a read-only filesystem apart from `/var/lib/holywisp`, a restricted set of system calls and only IPv4 and IPv6 sockets. To install it:

```sh
sudo install -m 755 holywisp holywisp-cli /usr/bin/
sudo install -D -m 644 systemd/holywisp.service /etc/systemd/system/holywisp.service
sudo install -D -m 644 systemd/holywisp.sysusers /usr/lib/sysusers.d/holywisp.conf
sudo install -D -m 644 systemd/holywisp.tmpfiles /usr/lib/tmpfiles.d/holywisp.conf
sudo systemd-sysusers
sudo systemd-tmpfiles --create
sudo install -m 640 -g wisp holywisp.conf /etc/holywisp/holywisp.conf
sudo systemctl enable --now holywisp
```

The shipped `holywisp.conf` binds to `127.0.0.1`, which is what you want behind a proxy. Change `host` if the server should be reachable directly. To listen on a port below 1024, the comments in the unit explain the two lines to change.

Check it with `systemctl status holywisp` and `journalctl -u holywisp`.

## Health and stats

`GET /health` returns `{"status":"ok"}`, good for a load balancer check. `GET /stats` returns counters as JSON: uptime, connections, streams, bytes in and out, and how many attempts were refused, blocked or throttled.

Both are plain HTTP on the same port. If the server is reachable from the internet, think about whether you want `/stats` public; the simplest answer is to block that path in the reverse proxy.

## The command line client

```
holywisp-cli [options] WS_URL HOST PORT
```

It reads standard input, sends it to HOST:PORT through the server at WS_URL, and writes the reply to standard output.

```sh
printf 'GET / HTTP/1.0\r\n\r\n' | holywisp-cli ws://localhost:6001/ example.com 80
holywisp-cli --udp ws://localhost:6001/ one.one.one.one 53 < query.bin > reply.bin
holywisp-cli --user alice --pass 'correct horse' ws://host:6001/ example.com 22
```

Options: `--udp` opens a UDP stream, `--v1` uses plain Wisp v1, `--user` and `--pass` supply a login, and `--wait SECS` sets how long to wait for more output once standard input ends (default 3). Only `ws://` is supported. For `wss://` servers, connect through a local TLS-aware tunnel.

The exit status is 0 for a normal finish, 1 if the connection failed or the server closed the stream with an error, and 2 for a bad command line.

## Using the library

Add the crate by path or git, then:

```rust
use holywisp_client::{connect, Event, Options};
use std::io;

fn main() -> io::Result<()> {
    let (handle, mut reader) = connect("ws://localhost:6001/", &Options::default())?;
    let stream = handle.open_tcp("example.com", 80)?;
    handle.send(stream, b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")?;

    while let Ok(event) = reader.next_event() {
        match event {
            Event::Data { data, .. } => print!("{}", String::from_utf8_lossy(&data)),
            Event::Close { .. } => break,
            Event::Continue { .. } => {}
        }
    }
    Ok(())
}
```

`connect` gives you two halves. The `Handle` opens and closes streams and sends data. It can be cloned and used from several threads. The `Reader` returns what the server sends and should be read from one thread. `Handle::send` waits when the server has not granted more credit, so a slow remote slows the sender instead of using up memory.

## Close reasons

When a stream ends, the server says why with one byte.

| Code | Meaning |
| --- | --- |
| `0x02` | Closed normally. |
| `0x03` | Network error. |
| `0x41` | Invalid request (bad host or port). |
| `0x42` | Destination unreachable (DNS failure or no route). |
| `0x43` | Destination did not answer in time. |
| `0x44` | Destination refused the connection. |
| `0x47` | Transfer timed out. |
| `0x48` | Blocked by the server's rules. |
| `0x49` | Too much data queued; slow down. |
| `0x81` | The client broke the protocol. |
| `0xc0`, `0xc1`, `0xc2` | Wrong password, bad signature, login required. |

## Troubleshooting

**Every stream closes with `0x48`.** The server's rules are blocking the destination. The usual causes are a literal IP address (set `allow-direct-ip = on` or use a hostname) and a target on loopback or the LAN (`allow-loopback`, `allow-private`). When testing, run `holywisp --allow-loopback --allow-direct-ip`.

**`0x42` on a name that works elsewhere.** The server resolves names itself. Check that the machine running it can resolve the name, and that `dns-order` suits your network (`ipv6first` or `verbatim` if you have IPv6 only).

**Connections work for a while, then clients get refused.** You have probably hit `connections-limit-per-ip`, or every client looks like the same IP because the proxy's address is not listed in `trusted-proxy`.

**The WebSocket upgrade fails behind nginx.** Check for the `Upgrade` and `Connection` headers and `proxy_http_version 1.1`.

**The server will not start and prints a config error.** The message names the file and line. Fix that line and try again.

## Working on the code

The workspace has four crates:

- `holywisp-proto`: Wisp packets, WebSocket frame headers, the HTTP upgrade parser and the SIMD unmask routine. No I/O, so it is easy to test.
- `holywisp-config`: the config file and flags.
- `holywisp`: the server.
- `holywisp-client`: the client library and `holywisp-cli`.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Unsafe code is denied across the workspace. The two places that need it, the SIMD unmask and the thin Linux system-call layer, say why next to each block.

The server is Linux-only because it uses epoll and splice directly. On Windows you can build and test the other crates; for the server, use WSL.
