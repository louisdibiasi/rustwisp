# rustwisp guide

This guide covers building the server, running it, configuring it, putting it on a real machine, and using the client library. For a short overview start with the [README](../README.md).

## Contents

1. [Build](#build)
2. [Run](#run)
3. [Configuration](#configuration)
4. [What clients are allowed to reach](#what-clients-are-allowed-to-reach)
5. [Passwords](#passwords)
6. [Sending traffic through another proxy](#sending-traffic-through-another-proxy)
7. [DNS servers](#dns-servers)
8. [Logging](#logging)
9. [Terminal streams (Twisp)](#terminal-streams-twisp)
10. [Behind a reverse proxy](#behind-a-reverse-proxy)
11. [Running under systemd](#running-under-systemd)
12. [Health and stats](#health-and-stats)
13. [The web client](#the-web-client)
14. [The command line client](#the-command-line-client)
15. [Using the library](#using-the-library)
16. [Close reasons](#close-reasons)
17. [Troubleshooting](#troubleshooting)
18. [Benchmarking](#benchmarking)
19. [Working on the code](#working-on-the-code)

## Build

You need a Linux machine and Rust 1.88 or newer (install it with [rustup](https://rustup.rs)).

```sh
cargo build --release
```

That produces `target/release/rustwisp` (the server) and `target/release/rustwisp-cli` (the client tool). The release profile uses fat LTO and a single codegen unit, so the first build takes a little while.

To make a tarball with both binaries, the example config and the systemd files, run `deploy/make-release.sh`. It writes the archive and a sha256 checksum to `dist/`.

## Run

```sh
rustwisp                       # defaults: all interfaces, port 6001
rustwisp --port 7000
rustwisp --config /etc/rustwisp/rustwisp.conf
rustwisp --help
```

Press Ctrl-C or send SIGTERM to stop it. Open connections are dropped and the reputation store is saved on the way out. If a parent process starts the server and holds a pipe to its standard input, `stop-on-stdin-eof = on` makes the server stop when that pipe closes; it is off by default.

The server listens on one port for everything. A plain HTTP request gets the built-in browser client (or a one-line text reply if you turn that off), and a WebSocket upgrade starts a Wisp session.

## Configuration

Settings come from a config file, from command line flags, or both. Every key in the file is also a flag with two dashes in front: `port = 7000` in the file is `--port 7000` on the command line. When both set the same key, the flag wins, whatever order they appear in.

The file is plain `key = value` lines. A `#` starts a comment. Booleans accept `on`/`off`, `true`/`false`, `yes`/`no` and `1`/`0`. Keys that make lists (`allow-host`, `allow-port`, `trusted-proxy` and a few more) are repeated, one value per line. Wrap a value in double quotes if it contains spaces.

[`rustwisp.conf.example`](../rustwisp.conf.example) lists every key with its default and a note. The ones you will touch most:

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
| `connections-limit-per-ip` | 200 | New WebSockets per IP per window. Over the limit a client gets a 429 with `Retry-After` set to `connection-window-s`, in seconds. |
| `log-level` | `info` | How much the server writes to stderr. See [Logging](#logging). |
| `dns-server` | empty | Resolve names with your own DNS servers. See [DNS servers](#dns-servers). |
| `enable-twisp` | off | Terminal streams. Needs a special build; see [Terminal streams](#terminal-streams-twisp). |
| `serve-webclient` | on | Serve the browser client on `GET /`. |
| `stream-queue-max` | 134217728 | Bytes one stream may have queued toward its remote (4096 to 2147483648). |
| `conn-queue-max` | 268435456 | Bytes one client may have queued across all its streams (4096 to 2147483648, at least `stream-queue-max`). |
| `client-recv-buffer` | 8388608 | Receive buffer asked for on client sockets (0 to 1073741824; 0 leaves it to the kernel). |
| `busy-poll-us` | 0 | Microseconds a worker keeps polling after a busy loop pass before it sleeps (0 to 10000). |

The server checks the config at startup and refuses to run if a value is out of range, with the file and line in the message. There is no reload: restart to apply changes.

### Flow control and memory

Each stream has a window of packets the client may have in flight. With the defaults the window is the full 128 packets, because a full window of maximum-size packets fits in `stream-queue-max`. When a stream's remote is slow, the server hands out new credit as the queue drains, and it shares the credit between a connection's streams. A client that keeps sending past its window, and fills a stream's queue, is closed with `0x49`.

`conn-queue-max` is the limit for one client across all its streams. When it is crossed the server stops reading from that client until the remotes catch up, and closes nothing, so a client with many stalled streams costs bounded memory. The check runs per frame, so the total can pass the limit by at most the frame being read. A separate hard cap on what is queued toward the client itself stays in force.

None of this is a limit on the whole process. Allocator overhead and kernel socket buffers come on top, so size the machine for the number of busy clients you expect times `conn-queue-max`, not for a single number.

`client-recv-buffer` is only applied when `socket-buffer-size` is 0 and the kernel allows at least 4 MiB (`net.core.rmem_max` of 2097152 or more, since the kernel doubles the value). Otherwise the kernel's own tuning is left alone. `busy-poll-us` trades CPU for round-trip time; 50 is a reasonable first value if you want it.


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

Checking a hash is slow on purpose, so it runs on two helper threads and not on the connection's own thread. A bounded queue sits in front of them: if more than 64 checks are waiting, new logins are refused until it drains. All accounts must use plain text or one hash scheme, variant, cost and salt length; mixed configurations are refused at startup because they expose account types through login timing. For hashed accounts, an unknown name still costs one verification using the configured profile. This does not guarantee identical response times.

## Sending traffic through another proxy

If the server itself should reach the internet through a SOCKS5 or HTTP proxy (a VPN gateway, Tor, a corporate proxy), set `proxy`:

```
proxy = socks5://127.0.0.1:1080
# proxy = socks5://user:pass@host:1080     (special characters in the login as %40 and so on)
# proxy = http://host:3128                 (uses CONNECT)
```

Every outbound TCP stream then goes to the proxy, which makes the last hop. The destination name is resolved and checked against your rules here first, and the proxy is told to connect to the address that passed. It never sees the name, so it cannot be pointed somewhere your rules forbid by a name that resolves differently on its side.

Some setups want the proxy to see the name, for example to route by domain. Set `proxy-send-hostnames = on` for that. The proxy then resolves the name itself, and your address checks no longer bind it, so only do this if the proxy enforces its own egress rules. A name that looks public from here can still be sent by the proxy to a loopback or LAN address.

UDP cannot go through these proxies. By default UDP streams are refused. `proxy-udp = direct` sends them straight out instead, bypassing the proxy, which may not be what you want if the proxy is there to hide the server's address.

The proxy's own address is resolved once at startup; the server will not start if it cannot. `https://` proxies (TLS to the proxy) are not supported. A failed proxy handshake closes the stream with the matching reason: refused, blocked, unreachable or timed out.

## DNS servers

By default the server resolves names with the system resolver. To use specific servers instead, list them, one per line (up to eight):

```
dns-server = 1.1.1.1
dns-server = [2606:4700:4700::1111]:53
```

The port is optional and defaults to 53. The servers are asked in the order you list them. Each one gets `dns-timeout-ms` (3000 by default) to answer a question; if it stays silent, sends garbage or answers with an error, the next one is tried. If both questions come back as "no such name", that is the answer and no other server is asked. The server asks for both the A and AAAA records over plain UDP and orders the result by `dns-order`. An answer that came back truncated counts as a failure, since there is no TCP fallback.

Answers are cached for their own TTL, bounded by `dns-ttl-s`, and failures for `dns-negative-ttl-s`; set either to 0 to turn that cache off. The egress rules (see [What clients are allowed to reach](#what-clients-are-allowed-to-reach)) are applied to the addresses that come back, and the connection goes to the address that passed. An answer with a TTL of 0 is cached for `dns-ttl-s`. The cache holds at most 4096 names, and when 256 lookups are already waiting, new ones are refused.

Replies are accepted only from the server that was asked, on a fresh socket with a random source port and a random ID, and only when the question section matches. Nothing here makes plain DNS safe against someone who can see your traffic, so point it at a resolver on a network you trust.

## Logging

The server writes one line per event to stderr, which systemd sends to the journal. Logging is best effort: lines go through a bounded queue to a separate writer, so a stuck stderr cannot stall a connection. If the queue fills up, lines are dropped, and on exit the server waits at most 100 ms for what is still queued.

```
2026-11-08T12:00:00.123Z [info] server: listening on 0.0.0.0:6001 with 4 workers
```

`log-level` picks what is written: `debug`, `info` (the default), `warn`, `error` or `none`. `info` covers startup, shutdown and the events worth noticing; `debug` adds a line for each connection accepted and closed, which is a lot on a busy server. Control characters in anything that came from a client are replaced with spaces, and passwords and request headers are never logged. Login names are not logged in normal use; a config error about a password hash the server does not support does name the entry it found.

`log-blocked-dials = on` adds an `info` line each time an outbound connection the server tried to make fails. Destinations the egress rules refuse have their own `info` lines whether or not this is on. It is off by default because a scanner can produce a lot of failed dials.

## Terminal streams (Twisp)

Twisp lets a Wisp v2 client open a stream that is a terminal on the server instead of a network connection. The client sends a stream of type `0x03` whose host field is the command to run. The server starts that command on a pseudo-terminal, passes bytes both ways, and closes the stream when the program exits or the client does. A packet of type `0xF0` with four bytes (rows, then columns, each a 16-bit little-endian number) resizes the terminal.

This runs programs on your machine on behalf of whoever can log in, so it is off twice over:

1. It is a build-time feature. Build with `cargo build --release --features twisp`. The release tarball does not include it, and a server built without it refuses every terminal stream.
2. It needs `enable-twisp = on`, Wisp v2, and a client that has logged in with one of the `password-user` entries. A terminal request from a client that has finished the opening exchange without meeting these is refused with close reason `0x48` and counts against its reputation. Anything sent before that exchange completes is ignored. No command is started in either case.

What to know before you turn it on:

- The command runs as the user the server runs as, with the same working directory and environment (plus `TERM=xterm-256color`). There is no sandbox and no privilege drop. Run the server as an unprivileged user, and think of the login as shell access.
- The command line is split like a shell would split quotes and backslashes, but no shell is involved: there is no globbing, piping or variable expansion. To get those, run `sh -c '...'` yourself.
- At most 32 terminals run at once per server. The ordinary connection limits apply as well.
- When a stream ends, the server sends `SIGHUP` to the program's process group and escalates after a second. A program that starts a daemon in a new session is out of that group and keeps running.
- A command that cannot start closes the stream with `0x03` straight away.
- Terminal output uses the same flow-control window and queue limit as network streams, so a client that stops reading does not make the server hold unbounded output.

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

with this in `rustwisp.conf`:

```
host = 127.0.0.1
trusted-proxy = 127.0.0.1
trusted-header = X-Forwarded-For
```

The server only reads those headers from addresses listed in `trusted-proxy`, so a client cannot fake its address by sending the header itself. The default `trusted-header` list has `CF-Connecting-IP` first. If your proxy is not Cloudflare, reset the list with `trusted-headers-reset = x` and add only the header your proxy sets.

## Running under systemd

The tarball from `deploy/make-release.sh` contains a hardened unit file. It runs the server as a dedicated `wisp` user with no capabilities, a read-only filesystem apart from `/var/lib/rustwisp`, a restricted set of system calls and only IPv4 and IPv6 sockets. To install it:

```sh
sudo install -m 755 rustwisp rustwisp-cli /usr/bin/
sudo install -D -m 644 systemd/rustwisp.service /etc/systemd/system/rustwisp.service
sudo install -D -m 644 systemd/rustwisp.sysusers /usr/lib/sysusers.d/rustwisp.conf
sudo install -D -m 644 systemd/rustwisp.tmpfiles /usr/lib/tmpfiles.d/rustwisp.conf
sudo systemd-sysusers
sudo systemd-tmpfiles --create
sudo install -m 640 -g wisp rustwisp.conf /etc/rustwisp/rustwisp.conf
sudo systemctl enable --now rustwisp
```

The shipped `rustwisp.conf` binds to `127.0.0.1`, which is what you want behind a proxy. Change `host` if the server should be reachable directly. To listen on a port below 1024, the comments in the unit explain the two lines to change.

Check it with `systemctl status rustwisp` and `journalctl -u rustwisp`.

## Health and stats

`GET /health` returns `{"status":"ok"}`, good for a load balancer check. `GET /stats` returns counters as JSON: uptime, connections, streams, bytes in and out, and how many attempts were refused, blocked or throttled.

Both are plain HTTP on the same port. If the server is reachable from the internet, think about whether you want `/stats` public; the simplest answer is to block that path in the reverse proxy.

## The web client

A small client lives in `web/index.html`: one file, no build step, nothing loaded from other sites. It does two jobs.

The server hands it out on `GET /`, and there it defaults to its own address, so opening `http://your-server:6001/` is enough to try the server from a browser. Set `serve-webclient = off` to turn that off, or `webclient-wisp-url` to make the page default to a different server.

The same file can also be published as a static page, for example on GitHub Pages, where it works with any Wisp server you give it. The repository has a workflow for that in `.github/workflows/pages.yml`; it publishes the `web/` folder whenever it changes. A page on Pages is served over HTTPS, so the browser will only let it talk to `wss://` servers (or `ws://localhost`). Put TLS in front of your server, as described under [Behind a reverse proxy](#behind-a-reverse-proxy).

What the page does: it connects with Wisp v1 or v2, shows the server's message of the day, logs in when the server asks for a password, and then either fetches an `http://` page through the server or sends raw text to any host and port. The protocol log shows every packet. **Copy link** puts the addresses into the page's URL fragment so a setup can be shared; the password is never saved or put in a link. Fields are remembered in the browser's local storage between visits.

It cannot do TLS, so it only fetches plain `http://` pages. That is a limit of running in a browser tab without a TLS library, not of the server.

## The command line client

```
rustwisp-cli [options] WS_URL HOST PORT
```

It reads standard input, sends it to HOST:PORT through the server at WS_URL, and writes the reply to standard output.

```sh
printf 'GET / HTTP/1.0\r\n\r\n' | rustwisp-cli ws://localhost:6001/ example.com 80
rustwisp-cli --udp ws://localhost:6001/ one.one.one.one 53 < query.bin > reply.bin
rustwisp-cli --user alice --pass 'correct horse' ws://host:6001/ example.com 22
```

Options: `--udp` opens a UDP stream, `--v1` uses plain Wisp v1, `--user` and `--pass` supply a login, and `--wait SECS` sets how long to wait for more output once standard input ends (default 3). Only `ws://` is supported. For `wss://` servers, connect through a local TLS-aware tunnel.

The exit status is 0 for a normal finish, 1 if the connection failed or the server closed the stream with an error, and 2 for a bad command line.

## Using the library

Add the crate by path or git, then:

```rust
use rustwisp_client::{connect, Event, Options};
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
| `0x49` | Too much data queued for one stream; slow down. Crossing `conn-queue-max` alone only pauses reading, it does not close anything. |
| `0x81` | The client broke the protocol. |
| `0xc0`, `0xc1`, `0xc2` | Wrong password, bad signature, login required. |

## Troubleshooting

**Every stream closes with `0x48`.** The server's rules are blocking the destination. The usual causes are a literal IP address (set `allow-direct-ip = on` or use a hostname) and a target on loopback or the LAN (`allow-loopback`, `allow-private`). When testing, run `rustwisp --allow-loopback --allow-direct-ip`.

**`0x42` on a name that works elsewhere.** The server resolves names itself. Check that the machine running it can resolve the name, that `dns-order` suits your network (`ipv6first` or `verbatim` if you have IPv6 only), and, if you set `dns-server`, that those servers are reachable over UDP and answer. Run with `--log-level debug` to see what the server is doing.

**Connections work for a while, then clients get refused.** You have probably hit `connections-limit-per-ip`, or every client looks like the same IP because the proxy's address is not listed in `trusted-proxy`.

**The WebSocket upgrade fails behind nginx.** Check for the `Upgrade` and `Connection` headers and `proxy_http_version 1.1`.

**The server will not start and prints a config error.** The message names the file and line. Fix that line and try again.

## Benchmarking

`rustwisp-bench` puts servers side by side and reports what each one costs. It starts the server, a small counting echo service and a load generator itself, and it reads the server's CPU time, peak memory and context switches from `/proc`, so it needs Linux. It only talks to servers over the network, which means any Wisp server that takes the same flags can be a contender, the C holyWisp included.

```sh
cargo build --release
target/release/rustwisp-bench run \
    --server c=/path/to/holywisp-c/build/release/holywisp \
    --server rust=target/release/rustwisp \
    --out results.tsv
```

The first `--server` is the baseline; the others are shown as a ratio against it. Each server gets `--port` and a set of flags that allow loopback targets and switch off the limiters, so the limits do not skew the result. Add your own options after the command, for example `--server rust4="target/release/rustwisp --workers 4"`.

The scenarios follow the upstream benchmark, so the numbers can be read next to its tables. `rustwisp-bench run --list` shows them:

| Scenario | What it does |
| --- | --- |
| `native-1`, `native-10` | One connection, 1 or 10 streams, kept full with 64 KiB packets. |
| `native-10-1m` | The same with 1 MiB packets. |
| `conns-8x4`, `conns-16x4` | 8 or 16 connections with 4 streams each. |
| `rtt-64` | One 64-byte message at a time; p50, p99, p99.9 and max round trip. |
| `churn` | Open a stream, echo a byte, close it, as fast as it goes. |

Throughput is counted by the echo service, not by the client, in the window after a 2 second warm-up. The table also shows the server's CPU seconds, MiB moved per CPU second, TCP segments and context switches per MiB, and peak memory. MiB per CPU second is the number that says how efficient a server is when the machine is busy with other things.

Useful options: `--scenarios native-1,rtt-64` runs part of the matrix, `--secs` and `--reps` set the length and the number of repetitions (the median is reported, with the range), and `--base-port` moves the ports. Repetitions are interleaved between servers, so slow drift in the machine hits all of them alike. To compare two saved runs, for example before and after a change:

```sh
rustwisp-bench compare before.tsv after.tsv
```

It prints the ratio for each headline number and marks anything within 8 percent as noise, which is about how much two runs of the same build differ here.

A few things to keep in mind. Everything runs on one machine, so the load generator and the echo service take CPU from the server; use the CPU-per-MiB columns, not only the raw rate. The load generator is a client like any other and tops out around 2 GiB/s on a single connection, so when two servers both land near that figure (the `native-10` row does), compare the CPU columns instead. Loopback skips most of the network stack, and under WSL it is not the kernel you would deploy on. Close other programs and repeat a result before you believe it. The churn scenario opens streams one after another on a single connection, so its rate is limited by round trips and will be lower than a pipelined test would show; it is meant for comparing servers, not for quoting.

## Working on the code

The workspace has five crates:

- `rustwisp-proto`: Wisp packets, WebSocket frame headers, the HTTP upgrade parser and the SIMD unmask routine. No I/O, so it is easy to test.
- `rustwisp-config`: the config file and flags.
- `rustwisp`: the server.
- `rustwisp-client`: the client library and `rustwisp-cli`.
- `rustwisp-bench`: the benchmark tool described above.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The code that reads bytes from the network is also fuzzed. The `fuzz/` folder holds libFuzzer targets for the WebSocket header, Wisp packets, the HTTP upgrade, the unmask routine (checked against a plain loop), the upstream proxy conversation, the config file and its small value types, the egress and client-address policy, and the client's address parser. It needs a nightly compiler and `cargo-fuzz`:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run ws_header seeds/ws_header -- -max_total_time=60
```

The seeds in `fuzz/seeds/` give each target something realistic to start from. A crash is saved under `fuzz/artifacts/` and can be replayed with `cargo +nightly fuzz run <target> <file>`. The targets assert more than "does not panic": a header that parses must write back out and parse the same, a CONNECT must rebuild into the same bytes, and a request cannot make the server's reply carry extra header lines.

Unsafe code is denied across the workspace. The two places that need it, the SIMD unmask and the thin Linux system-call layer, say why next to each block.

The server is Linux-only because it uses epoll and splice directly. On Windows you can build and test the other crates; for the server, use WSL.
