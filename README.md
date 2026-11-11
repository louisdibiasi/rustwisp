# rustwisp

A Wisp server written in Rust. Wisp is a small protocol that lets a browser (or any WebSocket client) open TCP and UDP connections through a server. This project is a rewrite of [Fracital/holyWisp](https://github.com/Fracital/holyWisp), the C11 server by David Reed, with the same protocol support and the same `holywisp.conf` keys. It is a separate project and does not send anything back upstream.

It speaks Wisp v1 and v2, so existing clients such as wisp-js and the browser client that ships with holyWisp work against it unchanged.

## What you get

- `rustwisp`, the server. One epoll loop per worker thread, `SO_REUSEPORT`, per-stream flow control, `/health` and `/stats`, and the built-in browser client on `GET /`.
- `rustwisp-cli`, a netcat that goes through a Wisp server.
- A one-file browser client (`web/index.html`). The server serves it on `GET /`, and it can be published as a static page that works with any Wisp server.
- `rustwisp-bench`, a benchmark tool that compares servers on speed, latency and CPU cost per byte.
- `rustwisp-client`, the Rust library behind the CLI, if you want to talk to a Wisp server from your own program.
- Egress rules that deny by default: no loopback, private ranges or literal IPs unless you turn them on, and the check runs on the addresses a name resolves to, not just the name.
- Flood protection, per-IP limits, bandwidth pacing and an IP reputation store, all on by default and configurable.
- Optional upstream proxy (SOCKS5 or HTTP CONNECT) for outbound TCP, and hashed passwords checked off the event loop.
- Your own DNS servers (with fail-over) instead of the system resolver, log levels with timestamps, and optional Twisp terminal streams.

## Quick start

You need Linux and a recent stable Rust (1.88 or newer).

```sh
cargo build --release
./target/release/rustwisp --port 6001
```

Open `http://localhost:6001/` for the built-in client, or point any Wisp client at `ws://localhost:6001/`. The same client page is published at [louisdibiasi.is-a.dev/rustwisp](https://louisdibiasi.is-a.dev/rustwisp/); it works with any Wisp server.

By default the server refuses to connect to loopback and private addresses, so a test against a service on your own machine needs `--allow-loopback --allow-direct-ip` (or use a hostname).

Try the CLI against a running server:

```sh
printf 'GET / HTTP/1.0\r\n\r\n' | ./target/release/rustwisp-cli ws://localhost:6001/ example.com 80
```

The [guide](docs/GUIDE.md) covers configuration, deployment behind a reverse proxy, the systemd unit, the client library and troubleshooting.

## Speed

The C server already uses epoll well, so switching language buys little by itself. Most of the speed-up comes from two changes. On the way from the remote server back to the client, payload bytes go through `splice` instead of being copied in user space. On the way in, several DATA frames for one stream leave in a single `sendmsg`, large frames are forwarded while they are still arriving, and the per-stream flow-control window is the full 128 packets by default.

Measured with the `rustwisp-bench` tool in this repo (i7-13700KF, WSL2, loopback, median of five 5-second runs, the C server as the baseline):

| Scenario | C | Rust | Rust vs C | Per CPU-second |
| --- | --- | --- | --- | --- |
| 1 stream, MiB/s | 1749 | 2559 | 1.46x | 1.88x |
| 10 streams | 1882 | 1931 | 1.03x | 1.14x |
| 10 streams, 1 MiB packets | 1829 | 2953 | 1.61x | 1.68x |
| 8 connections x 4 streams | 6385 | 7942 | 1.24x | 1.56x |
| 16 connections x 4 streams | 6918 | 7920 | 1.14x | 1.44x |
| Round trip, 64 bytes (p50) | 53.9 us | 54.6 us | same | |
| Stream churn, per second | 7421 | 7573 | same | |

"Per CPU-second" is megabytes moved for each second of CPU the server used, which matters more than the raw rate when the machine has other work to do. The Rust server also holds more memory under load than the C one (about 13 MiB against 3 MiB with one busy stream, 106 MiB against 68 MiB with 16 connections), because it queues more per stream.

Take these as rough numbers. Loopback inside WSL is not a real network, runs differ by about 8 percent either way, and I have not repeated them on bare metal yet. The load generator matters too. The C project's own pump, which sends from a separate process, gives larger ratios for one and for ten streams (about 1.7 to 1.8x in the last run), but only about 1.1x for ten streams with 1 MiB packets, where `rustwisp-bench` shows 1.6x. I traced that gap to how each generator drains and backs off, not to the server, and widening the flow-control window alone did not close it. Run `rustwisp-bench` yourself to check on your hardware; the [guide](docs/GUIDE.md#benchmarking) shows how.

## Limits

- Twisp (terminal streams) is a build-time feature and is off by default. Build with `--features twisp`, then set `enable-twisp = on`; it also needs Wisp v2 and a logged-in client. It runs programs on the server as the user the server runs as, with no sandbox, so read the [guide section](docs/GUIDE.md#terminal-streams-twisp) before turning it on. The release tarball does not include it.
- `password-user` accepts plain text and bcrypt, SHA-256 and SHA-512 hashes. yescrypt (`$y$`) and MD5 are refused at startup.
- The server has no config reload. Restart it to apply changes.
- TLS is not built in. Run it behind nginx, Caddy or similar for `wss://`.

## Compatibility

The wire format follows the [Wisp protocol](https://github.com/MercuryWorkshop/wisp-protocol). The v2 password extension is read in both the layout the specification gives and the one the C server uses. A test replays the same scripted sessions against the C server and this one and checks that the transcripts match. It is stricter than the C server in a few places: an upgrade request with malformed headers gets a 400 where the C server answers 101, and an invalid WebSocket close code gets 1002 where the C server echoes it.

## Building and testing

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The protocol, config and client crates build and test on any platform. The server itself is Linux-only.

## License

ISC. The original copyright belongs to David Reed; see [LICENSE](LICENSE).
