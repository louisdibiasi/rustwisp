# holyWisp-rust

A Wisp server written in Rust. Wisp is a small protocol that lets a browser (or any WebSocket client) open TCP and UDP connections through a server. This project is a rewrite of [Fracital/holyWisp](https://github.com/Fracital/holyWisp), the C11 server by David Reed, with the same protocol support and the same `holywisp.conf` keys. It is a separate project and does not send anything back upstream.

It speaks Wisp v1 and v2, so existing clients such as wisp-js and the browser client that ships with holyWisp work against it unchanged.

## What you get

- `holywisp`, the server. One epoll loop per worker thread, `SO_REUSEPORT`, per-stream flow control, `/health` and `/stats`, and the built-in browser client on `GET /`.
- `holywisp-cli`, a netcat that goes through a Wisp server.
- `holywisp-client`, the Rust library behind the CLI, if you want to talk to a Wisp server from your own program.
- Egress rules that deny by default: no loopback, private ranges or literal IPs unless you turn them on, and the check runs on the addresses a name resolves to, not just the name.
- Flood protection, per-IP limits, bandwidth pacing and an IP reputation store, all on by default and configurable.

## Quick start

You need Linux and a recent stable Rust (1.88 or newer).

```sh
cargo build --release
./target/release/holywisp --port 6001
```

Open `http://localhost:6001/` for the built-in client, or point any Wisp client at `ws://localhost:6001/`.

By default the server refuses to connect to loopback and private addresses, so a test against a service on your own machine needs `--allow-loopback --allow-direct-ip` (or use a hostname).

Try the CLI against a running server:

```sh
printf 'GET / HTTP/1.0\r\n\r\n' | ./target/release/holywisp-cli ws://localhost:6001/ example.com 80
```

The [guide](docs/GUIDE.md) covers configuration, deployment behind a reverse proxy, the systemd unit, the client library and troubleshooting.

## Speed

The C server already uses epoll well, so switching language buys little by itself. Most of the speed-up comes from one change: on the way from the remote server back to the client, payload bytes go through `splice` instead of being copied in user space. The client's reads are also larger. Traffic in the other direction is still copied, because every byte has to be unmasked.

Measured on one machine (i7-13700KF, WSL2, loopback, median of five 5-second runs, the C server as the control):

| Scenario | C | Rust |
| --- | --- | --- |
| 1 stream, MiB/s | 2377 | 2850 |
| 10 streams, MiB/s | 1967 | 3778 |
| Latency, 64-byte round trip | about 50 us | about 50 us |

Take these as rough numbers. Loopback inside WSL is not a real network, runs differ by about 8 percent either way, and I have not repeated them on bare metal yet. A single stream is a bit faster, ten streams are much faster, and latency is the same.

## Not done yet

- Twisp (terminal streams) is not implemented. `enable-twisp` is accepted but nothing serves it.
- Passwords in `password-user` are compared as plain text. `crypt(3)` hashes are not checked yet, so a value starting with `$` never matches.
- `proxy` (upstream SOCKS5/HTTP) and `dns-server` (custom resolvers) are read but not used. Names are resolved with the system resolver.
- Logging is minimal: startup and shutdown lines, nothing per connection.
- The server has no config reload. Restart it to apply changes.
- TLS is not built in. Run it behind nginx, Caddy or similar for `wss://`.

## Compatibility

The wire format follows the [Wisp protocol](https://github.com/MercuryWorkshop/wisp-protocol). The v2 password extension is read in both the layout the specification gives and the one the C server uses. A test replays the same scripted sessions against the C server and this one and checks that the transcripts match.

## Building and testing

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The protocol, config and client crates build and test on any platform. The server itself is Linux-only.

## License

ISC. The original copyright belongs to David Reed; see [LICENSE](LICENSE).
