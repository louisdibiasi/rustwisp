#![cfg(target_os = "linux")]
//! Outbound TCP through an upstream proxy, against small fake SOCKS5 and HTTP CONNECT proxies.

mod common;

#[test]
fn hostname_forwarding_delegates_address_policy_to_the_proxy() {
    use std::net::UdpSocket;
    for forward_name in [false, true] {
        let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
        dns.set_read_timeout(Some(TIMEOUT)).unwrap();
        let endpoint = dns.local_addr().unwrap();
        let resolver = thread::spawn(move || {
            for _ in 0..2 {
                let mut buf = [0; 512];
                let (n, peer) = dns.recv_from(&mut buf).unwrap();
                let mut reply = buf[..n].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                if buf[n - 3] == 1 {
                    reply[7] = 1;
                    reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 8, 8, 8, 8]);
                }
                dns.send_to(&reply, peer).unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut cfg = via(&format!(
            "http://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        ));
        cfg.dns_servers = vec![endpoint.to_string()];
        cfg.allow_loopback = false;
        cfg.proxy_send_hostnames = forward_name;
        let echo = echo_server();
        let proxy = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            client.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                client.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap();
            if forward_name {
                assert!(head.starts_with(&format!("CONNECT some.test:{echo} ")));
                let mut remote = TcpStream::connect(("127.0.0.1", echo)).unwrap();
                remote.set_read_timeout(Some(TIMEOUT)).unwrap();
                remote.write_all(b"proof").unwrap();
                let mut proof = [0; 5];
                remote.read_exact(&mut proof).unwrap();
                client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
                client.write_all(&proof).unwrap();
            } else {
                assert!(head.starts_with(&format!("CONNECT 8.8.8.8:{echo} ")));
                client
                    .write_all(b"HTTP/1.1 502 Unreachable\r\n\r\n")
                    .unwrap();
            }
        });
        let h = start(cfg);
        let mut c = Client::v1(h.port());
        c.connect_stream(1, stream_type::TCP, "some.test", echo);
        if forward_name {
            assert_eq!(c.read_data(1, 5), b"proof");
        } else {
            c.expect_close(1, close::UNREACHABLE);
        }
        h.stop_and_join();
        proxy.join().unwrap();
        resolver.join().unwrap();
    }
}

#[test]
fn stale_proxy_timer_cannot_close_a_reused_stream_id() {
    use std::time::Duration;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut cfg = via(&format!(
        "http://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    ));
    cfg.connect_timeout_ms = 300;
    let h = common::start(cfg);
    let mut c = common::Client::v1(h.port());
    c.tcp(1, 12345);
    let (mut old, _) = listener.accept().unwrap();
    old.set_read_timeout(Some(common::TIMEOUT)).unwrap();
    let mut head = [0; 1024];
    assert!(std::io::Read::read(&mut old, &mut head).unwrap() > 0);
    std::thread::sleep(Duration::from_millis(180));
    c.send_packet(rustwisp_proto::wisp::ptype::CLOSE, 1, &[0]);
    c.tcp(1, 12345);
    let (mut new, _) = listener.accept().unwrap();
    new.set_read_timeout(Some(common::TIMEOUT)).unwrap();
    assert!(std::io::Read::read(&mut new, &mut head).unwrap() > 0);
    std::thread::sleep(Duration::from_millis(180));
    std::io::Write::write_all(&mut new, b"HTTP/1.1 200 OK\r\n\r\nfresh").unwrap();
    assert_eq!(c.read_data(1, 5), b"fresh");
    h.stop_and_join();
}

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;

use common::*;
use rustwisp_config::{Config, ProxyUrl};
use rustwisp_proto::wisp::{close, ptype, stream_type};

#[derive(Clone, Copy)]
enum Mode {
    /// SOCKS5; `login` demands user/pass; `refuse` is the reply code to give instead of success.
    Socks { login: bool, refuse: u8 },
    /// HTTP CONNECT; `refuse` is the status to give instead of 200.
    Http { refuse: u16 },
    /// Accept and say nothing.
    Mute,
}

struct Fake {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

fn read_exact(s: &mut TcpStream, n: usize) -> Option<Vec<u8>> {
    let mut v = vec![0u8; n];
    s.read_exact(&mut v).ok()?;
    Some(v)
}

fn relay(client: TcpStream, dest: TcpStream) {
    let (mut c_r, mut c_w) = (client.try_clone().unwrap(), client);
    let (mut d_r, mut d_w) = (dest.try_clone().unwrap(), dest);
    thread::spawn(move || {
        let _ = std::io::copy(&mut c_r, &mut d_w);
        let _ = d_w.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut d_r, &mut c_w);
}

fn dial(target: &str) -> Option<TcpStream> {
    let (host, port) = target.rsplit_once(':')?;
    // A name can resolve to ::1 first while the test echo server listens on 127.0.0.1 only, as on
    // many CI machines, so try every address as a real proxy would.
    (host, port.parse::<u16>().ok()?)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| TcpStream::connect(addr).ok())
}

fn serve_socks(
    mut s: TcpStream,
    login: bool,
    refuse: u8,
    banner: &[u8],
    seen: &Mutex<Vec<String>>,
) {
    let Some(head) = read_exact(&mut s, 2) else {
        return;
    };
    let Some(_methods) = read_exact(&mut s, usize::from(head[1])) else {
        return;
    };
    if login {
        s.write_all(&[5, 2]).unwrap();
        let ulen = read_exact(&mut s, 2).unwrap();
        let user = read_exact(&mut s, usize::from(ulen[1])).unwrap();
        let plen = read_exact(&mut s, 1).unwrap();
        let pass = read_exact(&mut s, usize::from(plen[0])).unwrap();
        seen.lock().unwrap().push(format!(
            "auth:{}:{}",
            String::from_utf8_lossy(&user),
            String::from_utf8_lossy(&pass)
        ));
        s.write_all(&[1, 0]).unwrap();
    } else {
        s.write_all(&[5, 0]).unwrap();
    }
    let Some(req) = read_exact(&mut s, 4) else {
        return;
    };
    let host = match req[3] {
        1 => {
            let a = read_exact(&mut s, 4).unwrap();
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        3 => {
            let n = read_exact(&mut s, 1).unwrap()[0];
            String::from_utf8(read_exact(&mut s, usize::from(n)).unwrap()).unwrap()
        }
        _ => return,
    };
    let port = read_exact(&mut s, 2).unwrap();
    let target = format!("{host}:{}", u16::from_be_bytes([port[0], port[1]]));
    seen.lock().unwrap().push(target.clone());
    if refuse != 0 {
        let _ = s.write_all(&[5, refuse, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    }
    let Some(dest) = dial(&target) else {
        let _ = s.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    };
    let mut reply = vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    reply.extend_from_slice(banner); // sent in the same write, as a real proxy may
    s.write_all(&reply).unwrap();
    relay(s, dest);
}

fn serve_http(mut s: TcpStream, refuse: u16, banner: &[u8], seen: &Mutex<Vec<String>>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read_exact(&mut byte).is_err() {
            return;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let line = text.lines().next().unwrap_or("");
    let target = line.split(' ').nth(1).unwrap_or("").to_string();
    seen.lock().unwrap().push(target.clone());
    if let Some(auth) = text.lines().find(|l| l.starts_with("Proxy-Authorization:")) {
        seen.lock().unwrap().push(auth.to_string());
    }
    if refuse != 0 {
        let _ = write!(s, "HTTP/1.1 {refuse} No\r\n\r\n");
        return;
    }
    let Some(dest) = dial(&target) else {
        let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        return;
    };
    let mut reply = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
    reply.extend_from_slice(banner);
    s.write_all(&reply).unwrap();
    relay(s, dest);
}

fn fake_proxy(mode: Mode, banner: &[u8]) -> Fake {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (seen2, banner) = (Arc::clone(&seen), banner.to_vec());
    thread::spawn(move || {
        let mut idle = Vec::new();
        for s in l.incoming().flatten() {
            let (seen, banner) = (Arc::clone(&seen2), banner.clone());
            match mode {
                Mode::Socks { login, refuse } => {
                    thread::spawn(move || serve_socks(s, login, refuse, &banner, &seen));
                }
                Mode::Http { refuse } => {
                    thread::spawn(move || serve_http(s, refuse, &banner, &seen));
                }
                Mode::Mute => idle.push(s),
            }
        }
    });
    Fake { port, seen }
}

fn via(url: &str) -> Config {
    Config {
        proxy: Some(url.parse::<ProxyUrl>().unwrap()),
        ..test_config()
    }
}

fn open(c: &mut Client, sid: u32, host: &str, port: u16) {
    c.connect_stream(sid, stream_type::TCP, host, port);
}

#[test]
fn socks5_carries_a_stream_and_is_told_the_checked_address() {
    let echo = echo_server();
    let proxy = fake_proxy(
        Mode::Socks {
            login: false,
            refuse: 0,
        },
        b"",
    );
    let h = start(via(&format!("socks5://127.0.0.1:{}", proxy.port)));
    let mut c = Client::v1(h.port());
    open(&mut c, 1, "localhost", echo);
    c.send_packet(ptype::DATA, 1, b"hello"); // sent before the tunnel is up
    assert_eq!(c.read_data(1, 5), b"hello");
    assert_eq!(*proxy.seen.lock().unwrap(), [format!("127.0.0.1:{echo}")]);
    h.stop_and_join();
}

#[test]
fn the_name_goes_to_the_proxy_only_when_asked_for() {
    let echo = echo_server();
    let proxy = fake_proxy(
        Mode::Socks {
            login: false,
            refuse: 0,
        },
        b"",
    );
    let mut cfg = via(&format!("socks5://127.0.0.1:{}", proxy.port));
    cfg.proxy_send_hostnames = true;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    open(&mut c, 1, "localhost", echo);
    c.send_packet(ptype::DATA, 1, b"hi");
    assert_eq!(c.read_data(1, 2), b"hi");
    assert_eq!(*proxy.seen.lock().unwrap(), [format!("localhost:{echo}")]);
    h.stop_and_join();
}

#[test]
fn socks5_login_is_sent_when_configured() {
    let echo = echo_server();
    let proxy = fake_proxy(
        Mode::Socks {
            login: true,
            refuse: 0,
        },
        b"",
    );
    let h = start(via(&format!(
        "socks5://bob:p%40ss@127.0.0.1:{}",
        proxy.port
    )));
    let mut c = Client::v1(h.port());
    open(&mut c, 1, "localhost", echo);
    c.send_packet(ptype::DATA, 1, b"x");
    assert_eq!(c.read_data(1, 1), b"x");
    assert_eq!(proxy.seen.lock().unwrap()[0], "auth:bob:p@ss");
    h.stop_and_join();
}

#[test]
fn http_connect_carries_a_stream_with_basic_auth() {
    let echo = echo_server();
    let proxy = fake_proxy(Mode::Http { refuse: 0 }, b"");
    let h = start(via(&format!("http://u:p@127.0.0.1:{}", proxy.port)));
    let mut c = Client::v1(h.port());
    open(&mut c, 1, "localhost", echo);
    c.send_packet(ptype::DATA, 1, b"ping");
    assert_eq!(c.read_data(1, 4), b"ping");
    let seen = proxy.seen.lock().unwrap();
    assert_eq!(seen[0], format!("127.0.0.1:{echo}"));
    assert_eq!(seen[1], "Proxy-Authorization: Basic dTpw");
    drop(seen);
    h.stop_and_join();
}

#[test]
fn proxy_refusals_become_close_reasons() {
    let echo = echo_server();
    let cases: [(Mode, u8); 4] = [
        (
            Mode::Socks {
                login: false,
                refuse: 5,
            },
            close::REFUSED,
        ),
        (
            Mode::Socks {
                login: false,
                refuse: 2,
            },
            close::BLOCKED,
        ),
        (Mode::Http { refuse: 403 }, close::BLOCKED),
        (Mode::Http { refuse: 502 }, close::UNREACHABLE),
    ];
    for (mode, reason) in cases {
        let proxy = fake_proxy(mode, b"");
        let scheme = if matches!(mode, Mode::Http { .. }) {
            "http"
        } else {
            "socks5"
        };
        let h = start(via(&format!("{scheme}://127.0.0.1:{}", proxy.port)));
        let mut c = Client::v1(h.port());
        open(&mut c, 1, "localhost", echo);
        c.expect_close(1, reason);
        h.stop_and_join();
    }
}

#[test]
fn bytes_sent_right_after_the_proxy_reply_are_not_lost() {
    let echo = echo_server();
    for (mode, scheme) in [
        (
            Mode::Socks {
                login: false,
                refuse: 0,
            },
            "socks5",
        ),
        (Mode::Http { refuse: 0 }, "http"),
    ] {
        let proxy = fake_proxy(mode, b"WELCOME");
        let h = start(via(&format!("{scheme}://127.0.0.1:{}", proxy.port)));
        let mut c = Client::v1(h.port());
        open(&mut c, 1, "localhost", echo);
        assert_eq!(c.read_data(1, 7), b"WELCOME");
        h.stop_and_join();
    }
}

#[test]
fn a_dead_proxy_closes_the_stream_as_refused() {
    let h = start(via(&format!("socks5://127.0.0.1:{}", closed_port())));
    let mut c = Client::v1(h.port());
    open(&mut c, 1, "localhost", echo_server());
    c.expect_close(1, close::REFUSED);
    h.stop_and_join();
}

#[test]
fn a_silent_proxy_times_out() {
    let proxy = fake_proxy(Mode::Mute, b"");
    let mut cfg = via(&format!("socks5://127.0.0.1:{}", proxy.port));
    cfg.connect_timeout_ms = 300;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    open(&mut c, 1, "localhost", echo_server());
    c.expect_close(1, close::NO_RESPONSE);
    h.stop_and_join();
}

#[test]
fn udp_is_refused_by_default_and_goes_direct_when_allowed() {
    let udp = udp_echo_server();
    let proxy = fake_proxy(
        Mode::Socks {
            login: false,
            refuse: 0,
        },
        b"",
    );
    let url = format!("socks5://127.0.0.1:{}", proxy.port);

    let h = start(via(&url));
    let mut c = Client::v1(h.port());
    c.connect_stream(1, stream_type::UDP, "127.0.0.1", udp);
    c.expect_close(1, close::BLOCKED);
    h.stop_and_join();

    let mut cfg = via(&url);
    cfg.proxy_udp_direct = true;
    let h = start(cfg);
    let mut c = Client::v1(h.port());
    c.connect_stream(1, stream_type::UDP, "127.0.0.1", udp);
    c.send_packet(ptype::DATA, 1, b"dgram");
    assert_eq!(c.read_data(1, 5), b"dgram");
    assert!(
        proxy.seen.lock().unwrap().is_empty(),
        "UDP must bypass the proxy"
    );
    h.stop_and_join();
}

#[test]
fn a_proxy_host_that_does_not_resolve_stops_startup() {
    let cfg = via("socks5://no-such-host.invalid:1080");
    match rustwisp::Server::bind(cfg) {
        Err(e) => assert!(e.to_string().contains("proxy"), "{e}"),
        Ok(_) => panic!("startup should have failed"),
    }
}
