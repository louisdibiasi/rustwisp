//! One relayed stream: filter, resolve, check the resolved addresses against the egress policy,
//! connect to one of those same addresses, then move bytes both ways.
//!
//! Toward the remote, bytes go straight from the client's read buffer into `send`, and only what the
//! socket does not take is queued. Toward the client, bulk TCP data is spliced through a pipe.

use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, OwnedFd};
use std::time::Duration;

use holywisp_proto::wisp::{close, stream_type};

use crate::buf::Queue;
use crate::conn::Conn;
use crate::egress;
use crate::filter;
use crate::limits::SigDet;
use crate::link::{Link, Reg};
use crate::proxy::{Handshake, Progress};
use crate::reputation::{Event, Tier};
use crate::stats::Stats;
use crate::sys::{self, Errno, EventFlags};
use crate::worker::{Ctx, Entry, REMOTE_CHUNK, SPLICE_CHUNK, SpliceMode, TimerKind};

/// Resolved addresses tried per CONNECT.
const MAX_ADDRS: usize = 8;
const MAX_READS_PER_EVENT: usize = 4;
/// A splice that moves less than this means the remote has gone quiet: back to plain `recv`.
const BULK_MIN: usize = 16 * 1024;
/// Destinations whose connect outcomes one connection keeps for the SYN-flood signature.
const MAX_SIGDETS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SState {
    Resolving,
    Connecting,
    /// Connected to the upstream proxy, negotiating the tunnel to the destination.
    ProxyHandshake,
    Open,
    Closed,
}

/// An upstream proxy conversation in progress.
#[derive(Debug)]
pub(crate) struct ProxyHs {
    machine: Handshake,
    out: Vec<u8>,
    sent: usize,
}

#[derive(Debug)]
pub(crate) struct Stream {
    pub id: u32,
    pub udp: bool,
    pub state: SState,
    pub fd: Option<OwnedFd>,
    pub reg: Reg,
    /// Toward the remote. UDP entries are `[u32 len][datagram]`.
    pub out: Queue,
    pub remaining: u32,
    pub continue_due: bool,
    pub read_armed: bool,
    #[allow(dead_code)] // kept for logs
    pub host: String,
    pub port: u16,
    pub addrs: Vec<SocketAddr>,
    pub addr_idx: usize,
    /// Bumped on every resolve or connect attempt so a late timer or answer can be recognised.
    pub serial: u32,
    /// The last remote read filled a whole chunk, so more is probably waiting.
    pub bulk: bool,
    /// Holds one of the in-flight SYN slots.
    pub syn_held: bool,
    /// `ip:port` of the first resolved address, the key for per-destination limits.
    pub dest: String,
    pub hs: Option<Box<ProxyHs>>,
    /// The address that passed the egress checks; the proxy is told to connect to exactly this.
    pub vetted: Option<IpAddr>,
}

fn map_errno(e: Errno) -> u8 {
    match e {
        Errno::CONNREFUSED => close::REFUSED,
        Errno::TIMEDOUT => close::NO_RESPONSE,
        Errno::NETUNREACH | Errno::HOSTUNREACH | Errno::ADDRNOTAVAIL | Errno::AFNOSUPPORT => {
            close::UNREACHABLE
        }
        _ => close::NETWORK_ERROR,
    }
}

/// `Some(ip)` for an IP literal (optionally in brackets), `None` for a name, `Err` for something that
/// looks like a literal but is malformed.
pub(crate) fn parse_literal(host: &str) -> Result<Option<IpAddr>, ()> {
    let bracketed = host.len() >= 2 && host.starts_with('[') && host.ends_with(']');
    let inner = if bracketed {
        &host[1..host.len() - 1]
    } else {
        host
    };
    if let Ok(ip) = inner.parse::<IpAddr>() {
        return Ok(Some(ip));
    }
    // The system resolver also reads `127.1`, `2130706433` and `0x7f.0.0.1` as addresses. A real
    // hostname never ends in a numeric label, so anything that does is refused here instead of
    // being resolved behind the direct-IP switch and the host filters.
    let last = host.rsplit('.').next().unwrap_or(host);
    let numeric_label = !last.is_empty()
        && (last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .or_else(|| last.strip_prefix("0X"))
                .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit())));
    if bracketed || numeric_label || host.contains(':') {
        return Err(());
    }
    Ok(None)
}

// ------------------------------------------------------------------------------------- lifecycle

fn new_stream(cx: &mut Ctx, conn_tok: u64, id: u32, udp: bool, host: &str, port: u16) -> Stream {
    let token = cx.slab.insert(Entry::Stream {
        conn: conn_tok,
        sid: id,
    });
    Stats::inc(&cx.sh.stats.streams_total);
    Stats::inc(&cx.sh.stats.streams_active);
    Stream {
        id,
        udp,
        state: SState::Resolving,
        fd: None,
        reg: Reg::new(token),
        out: Queue::new(),
        remaining: cx.sh.window,
        continue_due: false,
        read_armed: false,
        host: host.to_string(),
        port,
        addrs: Vec::new(),
        addr_idx: 0,
        serial: 0,
        bulk: false,
        syn_held: false,
        dest: String::new(),
        hs: None,
        vetted: None,
    }
}

pub(crate) fn close_stream(link: &mut Link, cx: &mut Ctx, s: &mut Stream, reason: u8, send: bool) {
    if s.state == SState::Closed {
        return;
    }
    s.state = SState::Closed;
    release_syn(cx, s);
    s.fd = None; // closing the descriptor removes it from epoll
    s.reg.forget();
    cx.slab.release(s.reg.token);
    Stats::dec(&cx.sh.stats.streams_active);
    s.out.clear();
    s.hs = None;
    if send {
        link.send_close(cx, s.id, reason);
    }
}

fn release_syn(cx: &Ctx, s: &mut Stream) {
    if s.syn_held {
        cx.sh.in_flight_syns.release();
        s.syn_held = false;
    }
}

/// Record a connect outcome against the SYN-flood signature. Returns true when it matched and the
/// whole connection was closed.
fn signature_record(link: &mut Link, cx: &Ctx, s: &Stream, ok: bool) -> bool {
    // Through a proxy the TCP connect only reaches the proxy, which says nothing about the destination.
    !proxied(cx, s) && signature_record_always(link, cx, s, ok)
}

fn signature_record_always(link: &mut Link, cx: &Ctx, s: &Stream, ok: bool) -> bool {
    let f = &cx.cfg().flood;
    if !f.enabled || !f.syn_signature_enabled || s.udp {
        return false;
    }
    if link.sigdets.len() >= MAX_SIGDETS && !link.sigdets.contains_key(&s.dest) {
        // Make room by dropping the destination that has been quiet the longest.
        let oldest = link
            .sigdets
            .iter()
            .min_by_key(|(_, d)| d.last_seen())
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            link.sigdets.remove(&k);
        }
    }
    let d: &mut SigDet = link.sigdets.entry(s.dest.clone()).or_default();
    d.record(ok, cx.sh.now_ms(), u64::from(f.syn_signature_window_ms));
    if !d.matches(f.syn_signature_min_samples, f.syn_signature_failed_ratio) {
        return false;
    }
    Stats::inc(&cx.sh.stats.syn_signatures);
    link.rep_source(cx, Event::SynSignature);
    link.rep_dest(cx, &s.dest, Event::SynSignature);
    link.close();
    true
}

/// Per-destination rate caps, once the address set is known. Returns false when the stream was
/// closed.
fn dest_policy(link: &mut Link, cx: &mut Ctx, s: &mut Stream) -> bool {
    s.dest = format!("{}:{}", s.addrs[0].ip().to_canonical(), s.port);
    let now = cx.sh.now_ms();
    if let Some(w) = cx.sh.per_dest_sec.as_ref()
        && !w.allow(&s.dest, now)
    {
        Stats::inc(&cx.sh.stats.throttled_dest);
        link.rep_source(cx, Event::BurstRate);
        link.rep_dest(cx, &s.dest, Event::BurstRate);
        link.violation(cx);
        if !link.closing {
            close_stream(link, cx, s, close::THROTTLED, true);
        }
        return false;
    }
    if let Some(w) = cx.sh.per_dest_min.as_ref()
        && !w.allow(&s.dest, now)
    {
        Stats::inc(&cx.sh.stats.throttled_dest);
        close_stream(link, cx, s, close::THROTTLED, true);
        return false;
    }
    if let Some(rep) = cx.sh.reputation.as_ref() {
        // Every resolved address is checked, not just the first.
        let port = s.port;
        s.addrs.retain(|a| {
            rep.dest_tier(&format!("{}:{port}", a.ip().to_canonical())) != Tier::Strict
        });
        if s.addrs.is_empty() {
            link.rep_source(cx, Event::KnownBadDest);
            close_stream(link, cx, s, close::BLOCKED, true);
            return false;
        }
    }
    true
}

fn update_events(cx: &Ctx, s: &mut Stream) -> bool {
    let Some(fd) = s.fd.as_ref() else {
        return true;
    };
    let mut want = EventFlags::empty();
    match s.state {
        SState::Connecting => want |= sys::OUT,
        SState::ProxyHandshake => {
            want |= sys::IN;
            if s.hs.as_ref().is_some_and(|h| h.sent < h.out.len()) {
                want |= sys::OUT;
            }
        }
        SState::Open => {
            if s.read_armed {
                want |= sys::IN;
            }
            if !s.out.is_empty() {
                want |= sys::OUT;
            }
        }
        _ => {}
    }
    s.reg.set(&cx.ep, fd, want).is_ok()
}

/// Apply the connection's pause state to this stream's read interest.
pub(crate) fn set_paused(cx: &Ctx, s: &mut Stream, paused: bool) {
    if s.state != SState::Open || s.read_armed == !paused {
        return;
    }
    s.read_armed = !paused;
    update_events(cx, s);
}

// ------------------------------------------------------------------------------------- opening

/// A CONNECT from the client. `host` has already been checked for length and NULs.
pub(crate) fn open(conn: &mut Conn, cx: &mut Ctx, id: u32, kind: u8, host: &str, port: u16) {
    let link = &mut conn.link;
    if port == 0 {
        link.send_close(cx, id, close::INVALID_INFO);
        return;
    }
    if kind == stream_type::UDP && cx.sh.upstream.is_some() && !cx.cfg().proxy_udp_direct {
        link.send_close(cx, id, close::BLOCKED);
        return;
    }
    if !filter::host_port_ok(cx.cfg(), host, port) {
        Stats::inc(&cx.sh.stats.blocked_filter);
        link.send_close(cx, id, close::BLOCKED);
        return;
    }
    let mut s = new_stream(cx, link.reg.token, id, kind == stream_type::UDP, host, port);
    match parse_literal(host) {
        Err(()) => close_stream(link, cx, &mut s, close::INVALID_INFO, true),
        Ok(Some(ip)) => open_literal(link, cx, &mut s, ip),
        Ok(None) => {
            s.serial = s.serial.wrapping_add(1);
            let timeout = Duration::from_millis(u64::from(cx.cfg().dns_timeout_ms.max(1)));
            cx.add_timer(timeout, link.reg.token, id, s.serial, TimerKind::Connect);
            cx.sh
                .resolver
                .submit(host, &cx.mailbox, link.reg.token, id, s.serial);
        }
    }
    if s.state != SState::Closed {
        conn.streams.insert(id, s);
    }
}

fn open_literal(link: &mut Link, cx: &mut Ctx, s: &mut Stream, ip: IpAddr) {
    if !cx.cfg().allow_direct_ip {
        Stats::inc(&cx.sh.stats.blocked_egress);
        close_stream(link, cx, s, close::BLOCKED, true);
        return;
    }
    if egress::check(cx.cfg(), ip).is_err() {
        Stats::inc(&cx.sh.stats.blocked_egress);
        link.rep_source(cx, Event::PrivateEgress);
        close_stream(link, cx, s, close::BLOCKED, true);
        return;
    }
    s.addrs = vec![SocketAddr::new(ip, s.port)];
    if dest_policy(link, cx, s) {
        begin_connect(link, cx, s);
    }
}

/// The resolver answered (or failed) for a stream still in `Resolving`.
pub(crate) fn on_resolved(
    link: &mut Link,
    cx: &mut Ctx,
    s: &mut Stream,
    addrs: Result<Vec<IpAddr>, ()>,
) {
    if s.state != SState::Resolving {
        return;
    }
    let Ok(ips) = addrs else {
        close_stream(link, cx, s, close::UNREACHABLE, true);
        return;
    };
    let mut any_blocked = false;
    for ip in ips {
        if s.addrs.len() >= MAX_ADDRS {
            break;
        }
        if egress::check(cx.cfg(), ip).is_ok() {
            s.addrs.push(SocketAddr::new(ip, s.port));
        } else {
            any_blocked = true;
        }
    }
    if s.addrs.is_empty() {
        if any_blocked {
            Stats::inc(&cx.sh.stats.blocked_egress);
            link.rep_source(cx, Event::PrivateEgress);
        }
        let reason = if any_blocked {
            close::BLOCKED
        } else {
            close::UNREACHABLE
        };
        close_stream(link, cx, s, reason, true);
        return;
    }
    s.serial = s.serial.wrapping_add(1);
    if dest_policy(link, cx, s) {
        begin_connect(link, cx, s);
    }
}

/// The destination passed every check: connect to it, or to the proxy that will reach it.
fn begin_connect(link: &mut Link, cx: &mut Ctx, s: &mut Stream) {
    if proxied(cx, s)
        && let Some(up) = cx.sh.upstream.as_ref()
    {
        s.vetted = s.addrs.first().map(SocketAddr::ip);
        s.addrs = up.addrs.clone();
        s.addr_idx = 0;
    }
    connect_next(link, cx, s, Errno::HOSTUNREACH);
}

/// Try the next resolved address.
fn connect_next(link: &mut Link, cx: &mut Ctx, s: &mut Stream, mut last: Errno) {
    s.serial = s.serial.wrapping_add(1);
    while s.addr_idx < s.addrs.len() {
        let addr = s.addrs[s.addr_idx];
        s.addr_idx += 1;
        let fd = match sys::socket_nb(&addr, s.udp) {
            Ok(fd) => fd,
            Err(e) => {
                last = e;
                continue;
            }
        };
        if !s.udp && !s.syn_held {
            if !cx.sh.in_flight_syns.try_acquire() {
                Stats::inc(&cx.sh.stats.throttled_syns);
                link.violation(cx);
                if !link.closing {
                    close_stream(link, cx, s, close::THROTTLED, true);
                }
                return;
            }
            s.syn_held = true;
        }
        match sys::connect(&fd, &addr) {
            Ok(()) => {
                s.fd = Some(fd);
                if signature_record(link, cx, s, true) {
                    return;
                }
                tcp_up(link, cx, s);
                return;
            }
            Err(Errno::INPROGRESS) => {
                s.fd = Some(fd);
                s.state = SState::Connecting;
                if !update_events(cx, s) {
                    close_stream(link, cx, s, close::NETWORK_ERROR, true);
                    return;
                }
                let t = Duration::from_millis(u64::from(cx.cfg().connect_timeout_ms.max(1)));
                cx.add_timer(t, link.reg.token, s.id, s.serial, TimerKind::Connect);
                return;
            }
            Err(e) => last = e,
        }
    }
    if signature_record(link, cx, s, false) {
        return;
    }
    close_stream(link, cx, s, map_errno(last), true);
}

fn connected(link: &mut Link, cx: &mut Ctx, s: &mut Stream) {
    release_syn(cx, s);
    link.rep_source(cx, Event::SuccessfulStream);
    s.state = SState::Open;
    s.serial = s.serial.wrapping_add(1);
    if !s.udp
        && let Some(fd) = s.fd.as_ref()
    {
        let c = cx.cfg();
        sys::tune_tcp(fd, c.tcp_nodelay, c.tcp_quickack, c.socket_buffer_size);
    }
    s.read_armed = !link.reads_suspended();
    if !update_events(cx, s) {
        close_stream(link, cx, s, close::NETWORK_ERROR, true);
        return;
    }
    if link.stream_confirm {
        link.send_continue(cx, s.id, s.remaining);
        if link.closing {
            return;
        }
    }
    flush_out(link, cx, s);
}

/// A connect or resolve timer fired.
pub(crate) fn on_connect_timer(link: &mut Link, cx: &mut Ctx, s: &mut Stream, serial: u32) {
    if s.serial != serial {
        return;
    }
    match s.state {
        SState::Resolving => close_stream(link, cx, s, close::UNREACHABLE, true),
        SState::Connecting => {
            s.fd = None;
            s.reg.forget();
            if !signature_record(link, cx, s, false) {
                connect_next(link, cx, s, Errno::TIMEDOUT);
            }
        }
        SState::ProxyHandshake => proxy_fail(link, cx, s, close::NO_RESPONSE),
        _ => {}
    }
}

// ------------------------------------------------------------------------------------- upstream proxy

/// Outbound TCP goes through the configured proxy; UDP never does.
fn proxied(cx: &Ctx, s: &Stream) -> bool {
    !s.udp && cx.sh.upstream.is_some()
}

/// The socket to the destination (or to the proxy) is up.
fn tcp_up(link: &mut Link, cx: &mut Ctx, s: &mut Stream) {
    if proxied(cx, s) {
        start_proxy(link, cx, s);
    } else {
        connected(link, cx, s);
    }
}

/// Send the proxy our request for this destination and wait for its answer.
fn start_proxy(link: &mut Link, cx: &mut Ctx, s: &mut Stream) {
    let Some(up) = cx.sh.upstream.as_ref() else {
        return connected(link, cx, s);
    };
    let creds = up.cfg.user.as_deref().zip(up.cfg.pass.as_deref());
    // By default the proxy gets the address that was checked here, so it cannot be steered
    // elsewhere by a name that resolves differently on its side (DNS rebinding).
    let target = match s.vetted {
        Some(ip) if !cx.cfg().proxy_send_hostnames => ip.to_string(),
        _ => s.host.clone(),
    };
    let (machine, first) = match Handshake::new(up.cfg.kind, creds, &target, s.port) {
        Ok(started) => started,
        Err(reason) => {
            close_stream(link, cx, s, reason, true);
            return;
        }
    };
    s.hs = Some(Box::new(ProxyHs {
        machine,
        out: first,
        sent: 0,
    }));
    s.state = SState::ProxyHandshake;
    s.serial = s.serial.wrapping_add(1);
    let t = Duration::from_millis(u64::from(cx.cfg().connect_timeout_ms.max(1)));
    cx.add_timer(t, link.reg.token, s.id, s.serial, TimerKind::Connect);
    proxy_write(link, cx, s);
}

fn proxy_fail(link: &mut Link, cx: &mut Ctx, s: &mut Stream, reason: u8) {
    s.hs = None;
    if !signature_record_always(link, cx, s, false) {
        close_stream(link, cx, s, reason, true);
    }
}

/// Push pending handshake bytes. Returns false when the stream was closed.
fn proxy_write(link: &mut Link, cx: &mut Ctx, s: &mut Stream) -> bool {
    loop {
        let Some(hs) = s.hs.as_ref() else {
            return true;
        };
        if hs.sent >= hs.out.len() {
            break;
        }
        match send_remote(s, &hs.out[hs.sent..]) {
            Ok(n) => {
                if let Some(h) = s.hs.as_mut() {
                    h.sent += n;
                }
            }
            Err(Errno::INTR) => {}
            Err(e) if sys::is_would_block(e) => break,
            Err(e) => {
                proxy_fail(link, cx, s, map_errno(e));
                return false;
            }
        }
    }
    if !update_events(cx, s) {
        proxy_fail(link, cx, s, close::NETWORK_ERROR);
        return false;
    }
    true
}

fn proxy_event(link: &mut Link, cx: &mut Ctx, s: &mut Stream, flags: EventFlags) {
    if flags.contains(sys::OUT) && !proxy_write(link, cx, s) {
        return;
    }
    if flags.intersects(sys::IN | EventFlags::HUP | EventFlags::ERR) {
        proxy_read(link, cx, s);
    }
}

/// Read the proxy's answer. Only the bytes of the reply are taken off the socket; whatever the
/// destination sent after it stays queued for the relay.
fn proxy_read(link: &mut Link, cx: &mut Ctx, s: &mut Stream) {
    let mut buf = [0u8; 512];
    while s.state == SState::ProxyHandshake {
        let Some(fd) = s.fd.as_ref() else { return };
        let seen = match sys::peek(fd, &mut buf) {
            Ok(0) => return proxy_fail(link, cx, s, close::NETWORK_ERROR),
            Ok(n) => n,
            Err(Errno::INTR) => continue,
            Err(e) if sys::is_would_block(e) => return,
            Err(e) => return proxy_fail(link, cx, s, map_errno(e)),
        };
        let Some(hs) = s.hs.as_mut() else { return };
        let (used, progress) = hs.machine.feed(&buf[..seen]);
        let used = used.min(seen);
        if used > 0 {
            let took = match s.fd.as_ref() {
                Some(fd) => sys::recv(fd, &mut buf[..used]),
                None => return,
            };
            if took != Ok(used) {
                return proxy_fail(link, cx, s, close::NETWORK_ERROR);
            }
        }
        match progress {
            Progress::Wait => {}
            Progress::Send(bytes) => {
                if let Some(h) = s.hs.as_mut() {
                    h.out = bytes;
                    h.sent = 0;
                }
                if !proxy_write(link, cx, s) {
                    return;
                }
            }
            Progress::Done => {
                s.hs = None;
                if !signature_record_always(link, cx, s, true) {
                    connected(link, cx, s);
                }
                return;
            }
            Progress::Fail(reason) => return proxy_fail(link, cx, s, reason),
        }
    }
}

// ------------------------------------------------------------------------------------- events

pub(crate) fn on_event(link: &mut Link, cx: &mut Ctx, s: &mut Stream, flags: EventFlags) {
    match s.state {
        SState::Connecting => {
            let Some(fd) = s.fd.as_ref() else { return };
            let mut err = sys::so_error(fd).err();
            if err.is_none()
                && flags.intersects(EventFlags::ERR | EventFlags::HUP)
                && !flags.contains(sys::OUT)
            {
                err = Some(Errno::CONNREFUSED);
            }
            match err {
                Some(e) => {
                    s.fd = None;
                    s.reg.forget();
                    if !signature_record(link, cx, s, false) {
                        connect_next(link, cx, s, e);
                    }
                }
                None => {
                    if !signature_record(link, cx, s, true) {
                        tcp_up(link, cx, s);
                    }
                }
            }
        }
        SState::Open => {
            if flags.contains(sys::OUT) && !flush_out(link, cx, s) {
                return;
            }
            if flags.intersects(sys::IN | EventFlags::HUP | EventFlags::ERR) {
                read_remote(link, cx, s);
            }
        }
        SState::ProxyHandshake => proxy_event(link, cx, s, flags),
        SState::Resolving | SState::Closed => {}
    }
}

// ------------------------------------------------------------------------------------- client -> remote

fn send_remote(s: &Stream, buf: &[u8]) -> Result<usize, Errno> {
    match s.fd.as_ref() {
        Some(fd) => sys::send(fd, buf),
        None => Err(Errno::BADF),
    }
}

/// Drain `s.out` into the socket. Returns false when the stream was closed.
fn flush_out(link: &mut Link, cx: &mut Ctx, s: &mut Stream) -> bool {
    while !s.out.is_empty() {
        let head = s.out.as_slice();
        let (prefix, chunk) = if s.udp {
            if head.len() < 4 {
                break;
            }
            let n = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
            if head.len() < 4 + n {
                break;
            }
            (4, n)
        } else {
            (0, head.len())
        };
        let sent = send_remote(s, &s.out.as_slice()[prefix..prefix + chunk]);
        match sent {
            Ok(n) => s.out.consume(if s.udp { prefix + chunk } else { n }),
            Err(Errno::INTR) => {}
            Err(e) if sys::is_would_block(e) => {
                update_events(cx, s);
                return true;
            }
            Err(e) => {
                close_stream(link, cx, s, map_errno(e), true);
                return false;
            }
        }
    }
    s.out.shrink_if_idle(1 << 20);
    update_events(cx, s);
    if s.continue_due {
        s.continue_due = false;
        link.send_continue(cx, s.id, s.remaining);
        if link.closing {
            return false;
        }
    }
    true
}

/// DATA from the client for this stream. The payload is a slice of the worker's read buffer: try to
/// send it straight to the remote and queue only what is left.
pub(crate) fn on_data(link: &mut Link, cx: &mut Ctx, s: &mut Stream, data: &[u8]) {
    if s.state == SState::Closed {
        return;
    }
    let mut data = data;
    let mut queued = !s.out.is_empty() || s.state != SState::Open;
    if !queued {
        match send_remote(s, data) {
            Ok(n) => data = &data[n..],
            Err(e) if sys::is_would_block(e) || e == Errno::INTR => {}
            Err(e) if s.udp && (e == Errno::MSGSIZE || e == Errno::CONNREFUSED) => data = &[],
            Err(e) => {
                close_stream(link, cx, s, map_errno(e), true);
                return;
            }
        }
        if s.udp {
            data = &[]; // a datagram is all or nothing
        }
        queued = !data.is_empty();
    }
    if queued && !data.is_empty() {
        if s.out.len() + data.len() + 4 > cx.cfg().stream_queue_max as usize {
            close_stream(link, cx, s, close::THROTTLED, true);
            return;
        }
        if s.udp {
            s.out.push(&(data.len() as u32).to_le_bytes());
        }
        s.out.push(data);
        if s.state == SState::Open {
            update_events(cx, s);
        }
    }
    // UDP queued entries (rare): a datagram that could not be sent immediately was dropped above.
    if !s.udp {
        s.remaining = s.remaining.saturating_sub(1);
        if s.remaining == 0 {
            s.remaining = cx.sh.window;
            if s.out.is_empty() {
                link.send_continue(cx, s.id, s.remaining);
            } else {
                s.continue_due = true;
            }
        }
    }
}

// ------------------------------------------------------------------------------------- remote -> client

fn use_splice(link: &Link, cx: &Ctx, s: &Stream) -> bool {
    if s.udp || cx.pipe.is_none() || !link.wbuf.is_empty() {
        return false;
    }
    match cx.sh.splice {
        SpliceMode::Off => false,
        SpliceMode::Always => true,
        SpliceMode::Auto => s.bulk,
    }
}

fn read_remote(link: &mut Link, cx: &mut Ctx, s: &mut Stream) {
    if s.udp {
        read_udp(link, cx, s);
    } else if use_splice(link, cx, s) {
        read_splice(link, cx, s);
    } else {
        read_copy(link, cx, s);
    }
}

fn read_ok(link: &Link, s: &Stream) -> bool {
    s.read_armed && !link.reads_suspended() && !link.closing && s.state == SState::Open
}

fn read_copy(link: &mut Link, cx: &mut Ctx, s: &mut Stream) {
    let mut rd = std::mem::take(&mut cx.rd);
    for _ in 0..MAX_READS_PER_EVENT {
        if !read_ok(link, s) {
            break;
        }
        let Some(fd) = s.fd.as_ref() else { break };
        match sys::recv(fd, &mut rd[..REMOTE_CHUNK]) {
            Ok(0) => {
                close_stream(link, cx, s, close::VOLUNTARY, true);
                break;
            }
            Ok(n) => {
                link.send_data(cx, s.id, &rd[..n]);
                s.bulk = n == REMOTE_CHUNK;
                if n < REMOTE_CHUNK {
                    break;
                }
            }
            Err(Errno::INTR) => {}
            Err(e) if sys::is_would_block(e) => break,
            Err(e) => {
                close_stream(link, cx, s, map_errno(e), true);
                break;
            }
        }
    }
    cx.rd = rd;
}

fn read_splice(link: &mut Link, cx: &mut Ctx, s: &mut Stream) {
    let max_payload = (cx.cfg().max_message_size as usize)
        .saturating_sub(5)
        .max(1);
    let len = SPLICE_CHUNK.min(max_payload);
    for _ in 0..MAX_READS_PER_EVENT {
        if !read_ok(link, s) {
            return;
        }
        if !link.wbuf.is_empty() {
            return read_copy(link, cx, s);
        }
        let (Some(fd), Some((_, pw))) = (s.fd.as_ref(), cx.pipe.as_ref()) else {
            return;
        };
        match sys::splice_to_pipe(fd.as_fd(), pw, len) {
            Ok(0) => {
                close_stream(link, cx, s, close::VOLUNTARY, true);
                return;
            }
            Ok(n) => {
                link.splice_data(cx, s.id, n);
                if n < BULK_MIN {
                    s.bulk = false;
                    return;
                }
            }
            Err(Errno::INTR) => {}
            Err(e) if sys::is_would_block(e) => return,
            Err(e) => {
                close_stream(link, cx, s, map_errno(e), true);
                return;
            }
        }
    }
}

fn read_udp(link: &mut Link, cx: &mut Ctx, s: &mut Stream) {
    let mut rd = std::mem::take(&mut cx.rd);
    for _ in 0..MAX_READS_PER_EVENT {
        if !read_ok(link, s) {
            break;
        }
        let Some(fd) = s.fd.as_ref() else { break };
        match sys::recv(fd, &mut rd) {
            Ok(n) => link.send_data(cx, s.id, &rd[..n]),
            Err(Errno::INTR) => {}
            Err(e) if sys::is_would_block(e) => break,
            Err(Errno::CONNREFUSED) => {
                close_stream(link, cx, s, close::UNREACHABLE, true);
                break;
            }
            Err(e) => {
                close_stream(link, cx, s, map_errno(e), true);
                break;
            }
        }
    }
    cx.rd = rd;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_names() {
        assert_eq!(
            parse_literal("127.0.0.1"),
            Ok(Some("127.0.0.1".parse().unwrap()))
        );
        assert_eq!(parse_literal("[::1]"), Ok(Some("::1".parse().unwrap())));
        assert_eq!(parse_literal("::1"), Ok(Some("::1".parse().unwrap())));
        assert_eq!(parse_literal("example.com"), Ok(None));
        assert_eq!(parse_literal("a1.b2"), Ok(None));
    }

    #[test]
    fn malformed_literals_are_rejected_not_resolved() {
        assert_eq!(parse_literal("1.2.3"), Err(()));
        assert_eq!(parse_literal("256.1.1.1"), Err(()));
        assert_eq!(parse_literal("[example.com]"), Err(()));
        assert_eq!(parse_literal("fe80::1%eth0"), Err(()));
        assert_eq!(parse_literal("host:80"), Err(()));
        // Forms the system resolver would read as addresses.
        assert_eq!(parse_literal("127.1"), Err(()));
        assert_eq!(parse_literal("2130706433"), Err(()));
        assert_eq!(parse_literal("0x7f.0.0.1"), Err(()));
        assert_eq!(parse_literal("0x7f000001"), Err(()));
        assert_eq!(parse_literal("0177.0.0.1"), Err(()));
        assert_eq!(parse_literal("1password.com"), Ok(None));
        assert_eq!(parse_literal("0xdead.beef.example"), Ok(None));
    }
}
