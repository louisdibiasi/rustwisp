//! The client side of a connection: its socket, the write queue toward it, WebSocket framing of
//! outgoing Wisp packets, and the splice fast path for remote data.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::{AsFd, OwnedFd};

use rustwisp_proto::{wisp, ws};

use crate::buf::Queue;
use crate::limits::SigDet;
use crate::reputation::{Event, Tier};
use crate::stats::Stats;
use crate::sys::{self, Errno, EventFlags};
use crate::worker::Ctx;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    /// Reading the request head.
    Http,
    /// A plain HTTP response is queued; close once it is flushed.
    HttpReply,
    Ws,
}

/// Which epoll interest a descriptor currently has. Interest of `empty` means "not registered":
/// a descriptor that is only waiting to be resumed must not spin the loop on HUP.
#[derive(Debug)]
pub(crate) struct Reg {
    pub token: u64,
    flags: EventFlags,
    registered: bool,
}

impl Reg {
    pub(crate) fn new(token: u64) -> Reg {
        Reg {
            token,
            flags: EventFlags::empty(),
            registered: false,
        }
    }

    /// Make the kernel's interest equal `want`, touching epoll only when it changes.
    pub(crate) fn set(
        &mut self,
        ep: &OwnedFd,
        fd: &OwnedFd,
        want: EventFlags,
    ) -> Result<(), Errno> {
        if want.is_empty() {
            if self.registered {
                self.registered = false;
                self.flags = EventFlags::empty();
                return sys::epoll_del(ep, fd);
            }
            return Ok(());
        }
        if !self.registered {
            sys::epoll_add(ep, fd, self.token, want)?;
            self.registered = true;
            self.flags = want;
        } else if self.flags != want {
            sys::epoll_mod(ep, fd, self.token, want)?;
            self.flags = want;
        }
        Ok(())
    }

    /// The descriptor was closed, which removes it from epoll by itself.
    pub(crate) fn forget(&mut self) {
        self.registered = false;
        self.flags = EventFlags::empty();
    }
}

#[derive(Debug)]
pub(crate) struct Link {
    pub fd: OwnedFd,
    pub reg: Reg,
    pub state: State,
    /// The request head, or the front of a frame that has not fully arrived.
    pub rbuf: Vec<u8>,
    /// Size of the frame `rbuf` is waiting to complete, when known.
    pub need: usize,
    pub wbuf: Queue,
    pub frag: Option<Vec<u8>>,
    pub is_v2: bool,
    pub handshake_done: bool,
    pub stream_confirm: bool,
    pub authenticated: bool,
    /// A password check is running on the auth pool; its id.
    pub auth_pending: Option<u64>,
    /// `stream_confirm` from the INFO that started that check.
    pub auth_confirm: bool,
    /// Remote reads are suspended because the client is not draining.
    pub paused: bool,
    pub pause_changed: bool,
    pub throttled: bool,
    pub read_paused: bool,
    pub read_resumed: bool,
    pub queued_out: usize,
    pub live_streams: usize,
    pub packet_average: usize,
    pub closing: bool,
    pub violations: u32,
    /// Holds one of the server-wide connection slots.
    pub conn_slot: bool,
    pub reject_slot: bool,
    /// Per destination, the recent connect outcomes (SYN-flood signature).
    pub sigdets: HashMap<String, SigDet>,
    /// A bandwidth charge asked for a pause; the connection schedules it when the event is done.
    pub pending_throttle_ms: u64,
    pub tier: Tier,
    pub stream_cap: usize,
    #[allow(dead_code)] // read by the per-IP limits and logs
    pub peer: SocketAddr,
    /// The address policy applies to (the socket peer unless a trusted proxy said otherwise).
    #[allow(dead_code)]
    pub ip: String,
}

const DATA_HEADER_MAX: usize = ws::MAX_HEADER + wisp::HEADER_LEN;

/// The WebSocket frame header plus the Wisp DATA header for a payload of `payload_len` bytes.
fn data_header(sid: u32, payload_len: usize) -> ([u8; DATA_HEADER_MAX], usize) {
    let mut ws_head = [0u8; ws::MAX_HEADER];
    let wl = ws::write_header(
        &mut ws_head,
        true,
        ws::opcode::BINARY,
        (wisp::HEADER_LEN + payload_len) as u64,
        None,
    );
    let mut out = [0u8; DATA_HEADER_MAX];
    out[..wl].copy_from_slice(&ws_head[..wl]);
    let mut wisp_head = [0u8; wisp::HEADER_LEN];
    wisp::write_header(&mut wisp_head, wisp::ptype::DATA, sid);
    out[wl..wl + wisp::HEADER_LEN].copy_from_slice(&wisp_head);
    (out, wl + wisp::HEADER_LEN)
}

/// An error that means the socket is broken, as opposed to "try again".
fn fail_reason(e: Errno) -> bool {
    !(sys::is_would_block(e) || e == Errno::INTR)
}

impl Link {
    /// Remote reads are suspended: the client is not draining, or its bandwidth budget is spent.
    pub(crate) fn reads_suspended(&self) -> bool {
        self.paused || self.throttled
    }

    pub(crate) fn want(&self) -> EventFlags {
        let mut f = if self.throttled || self.read_paused {
            EventFlags::RDHUP
        } else {
            sys::IN
        };
        if !self.wbuf.is_empty() {
            f |= sys::OUT;
        }
        f
    }

    pub(crate) fn refill_window(&self, cx: &Ctx) -> u32 {
        let packets = cx.cfg().ws_write_high_water as usize
            / self.live_streams.max(1)
            / self.packet_average.max(1);
        packets.clamp(4.min(cx.sh.window) as usize, cx.sh.window as usize) as u32
    }

    pub(crate) fn queue_add(&mut self, cx: &Ctx, n: usize) {
        self.queued_out += n;
        if self.queued_out > cx.cfg().conn_queue_max as usize && !self.read_paused {
            self.read_paused = true;
            self.sync_interest(cx);
        }
    }

    pub(crate) fn queue_sub(&mut self, cx: &Ctx, n: usize) {
        self.queued_out = self.queued_out.saturating_sub(n);
        if self.read_paused && self.queued_out < cx.cfg().conn_queue_max as usize / 2 {
            self.read_paused = false;
            self.read_resumed = true;
            self.sync_interest(cx);
        }
    }

    pub(crate) fn sync_interest(&mut self, cx: &Ctx) {
        if self.closing {
            return;
        }
        let want = self.want();
        if self.reg.set(&cx.ep, &self.fd, want).is_err() {
            self.closing = true;
        }
    }

    pub(crate) fn rep_source(&self, cx: &Ctx, e: Event) {
        if let Some(r) = cx.sh.reputation.as_ref() {
            r.add_source(&self.ip, e);
        }
    }

    pub(crate) fn rep_dest(&self, cx: &Ctx, dest: &str, e: Event) {
        if let Some(r) = cx.sh.reputation.as_ref() {
            r.add_dest(dest, e, Some(&self.ip));
        }
    }

    /// Count a flood-protection violation; enough of them close the connection.
    pub(crate) fn violation(&mut self, cx: &Ctx) {
        crate::log::debug("flood", format_args!("{}: throttled", self.ip));
        self.rep_source(cx, Event::ProtocolViolation);
        let limit = cx.cfg().flood.ws_close_after_violations;
        if limit == 0 {
            return;
        }
        self.violations += 1;
        if self.violations >= limit {
            Stats::inc(&cx.sh.stats.ws_closed_violations);
            self.closing = true;
        }
    }

    /// Charge `bytes` against the per-IP bandwidth budget.
    pub(crate) fn charge_bandwidth(&mut self, cx: &Ctx, bytes: usize) {
        let Some(bw) = cx.sh.bandwidth.as_ref() else {
            return;
        };
        // Every byte is charged, throttled or not, so pacing holds in both directions; the pause
        // itself is only scheduled when one is not already running.
        let wait = bw.charge(&self.ip, bytes, cx.sh.now_ms());
        if !self.throttled {
            self.pending_throttle_ms = self.pending_throttle_ms.max(wait);
        }
    }

    /// Mark the connection for teardown; the worker frees it when the current event is done.
    pub(crate) fn close(&mut self) {
        self.closing = true;
    }

    fn backpressure(&mut self, cx: &Ctx) {
        let queued = self.wbuf.len();
        let high = cx.cfg().ws_write_high_water as usize;
        // A client that keeps asking for replies (pings) and never reads them must not grow the
        // queue without bound: past twice the high-water mark plus one message, drop it.
        if queued > high.saturating_mul(2) + cx.cfg().max_message_size as usize {
            self.closing = true;
            return;
        }
        if !self.paused && queued > high {
            self.paused = true;
            self.pause_changed = true;
        } else if self.paused && queued < high / 4 {
            self.paused = false;
            self.pause_changed = true;
        }
    }

    /// Write what the socket takes now and arm EPOLLOUT for the rest.
    pub(crate) fn flush(&mut self, cx: &Ctx) {
        if self.closing {
            return;
        }
        while !self.wbuf.is_empty() {
            match sys::send(&self.fd, self.wbuf.as_slice()) {
                Ok(n) => self.wbuf.consume(n),
                Err(Errno::INTR) => {}
                Err(e) if sys::is_would_block(e) => break,
                Err(_) => {
                    self.closing = true;
                    return;
                }
            }
        }
        if self.wbuf.is_empty() {
            self.wbuf.shrink_if_idle(1 << 20);
        }
        self.sync_interest(cx);
        self.backpressure(cx);
        if self.state == State::HttpReply && self.wbuf.is_empty() {
            self.closing = true;
        }
    }

    /// Queue one WebSocket frame whose payload is `parts` joined, and flush.
    pub(crate) fn send_frame(&mut self, cx: &Ctx, opcode: u8, parts: &[&[u8]]) {
        if self.closing {
            return;
        }
        let len: usize = parts.iter().map(|p| p.len()).sum();
        let mut hdr = [0u8; ws::MAX_HEADER];
        let hl = ws::write_header(&mut hdr, true, opcode, len as u64, None);
        // With nothing queued and a single payload part, hand header and payload to the kernel
        // in one gathered write and only queue what it did not take.
        if self.wbuf.is_empty() && parts.len() == 1 {
            let total = hl + len;
            match sys::send_pair(&self.fd, &hdr[..hl], parts[0]) {
                Ok(n) if n == total => {
                    self.after_direct(cx);
                    return;
                }
                Ok(n) => {
                    if n < hl {
                        self.wbuf.push(&hdr[n..hl]);
                        self.wbuf.push(parts[0]);
                    } else {
                        self.wbuf.push(&parts[0][n - hl..]);
                    }
                }
                Err(e) if !fail_reason(e) => {
                    self.wbuf.push(&hdr[..hl]);
                    self.wbuf.push(parts[0]);
                }
                Err(_) => {
                    self.closing = true;
                    return;
                }
            }
            self.flush(cx);
            return;
        }
        self.wbuf.push(&hdr[..hl]);
        for p in parts {
            self.wbuf.push(p);
        }
        self.flush(cx);
    }

    fn after_direct(&mut self, cx: &Ctx) {
        if self.state == State::HttpReply {
            self.closing = true;
        } else {
            self.backpressure(cx);
        }
    }

    pub(crate) fn send_packet(&mut self, cx: &Ctx, packet: &[u8]) {
        self.send_frame(cx, ws::opcode::BINARY, &[packet]);
    }

    pub(crate) fn send_continue(&mut self, cx: &Ctx, sid: u32, remaining: u32) {
        let p = wisp::build_continue(sid, remaining);
        self.send_packet(cx, &p);
    }

    pub(crate) fn send_close(&mut self, cx: &Ctx, sid: u32, reason: u8) {
        let p = wisp::build_close(sid, reason);
        self.send_packet(cx, &p);
    }

    /// DATA for the client, split so no frame exceeds `max-message-size`.
    pub(crate) fn send_data(&mut self, cx: &Ctx, sid: u32, data: &[u8]) {
        let max = (cx.cfg().max_message_size as usize)
            .saturating_sub(wisp::HEADER_LEN)
            .max(1);
        let mut rest = data;
        loop {
            let n = rest.len().min(max);
            self.send_data_frame(cx, sid, &rest[..n]);
            rest = &rest[n..];
            if rest.is_empty() || self.closing {
                break;
            }
        }
        Stats::add(&cx.sh.stats.bytes_out, data.len() as u64);
        self.charge_bandwidth(cx, data.len());
    }

    fn send_data_frame(&mut self, cx: &Ctx, sid: u32, payload: &[u8]) {
        let (hdr, hl) = data_header(sid, payload.len());
        if self.closing {
            return;
        }
        if self.wbuf.is_empty() {
            match sys::send_pair(&self.fd, &hdr[..hl], payload) {
                Ok(n) if n == hl + payload.len() => {
                    self.backpressure(cx);
                    return;
                }
                Ok(n) if n >= hl => self.wbuf.push(&payload[n - hl..]),
                Ok(n) => {
                    self.wbuf.push(&hdr[n..hl]);
                    self.wbuf.push(payload);
                }
                Err(e) if !fail_reason(e) => {
                    self.wbuf.push(&hdr[..hl]);
                    self.wbuf.push(payload);
                }
                Err(_) => {
                    self.closing = true;
                    return;
                }
            }
        } else {
            self.wbuf.push(&hdr[..hl]);
            self.wbuf.push(payload);
        }
        self.flush(cx);
    }

    /// Remote data already sitting in the worker's pipe goes to the client without passing through
    /// user space: the headers go out with MSG_MORE, then the payload is spliced after them. If the
    /// client socket takes only part, the rest is moved into the write queue in order.
    ///
    /// Requires an empty write queue, so ordering with queued frames is never in question.
    pub(crate) fn splice_data(&mut self, cx: &Ctx, sid: u32, n: usize) {
        let Some((pr, _)) = cx.pipe.as_ref() else {
            self.closing = true;
            return;
        };
        let (hdr, hl) = data_header(sid, n);
        let sent = match sys::send_more(&self.fd, &hdr[..hl]) {
            Ok(k) => k,
            Err(e) if !fail_reason(e) => 0,
            Err(_) => {
                self.closing = true;
                self.drain_pipe(pr, n, false);
                return;
            }
        };
        if sent < hl {
            self.wbuf.push(&hdr[sent..hl]);
        }
        let mut left = n;
        if self.wbuf.is_empty() {
            while left > 0 {
                match sys::splice_from_pipe(pr, self.fd.as_fd(), left) {
                    Ok(0) => break,
                    Ok(k) => left -= k,
                    Err(Errno::INTR) => {}
                    Err(_) => break,
                }
            }
        }
        if left > 0 && !self.drain_pipe(pr, left, true) {
            self.closing = true;
            return;
        }
        Stats::add(&cx.sh.stats.bytes_out, n as u64);
        self.charge_bandwidth(cx, n);
        if !self.wbuf.is_empty() {
            self.flush(cx);
        } else {
            self.backpressure(cx);
        }
    }

    /// Move exactly `left` bytes from the pipe into the write queue (or discard them).
    fn drain_pipe(&mut self, pr: &OwnedFd, mut left: usize, keep: bool) -> bool {
        let mut tmp = [0u8; 16 * 1024];
        while left > 0 {
            let want = left.min(tmp.len());
            match sys::read_fd(pr, &mut tmp[..want]) {
                Ok(0) => return false,
                Ok(k) => {
                    if keep {
                        self.wbuf.push(&tmp[..k]);
                    }
                    left -= k;
                }
                Err(Errno::INTR) => {}
                Err(_) => return false,
            }
        }
        true
    }
}
