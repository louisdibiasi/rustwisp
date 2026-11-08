//! Thin, non-blocking wrappers over the Linux calls the server uses: epoll, accept4, listeners with
//! SO_REUSEPORT, splice and pipes, `send` with `MSG_MORE`. Built on `rustix`, so the only `unsafe`
//! in this file is the signal handler.

#![allow(unsafe_code)]

use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use rustix::event::epoll::{self, CreateFlags, Event, EventData};
use rustix::event::{EventfdFlags, eventfd};
use rustix::net::{
    AddressFamily, RecvFlags, SendAncillaryBuffer, SendFlags, SocketFlags, SocketType, sockopt,
};
use rustix::pipe::{PipeFlags, SpliceFlags};
use rustix::time::Timespec;

pub use rustix::event::epoll::EventFlags;
pub use rustix::io::Errno;

pub type Res<T> = Result<T, Errno>;

/// `EventFlags` for "readable".
pub const IN: EventFlags = EventFlags::IN;
pub const OUT: EventFlags = EventFlags::OUT;

pub fn is_would_block(e: Errno) -> bool {
    e == Errno::AGAIN || e == Errno::WOULDBLOCK
}

// ------------------------------------------------------------------------------------- epoll

pub fn epoll_new() -> Res<OwnedFd> {
    epoll::create(CreateFlags::CLOEXEC)
}

pub fn epoll_add(ep: &OwnedFd, fd: impl AsFd, token: u64, flags: EventFlags) -> Res<()> {
    epoll::add(ep, fd, EventData::new_u64(token), flags)
}

pub fn epoll_mod(ep: &OwnedFd, fd: impl AsFd, token: u64, flags: EventFlags) -> Res<()> {
    epoll::modify(ep, fd, EventData::new_u64(token), flags)
}

pub fn epoll_del(ep: &OwnedFd, fd: impl AsFd) -> Res<()> {
    epoll::delete(ep, fd)
}

/// Wait for events; `timeout` of `None` blocks. Fills `out` with `(token, flags)`.
pub fn epoll_wait(
    ep: &OwnedFd,
    scratch: &mut Vec<Event>,
    out: &mut Vec<(u64, EventFlags)>,
    timeout: Option<Duration>,
) -> Res<()> {
    out.clear();
    scratch.clear();
    let ts = timeout.map(|d| Timespec {
        tv_sec: d.as_secs() as _,
        tv_nsec: d.subsec_nanos() as _,
    });
    match epoll::wait(ep, rustix::buffer::spare_capacity(scratch), ts.as_ref()) {
        Ok(_) => {
            out.extend(scratch.iter().map(|e| (e.data.u64(), e.flags)));
            Ok(())
        }
        Err(Errno::INTR) => Ok(()),
        Err(e) => Err(e),
    }
}

// ------------------------------------------------------------------------------------- eventfd

pub fn wake_fd() -> Res<OwnedFd> {
    eventfd(0, EventfdFlags::NONBLOCK | EventfdFlags::CLOEXEC)
}

pub fn wake(fd: impl AsFd) {
    let _ = rustix::io::write(fd, &1u64.to_ne_bytes());
}

/// Reset an eventfd after it fired.
pub fn drain_wake(fd: impl AsFd) {
    let mut b = [0u8; 8];
    let _ = rustix::io::read(fd, &mut b);
}

// ------------------------------------------------------------------------------------- sockets

fn domain(addr: &SocketAddr) -> AddressFamily {
    match addr {
        SocketAddr::V4(_) => AddressFamily::INET,
        SocketAddr::V6(_) => AddressFamily::INET6,
    }
}

/// A non-blocking, close-on-exec TCP or UDP socket for `addr`'s family.
pub fn socket_nb(addr: &SocketAddr, udp: bool) -> Res<OwnedFd> {
    let ty = if udp {
        SocketType::DGRAM
    } else {
        SocketType::STREAM
    };
    rustix::net::socket_with(
        domain(addr),
        ty,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )
}

pub fn connect(fd: &OwnedFd, addr: &SocketAddr) -> Res<()> {
    rustix::net::connect(fd, addr)
}

pub fn so_error(fd: &OwnedFd) -> Res<()> {
    sockopt::socket_error(fd)?
}

fn bind_listener(addr: SocketAddr, backlog: i32) -> Res<OwnedFd> {
    let fd = socket_nb(&addr, false)?;
    sockopt::set_socket_reuseaddr(&fd, true)?;
    sockopt::set_socket_reuseport(&fd, true)?;
    if addr.is_ipv6() {
        sockopt::set_ipv6_v6only(&fd, false)?;
    }
    rustix::net::bind(&fd, &addr)?;
    rustix::net::listen(&fd, backlog)?;
    Ok(fd)
}

/// A listener with SO_REUSEPORT so every worker can bind the same port. An empty `host` means every
/// interface, dual-stack when IPv6 is available.
pub fn listen_tcp(host: &str, port: u16, backlog: u32) -> io::Result<(OwnedFd, u16)> {
    let backlog = backlog.min(i32::MAX as u32) as i32;
    let mut candidates: Vec<SocketAddr> = Vec::new();
    if host.is_empty() {
        candidates.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port));
        candidates.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    } else {
        let h = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = h.parse::<IpAddr>() {
            candidates.push(SocketAddr::new(ip, port));
        } else {
            candidates.extend((h, port).to_socket_addrs()?);
        }
    }
    let mut last = io::Error::from(io::ErrorKind::AddrNotAvailable);
    for addr in candidates {
        match bind_listener(addr, backlog) {
            Ok(fd) => {
                let bound = rustix::net::getsockname(&fd)
                    .ok()
                    .and_then(|a| SocketAddr::try_from(a).ok())
                    .map_or(port, |a| a.port());
                return Ok((fd, bound));
            }
            Err(e) => last = io::Error::from(e),
        }
    }
    Err(last)
}

/// Accept one connection, non-blocking and close-on-exec.
pub fn accept(listener: &OwnedFd) -> Res<(OwnedFd, Option<SocketAddr>)> {
    let (fd, peer) =
        rustix::net::acceptfrom_with(listener, SocketFlags::NONBLOCK | SocketFlags::CLOEXEC)?;
    Ok((fd, peer.and_then(|a| SocketAddr::try_from(a).ok())))
}

/// Per-socket options from the config. Failures are ignored: they are tuning, not correctness.
pub fn tune_tcp(fd: &OwnedFd, nodelay: bool, quickack: bool, buffer: u32) {
    if nodelay {
        let _ = sockopt::set_tcp_nodelay(fd, true);
    }
    if quickack {
        let _ = sockopt::set_tcp_quickack(fd, true);
    }
    let _ = sockopt::set_socket_keepalive(fd, true);
    if buffer > 0 {
        let _ = sockopt::set_socket_recv_buffer_size(fd, buffer as usize);
        let _ = sockopt::set_socket_send_buffer_size(fd, buffer as usize);
    }
}

pub fn recv(fd: impl AsFd, buf: &mut [u8]) -> Res<usize> {
    let (n, _) = rustix::net::recv(fd, buf, RecvFlags::empty())?;
    Ok(n)
}

/// Look at the next bytes without taking them off the socket.
pub fn peek(fd: impl AsFd, buf: &mut [u8]) -> Res<usize> {
    let (n, _) = rustix::net::recv(fd, buf, RecvFlags::PEEK)?;
    Ok(n)
}

pub fn send(fd: impl AsFd, buf: &[u8]) -> Res<usize> {
    rustix::net::send(fd, buf, SendFlags::NOSIGNAL | SendFlags::DONTWAIT)
}

/// `send` that tells the kernel more bytes follow (so it does not emit a tiny segment).
pub fn send_more(fd: impl AsFd, buf: &[u8]) -> Res<usize> {
    rustix::net::send(
        fd,
        buf,
        SendFlags::NOSIGNAL | SendFlags::DONTWAIT | SendFlags::MORE,
    )
}

/// Send two buffers with one syscall and no copy.
pub fn send_pair(fd: impl AsFd, a: &[u8], b: &[u8]) -> Res<usize> {
    let iov = [IoSlice::new(a), IoSlice::new(b)];
    rustix::net::sendmsg(
        fd,
        &iov,
        &mut SendAncillaryBuffer::default(),
        SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
    )
}

// ------------------------------------------------------------------------------------- splice

/// A non-blocking pipe whose capacity is raised to `size` where the kernel allows it.
pub fn pipe_pair(size: usize) -> Res<(OwnedFd, OwnedFd)> {
    let (r, w) = rustix::pipe::pipe_with(PipeFlags::NONBLOCK | PipeFlags::CLOEXEC)?;
    let _ = rustix::pipe::fcntl_setpipe_size(&r, size);
    Ok((r, w))
}

/// Move up to `len` bytes from a socket into a pipe without copying through user space.
pub fn splice_to_pipe(sock: BorrowedFd<'_>, pipe_w: &OwnedFd, len: usize) -> Res<usize> {
    rustix::pipe::splice(
        sock,
        None,
        pipe_w,
        None,
        len,
        SpliceFlags::NONBLOCK | SpliceFlags::MOVE,
    )
}

/// Move up to `len` bytes from a pipe into a socket.
pub fn splice_from_pipe(pipe_r: &OwnedFd, sock: BorrowedFd<'_>, len: usize) -> Res<usize> {
    rustix::pipe::splice(
        pipe_r,
        None,
        sock,
        None,
        len,
        SpliceFlags::NONBLOCK | SpliceFlags::MOVE,
    )
}

pub fn read_fd(fd: impl AsFd, buf: &mut [u8]) -> Res<usize> {
    rustix::io::read(fd, buf)
}

// ------------------------------------------------------------------------------------- signals

static SIGNAL_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(_: libc::c_int) {
    let fd = SIGNAL_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let one = 1u64.to_ne_bytes();
        // SAFETY: write(2) is async-signal-safe; `fd` is an eventfd that stays open for the
        // life of the process and `one` is eight valid bytes.
        unsafe {
            libc::write(fd, one.as_ptr().cast(), one.len());
        }
    }
}

/// Make SIGINT and SIGTERM write to `fd` (an eventfd), and ignore SIGPIPE.
pub fn install_signal_handlers(fd: &OwnedFd) -> io::Result<()> {
    SIGNAL_FD.store(fd.as_raw_fd(), Ordering::Relaxed);
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: `sa` is zero-initialised and then given a valid handler of the signature
        // sigaction expects; the handler only calls async-signal-safe functions.
        let rc = unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut())
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: setting a signal disposition to SIG_IGN is always valid.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoll_reports_a_ready_eventfd() {
        let ep = epoll_new().unwrap();
        let w = wake_fd().unwrap();
        epoll_add(&ep, &w, 42, IN).unwrap();
        let mut scratch = Vec::with_capacity(8);
        let mut out = Vec::new();
        epoll_wait(&ep, &mut scratch, &mut out, Some(Duration::from_millis(10))).unwrap();
        assert!(out.is_empty());
        wake(&w);
        epoll_wait(&ep, &mut scratch, &mut out, None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 42);
        assert!(out[0].1.contains(IN));
    }
}
