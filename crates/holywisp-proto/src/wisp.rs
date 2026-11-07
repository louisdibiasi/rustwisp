//! Wisp v1/v2 packets: one type byte, a little-endian u32 stream id, then the payload.
//! Spec: <https://github.com/MercuryWorkshop/wisp-protocol>.

use crate::ProtoError;

pub const HEADER_LEN: usize = 5;
pub const MAJOR: u8 = 2;
pub const MINOR: u8 = 1;
pub const V2_PROTOCOL: &str = "wisp-v2";

/// Packet type bytes.
pub mod ptype {
    pub const CONNECT: u8 = 0x01;
    pub const DATA: u8 = 0x02;
    pub const CONTINUE: u8 = 0x03;
    pub const CLOSE: u8 = 0x04;
    pub const INFO: u8 = 0x05;
}

/// Stream type bytes carried in a CONNECT packet.
pub mod stream_type {
    pub const TCP: u8 = 0x01;
    pub const UDP: u8 = 0x02;
    /// Twisp: a PTY running the command named in the hostname field.
    pub const TERM: u8 = 0x03;
}

/// Twisp resize: payload is rows (u16 LE) then cols (u16 LE).
pub const TWISP_RESIZE: u8 = 0xF0;

/// CLOSE reason bytes.
pub mod close {
    pub const UNKNOWN: u8 = 0x01;
    pub const VOLUNTARY: u8 = 0x02;
    pub const NETWORK_ERROR: u8 = 0x03;
    pub const INCOMPATIBLE: u8 = 0x04;
    pub const INVALID_INFO: u8 = 0x41;
    pub const UNREACHABLE: u8 = 0x42;
    pub const NO_RESPONSE: u8 = 0x43;
    pub const REFUSED: u8 = 0x44;
    pub const TRANSFER_TIMEOUT: u8 = 0x47;
    pub const BLOCKED: u8 = 0x48;
    pub const THROTTLED: u8 = 0x49;
    pub const CLIENT_ERROR: u8 = 0x81;
    pub const AUTH_BAD_PASSWORD: u8 = 0xc0;
    pub const AUTH_BAD_SIGNATURE: u8 = 0xc1;
    pub const AUTH_REQUIRED: u8 = 0xc2;
}

/// v2 extension ids.
pub mod ext {
    pub const UDP: u8 = 0x01;
    pub const PASSWORD: u8 = 0x02;
    pub const CERTIFICATE: u8 = 0x03;
    pub const MOTD: u8 = 0x04;
    pub const STREAM_CONFIRM: u8 = 0x05;
}

/// A parsed packet. `payload` borrows from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub ptype: u8,
    pub stream_id: u32,
    pub payload: &'a [u8],
}

/// A parsed CONNECT payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connect<'a> {
    pub stream_type: u8,
    pub port: u16,
    /// Not guaranteed to be UTF-8; callers validate before resolving.
    pub host: &'a [u8],
}

/// Everything an INFO packet can say, in either direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Info<'a> {
    pub major: u8,
    pub minor: u8,
    pub has_udp: bool,
    pub has_stream_confirm: bool,
    /// The password extension is present.
    pub has_password: bool,
    /// Server to client: the single meta byte, "a password is required".
    pub password_required: bool,
    /// Client to server credentials.
    pub user: Option<&'a [u8]>,
    pub pass: Option<&'a [u8]>,
    pub motd: Option<&'a [u8]>,
}

#[inline]
pub fn le32(p: &[u8]) -> u32 {
    u32::from_le_bytes([p[0], p[1], p[2], p[3]])
}

#[inline]
pub fn le16(p: &[u8]) -> u16 {
    u16::from_le_bytes([p[0], p[1]])
}

/// Split a message into its packet header and payload.
pub fn parse(data: &[u8]) -> Result<Packet<'_>, ProtoError> {
    if data.len() < HEADER_LEN {
        return Err(ProtoError::Invalid);
    }
    Ok(Packet {
        ptype: data[0],
        stream_id: le32(&data[1..5]),
        payload: &data[HEADER_LEN..],
    })
}

/// Read a CONNECT payload: stream type, port, hostname.
pub fn parse_connect<'a>(p: &Packet<'a>) -> Result<Connect<'a>, ProtoError> {
    if p.payload.len() < 3 {
        return Err(ProtoError::Invalid);
    }
    Ok(Connect {
        stream_type: p.payload[0],
        port: le16(&p.payload[1..3]),
        host: &p.payload[3..],
    })
}

/// Read an INFO payload. Unknown extensions are skipped, as the spec asks.
pub fn parse_info<'a>(p: &Packet<'a>) -> Result<Info<'a>, ProtoError> {
    if p.payload.len() < 2 {
        return Err(ProtoError::Invalid);
    }
    let mut out = Info {
        major: p.payload[0],
        minor: p.payload[1],
        ..Info::default()
    };
    let mut rest = &p.payload[2..];
    while !rest.is_empty() {
        if rest.len() < 5 {
            return Err(ProtoError::Invalid);
        }
        let id = rest[0];
        let meta_len = le32(&rest[1..5]) as usize;
        rest = &rest[5..];
        if meta_len > rest.len() {
            return Err(ProtoError::Invalid);
        }
        let (meta, tail) = rest.split_at(meta_len);
        match id {
            ext::UDP => out.has_udp = true,
            ext::STREAM_CONFIRM => out.has_stream_confirm = true,
            ext::MOTD => out.motd = Some(meta),
            ext::PASSWORD => {
                out.has_password = true;
                if meta.len() == 1 {
                    out.password_required = meta[0] != 0;
                } else if !meta.is_empty() {
                    let ulen = meta[0] as usize;
                    if 1 + ulen > meta.len() {
                        return Err(ProtoError::Invalid);
                    }
                    out.user = Some(&meta[1..1 + ulen]);
                    out.pass = Some(&meta[1 + ulen..]);
                }
            }
            _ => {}
        }
        rest = tail;
    }
    Ok(out)
}

/// Write the five header bytes.
pub fn write_header(out: &mut [u8; HEADER_LEN], ptype: u8, stream_id: u32) {
    out[0] = ptype;
    out[1..5].copy_from_slice(&stream_id.to_le_bytes());
}

/// Build a CONNECT packet. Returns the length written, or `None` when `out` is too small.
pub fn build_connect(
    out: &mut [u8],
    stream_id: u32,
    stream_type: u8,
    port: u16,
    host: &[u8],
) -> Option<usize> {
    let need = HEADER_LEN + 3 + host.len();
    if out.len() < need {
        return None;
    }
    let mut head = [0u8; HEADER_LEN];
    write_header(&mut head, ptype::CONNECT, stream_id);
    out[..HEADER_LEN].copy_from_slice(&head);
    out[5] = stream_type;
    out[6..8].copy_from_slice(&port.to_le_bytes());
    out[8..need].copy_from_slice(host);
    Some(need)
}

/// A CONTINUE packet: the stream may send `buffer_remaining` more packets.
pub fn build_continue(stream_id: u32, buffer_remaining: u32) -> [u8; HEADER_LEN + 4] {
    let mut out = [0u8; HEADER_LEN + 4];
    out[0] = ptype::CONTINUE;
    out[1..5].copy_from_slice(&stream_id.to_le_bytes());
    out[5..9].copy_from_slice(&buffer_remaining.to_le_bytes());
    out
}

/// A CLOSE packet with a reason byte.
pub fn build_close(stream_id: u32, reason: u8) -> [u8; HEADER_LEN + 1] {
    let mut out = [0u8; HEADER_LEN + 1];
    out[0] = ptype::CLOSE;
    out[1..5].copy_from_slice(&stream_id.to_le_bytes());
    out[5] = reason;
    out
}

/// The INFO header (type, stream 0, major, minor). Append extensions with [`build_extension`].
pub fn build_info(major: u8, minor: u8) -> [u8; HEADER_LEN + 2] {
    let mut out = [0u8; HEADER_LEN + 2];
    out[0] = ptype::INFO;
    out[5] = major;
    out[6] = minor;
    out
}

/// One extension record: id, u32 LE meta length, meta bytes. `None` when `out` is too small.
pub fn build_extension(out: &mut [u8], id: u8, meta: &[u8]) -> Option<usize> {
    let need = 5 + meta.len();
    let len = u32::try_from(meta.len()).ok()?;
    if out.len() < need {
        return None;
    }
    out[0] = id;
    out[1..5].copy_from_slice(&len.to_le_bytes());
    out[5..need].copy_from_slice(meta);
    Some(need)
}

pub fn type_str(t: u8) -> &'static str {
    match t {
        ptype::CONNECT => "CONNECT",
        ptype::DATA => "DATA",
        ptype::CONTINUE => "CONTINUE",
        ptype::CLOSE => "CLOSE",
        ptype::INFO => "INFO",
        _ => "UNKNOWN",
    }
}

pub fn close_reason_str(r: u8) -> &'static str {
    match r {
        close::UNKNOWN => "unknown",
        close::VOLUNTARY => "voluntary",
        close::NETWORK_ERROR => "network error",
        close::INCOMPATIBLE => "incompatible extensions",
        close::INVALID_INFO => "invalid stream info",
        close::UNREACHABLE => "unreachable host",
        close::NO_RESPONSE => "no response",
        close::REFUSED => "connection refused",
        close::TRANSFER_TIMEOUT => "transfer timeout",
        close::BLOCKED => "host blocked",
        close::THROTTLED => "throttled",
        close::CLIENT_ERROR => "client error",
        close::AUTH_BAD_PASSWORD => "bad password",
        close::AUTH_BAD_SIGNATURE => "bad signature",
        close::AUTH_REQUIRED => "authentication required",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_header_and_payload() {
        let msg = [ptype::DATA, 7, 0, 0, 0, 0xde, 0xad];
        let p = parse(&msg).unwrap();
        assert_eq!(p.ptype, ptype::DATA);
        assert_eq!(p.stream_id, 7);
        assert_eq!(p.payload, &[0xde, 0xad]);
    }

    #[test]
    fn parse_rejects_short_input() {
        for n in 0..HEADER_LEN {
            assert_eq!(parse(&vec![0u8; n]), Err(ProtoError::Invalid));
        }
        assert_eq!(parse(&[1, 0, 0, 0, 0]).unwrap().payload.len(), 0);
    }

    #[test]
    fn stream_id_is_little_endian() {
        let msg = [ptype::DATA, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(parse(&msg).unwrap().stream_id, 0x1234_5678);
    }

    #[test]
    fn connect_round_trips() {
        let mut buf = [0u8; 64];
        let n = build_connect(&mut buf, 3, stream_type::TCP, 443, b"example.org").unwrap();
        let p = parse(&buf[..n]).unwrap();
        assert_eq!(p.ptype, ptype::CONNECT);
        assert_eq!(p.stream_id, 3);
        let c = parse_connect(&p).unwrap();
        assert_eq!(c.stream_type, stream_type::TCP);
        assert_eq!(c.port, 443);
        assert_eq!(c.host, b"example.org");
    }

    #[test]
    fn connect_needs_three_payload_bytes() {
        let p = Packet {
            ptype: ptype::CONNECT,
            stream_id: 1,
            payload: &[1, 0],
        };
        assert_eq!(parse_connect(&p), Err(ProtoError::Invalid));
        let p = Packet {
            ptype: ptype::CONNECT,
            stream_id: 1,
            payload: &[1, 0x50, 0],
        };
        assert_eq!(parse_connect(&p).unwrap().host, b"");
    }

    #[test]
    fn build_connect_reports_a_small_buffer() {
        let mut buf = [0u8; 10];
        assert_eq!(build_connect(&mut buf, 1, 1, 80, b"example.org"), None);
        let mut exact = [0u8; 8 + 3];
        assert_eq!(build_connect(&mut exact, 1, 1, 80, b"abc"), Some(11));
    }

    #[test]
    fn continue_and_close_layout() {
        let c = build_continue(9, 128);
        assert_eq!(c, [3, 9, 0, 0, 0, 128, 0, 0, 0]);
        let x = build_close(9, close::VOLUNTARY);
        assert_eq!(x, [4, 9, 0, 0, 0, 2]);
    }

    fn info_packet(extra: &[u8]) -> Vec<u8> {
        let mut v = build_info(MAJOR, MINOR).to_vec();
        v.extend_from_slice(extra);
        v
    }

    #[test]
    fn info_with_no_extensions() {
        let msg = info_packet(&[]);
        let p = parse(&msg).unwrap();
        let i = parse_info(&p).unwrap();
        assert_eq!((i.major, i.minor), (MAJOR, MINOR));
        assert!(!i.has_udp && !i.has_password && i.motd.is_none());
    }

    #[test]
    fn info_reads_flags_motd_and_skips_unknown() {
        let mut ext_bytes = Vec::new();
        let mut tmp = [0u8; 64];
        for (id, meta) in [
            (ext::UDP, &b""[..]),
            (0x77, &b"ignored"[..]),
            (ext::MOTD, &b"hello"[..]),
            (ext::STREAM_CONFIRM, &b""[..]),
        ] {
            let n = build_extension(&mut tmp, id, meta).unwrap();
            ext_bytes.extend_from_slice(&tmp[..n]);
        }
        let msg = info_packet(&ext_bytes);
        let i = parse_info(&parse(&msg).unwrap()).unwrap();
        assert!(i.has_udp && i.has_stream_confirm);
        assert_eq!(i.motd, Some(&b"hello"[..]));
    }

    #[test]
    fn info_password_both_directions() {
        let mut tmp = [0u8; 64];
        let n = build_extension(&mut tmp, ext::PASSWORD, &[1]).unwrap();
        let msg = info_packet(&tmp[..n]);
        let i = parse_info(&parse(&msg).unwrap()).unwrap();
        assert!(i.has_password && i.password_required && i.user.is_none());

        let mut meta = vec![5u8];
        meta.extend_from_slice(b"alice");
        meta.extend_from_slice(b"s3cret");
        let n = build_extension(&mut tmp, ext::PASSWORD, &meta).unwrap();
        let msg = info_packet(&tmp[..n]);
        let i = parse_info(&parse(&msg).unwrap()).unwrap();
        assert_eq!(i.user, Some(&b"alice"[..]));
        assert_eq!(i.pass, Some(&b"s3cret"[..]));
    }

    #[test]
    fn info_rejects_truncation() {
        // meta length larger than what is left
        let msg = info_packet(&[ext::MOTD, 9, 0, 0, 0, b'x']);
        assert_eq!(parse_info(&parse(&msg).unwrap()), Err(ProtoError::Invalid));
        // header cut short
        let msg = info_packet(&[ext::MOTD, 0, 0]);
        assert_eq!(parse_info(&parse(&msg).unwrap()), Err(ProtoError::Invalid));
        // username length overruns the meta
        let msg = info_packet(&[ext::PASSWORD, 3, 0, 0, 0, 9, b'a', b'b']);
        assert_eq!(parse_info(&parse(&msg).unwrap()), Err(ProtoError::Invalid));
        // payload shorter than major+minor
        let p = Packet {
            ptype: ptype::INFO,
            stream_id: 0,
            payload: &[2],
        };
        assert_eq!(parse_info(&p), Err(ProtoError::Invalid));
    }

    #[test]
    fn build_extension_reports_a_small_buffer() {
        let mut tmp = [0u8; 6];
        assert_eq!(build_extension(&mut tmp, 1, b"ab"), None);
        assert_eq!(build_extension(&mut tmp, 1, b"a"), Some(6));
    }

    #[test]
    fn names() {
        assert_eq!(type_str(ptype::DATA), "DATA");
        assert_eq!(type_str(0xff), "UNKNOWN");
        assert_eq!(close_reason_str(close::BLOCKED), "host blocked");
        assert_eq!(close_reason_str(0), "?");
    }
}
