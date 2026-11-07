//! RFC 6455 frame headers. The payload never passes through here; see [`crate::simd`] to unmask.

use crate::ProtoError;

/// Frame opcodes.
pub mod opcode {
    pub const CONTINUATION: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xA;
}

/// Largest possible header: 2 + 8 (64-bit length) + 4 (mask).
pub const MAX_HEADER: usize = 14;
/// Sec-WebSocket-Accept is always 28 characters.
pub const ACCEPT_LEN: usize = 28;
pub const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A validated frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub fin: bool,
    pub opcode: u8,
    pub masked: bool,
    pub mask: [u8; 4],
    pub payload_len: u64,
    pub header_len: usize,
}

impl FrameHeader {
    pub fn is_control(&self) -> bool {
        self.opcode >= 0x8
    }
}

/// Parse a frame header.
///
/// `Err(Again)` means the header is not all here yet; `Err(Protocol)` means it is invalid (reserved
/// bits set, unknown opcode, control frame that is fragmented or longer than 125 bytes, a length
/// that is not minimally encoded, or a 64-bit length with the top bit set).
pub fn parse_header(data: &[u8]) -> Result<FrameHeader, ProtoError> {
    if data.len() < 2 {
        return Err(ProtoError::Again);
    }
    let fin = data[0] & 0x80 != 0;
    let rsv = (data[0] >> 4) & 0x7;
    let opcode = data[0] & 0x0F;
    let masked = data[1] & 0x80 != 0;
    let code = data[1] & 0x7F;
    let ext = match code {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let header_len = 2 + ext + if masked { 4 } else { 0 };
    if data.len() < header_len {
        return Err(ProtoError::Again);
    }
    if rsv != 0 {
        return Err(ProtoError::Protocol); // no extensions are negotiated
    }
    let payload_len = match code {
        126 => {
            let n = u64::from(u16::from_be_bytes([data[2], data[3]]));
            if n < 126 {
                return Err(ProtoError::Protocol);
            }
            n
        }
        127 => {
            let n = u64::from_be_bytes([
                data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
            ]);
            if n >> 63 != 0 || n < 65_536 {
                return Err(ProtoError::Protocol);
            }
            n
        }
        n => u64::from(n),
    };
    let control = opcode >= 0x8;
    if control && (!fin || payload_len > 125) {
        return Err(ProtoError::Protocol);
    }
    if (0x3..0x8).contains(&opcode) || opcode > 0xA {
        return Err(ProtoError::Protocol);
    }
    let mut mask = [0u8; 4];
    if masked {
        mask.copy_from_slice(&data[header_len - 4..header_len]);
    }
    Ok(FrameHeader {
        fin,
        opcode,
        masked,
        mask,
        payload_len,
        header_len,
    })
}

/// Header size for a payload of `payload_len` bytes.
pub fn header_len(payload_len: u64, masked: bool) -> usize {
    let base = if payload_len > 65_535 {
        10
    } else if payload_len > 125 {
        4
    } else {
        2
    };
    base + if masked { 4 } else { 0 }
}

/// Write a header; `mask` of `None` means unmasked (server to client). Returns bytes written.
pub fn write_header(
    out: &mut [u8; MAX_HEADER],
    fin: bool,
    opcode: u8,
    payload_len: u64,
    mask: Option<[u8; 4]>,
) -> usize {
    out[0] = (if fin { 0x80 } else { 0 }) | (opcode & 0x0F);
    let mut n = 2;
    if payload_len <= 125 {
        out[1] = payload_len as u8;
    } else if payload_len <= 65_535 {
        out[1] = 126;
        out[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
        n = 4;
    } else {
        out[1] = 127;
        out[2..10].copy_from_slice(&payload_len.to_be_bytes());
        n = 10;
    }
    if let Some(m) = mask {
        out[1] |= 0x80;
        out[n..n + 4].copy_from_slice(&m);
        n += 4;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(fin: bool, op: u8, len: u64, mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut b = [0u8; MAX_HEADER];
        let n = write_header(&mut b, fin, op, len, mask);
        b[..n].to_vec()
    }

    #[test]
    fn round_trips_across_length_classes() {
        for len in [0u64, 1, 125, 126, 127, 65_535, 65_536, 1 << 20, 1 << 40] {
            for mask in [None, Some([1, 2, 3, 4])] {
                let h = header(true, opcode::BINARY, len, mask);
                assert_eq!(h.len(), header_len(len, mask.is_some()), "len {len}");
                let f = parse_header(&h).unwrap();
                assert_eq!(f.payload_len, len);
                assert_eq!(f.opcode, opcode::BINARY);
                assert!(f.fin);
                assert_eq!(f.masked, mask.is_some());
                assert_eq!(f.header_len, h.len());
                if let Some(m) = mask {
                    assert_eq!(f.mask, m);
                }
            }
        }
    }

    #[test]
    fn reports_again_until_the_whole_header_is_present() {
        let h = header(true, opcode::BINARY, 70_000, Some([9, 9, 9, 9]));
        for n in 0..h.len() {
            assert_eq!(parse_header(&h[..n]), Err(ProtoError::Again), "prefix {n}");
        }
        assert!(parse_header(&h).is_ok());
    }

    #[test]
    fn rejects_reserved_bits() {
        let mut h = header(true, opcode::BINARY, 5, None);
        for bit in [0x40, 0x20, 0x10] {
            h[0] |= bit;
            assert_eq!(parse_header(&h), Err(ProtoError::Protocol));
            h[0] &= !bit;
        }
    }

    #[test]
    fn rejects_unknown_opcodes() {
        for op in (0x3..=0x7).chain(0xB..=0xF) {
            assert_eq!(
                parse_header(&header(true, op, 0, None)),
                Err(ProtoError::Protocol),
                "op {op:#x}"
            );
        }
        for op in [0x0, 0x1, 0x2, 0x8, 0x9, 0xA] {
            assert!(
                parse_header(&header(true, op, 0, None)).is_ok(),
                "op {op:#x}"
            );
        }
    }

    #[test]
    fn control_frames_must_be_small_and_final() {
        assert_eq!(
            parse_header(&header(false, opcode::PING, 0, None)),
            Err(ProtoError::Protocol)
        );
        assert_eq!(
            parse_header(&header(true, opcode::PING, 126, None)),
            Err(ProtoError::Protocol)
        );
        assert!(parse_header(&header(true, opcode::PING, 125, None)).is_ok());
        assert!(parse_header(&header(false, opcode::TEXT, 10, None)).is_ok());
    }

    #[test]
    fn lengths_must_be_minimally_encoded() {
        // 126-form carrying 100
        assert_eq!(
            parse_header(&[0x82, 126, 0, 100]),
            Err(ProtoError::Protocol)
        );
        // 127-form carrying 65535
        let mut h = vec![0x82, 127];
        h.extend_from_slice(&65_535u64.to_be_bytes());
        assert_eq!(parse_header(&h), Err(ProtoError::Protocol));
    }

    #[test]
    fn rejects_a_64_bit_length_with_the_top_bit_set() {
        let mut h = vec![0x82, 127];
        h.extend_from_slice(&(1u64 << 63).to_be_bytes());
        assert_eq!(parse_header(&h), Err(ProtoError::Protocol));
    }

    #[test]
    fn never_panics_on_arbitrary_short_input() {
        // exhaustive over the first two bytes, then a few extension shapes
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let _ = parse_header(&[a, b]);
                let _ = parse_header(&[a, b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                let _ = parse_header(&[
                    a, b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4,
                ]);
            }
        }
    }

    #[test]
    fn write_header_sets_fin_and_opcode() {
        assert_eq!(header(true, opcode::BINARY, 5, None), vec![0x82, 5]);
        assert_eq!(header(false, opcode::TEXT, 5, None), vec![0x01, 5]);
        assert_eq!(
            header(true, opcode::CLOSE, 2, Some([1, 2, 3, 4])),
            vec![0x88, 0x82, 1, 2, 3, 4]
        );
    }
}
