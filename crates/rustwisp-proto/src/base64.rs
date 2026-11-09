//! Standard base64 with padding, enough for the WebSocket handshake.

const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Number of characters `encode` produces for `n` input bytes.
pub const fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Encode `input` into `out`, which must hold at least `encoded_len(input.len())` bytes.
/// Returns the number of bytes written.
///
/// # Panics
/// Panics when `out` is too small.
pub fn encode_into(input: &[u8], out: &mut [u8]) -> usize {
    let need = encoded_len(input.len());
    assert!(out.len() >= need, "output buffer too small");
    let mut o = 0;
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out[o] = TABLE[(n >> 18) as usize & 63];
        out[o + 1] = TABLE[(n >> 12) as usize & 63];
        out[o + 2] = if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63]
        } else {
            b'='
        };
        out[o + 3] = if chunk.len() > 2 {
            TABLE[n as usize & 63]
        } else {
            b'='
        };
        o += 4;
    }
    o
}

/// Encode to a new string.
pub fn encode(input: &[u8]) -> String {
    let mut out = vec![0u8; encoded_len(input.len())];
    let n = encode_into(input, &mut out);
    out.truncate(n);
    // The table is ASCII, so this cannot fail.
    String::from_utf8(out).unwrap_or_default()
}

fn value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode padded base64. `None` on any malformed input.
pub fn decode(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let last = input.len() / 4;
    for (i, q) in input.chunks_exact(4).enumerate() {
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &q[..4 - pad] {
            n = n << 6 | value(c)?;
        }
        n <<= 6 * pad as u32;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), enc);
            assert_eq!(decode(enc.as_bytes()).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn round_trips_every_length() {
        for n in 0..200 {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(decode(encode(&data).as_bytes()).unwrap(), data);
        }
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in ["Zg=", "Z", "Zg==Zg==", "Z===", "Zm9v!A==", "=Zm9"] {
            assert_eq!(decode(bad.as_bytes()), None, "{bad}");
        }
    }
}
