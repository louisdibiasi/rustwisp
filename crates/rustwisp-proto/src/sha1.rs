//! SHA-1, only for the WebSocket accept key (RFC 6455). Not for anything security-sensitive.

/// Digest of `data`.
pub fn digest(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut chunks = data.chunks_exact(64);
    for block in &mut chunks {
        compress(&mut h, block);
    }
    let rest = chunks.remainder();
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let total = if rest.len() < 56 { 64 } else { 128 };
    let bits = (data.len() as u64).wrapping_mul(8);
    tail[total - 8..total].copy_from_slice(&bits.to_be_bytes());
    for block in tail[..total].chunks_exact(64) {
        compress(&mut h, block);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn compress(h: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    for (i, c) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6u32),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: [u8; 20]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn known_vectors() {
        assert_eq!(hex(digest(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn million_a() {
        let data = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(digest(&data)),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn padding_boundaries() {
        // lengths around the 55/56/63/64 byte padding edges must not panic and must differ
        let mut seen = std::collections::HashSet::new();
        for n in 50..70 {
            assert!(seen.insert(digest(&vec![b'x'; n])));
        }
    }
}
