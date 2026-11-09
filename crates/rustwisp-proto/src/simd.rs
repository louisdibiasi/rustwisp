//! WebSocket payload unmasking, with SIMD fast paths.
//!
//! This is one of the two places in the project that may use `unsafe` (the other is the syscall
//! layer in the server). Every vector path is checked against the scalar reference in the tests,
//! for every length and alignment that matters.

#![allow(unsafe_code)]

/// XOR `data` with the 4-byte `mask`, starting `offset` bytes into the mask cycle.
///
/// The offset lets a payload that arrives in several reads be unmasked piece by piece.
pub fn unmask(data: &mut [u8], mask: [u8; 4], offset: usize) {
    let key = rotate(mask, offset);
    unmask_aligned(data, key);
}

/// `mask` rotated so that `key[i]` is the mask byte for payload byte `offset + i`.
fn rotate(mask: [u8; 4], offset: usize) -> [u8; 4] {
    let o = offset & 3;
    [
        mask[o],
        mask[(o + 1) & 3],
        mask[(o + 2) & 3],
        mask[(o + 3) & 3],
    ]
}

/// `key` already starts at payload byte 0 of `data`.
fn unmask_aligned(data: &mut [u8], key: [u8; 4]) {
    #[cfg(target_arch = "x86_64")]
    {
        if data.len() >= 64 && std::is_x86_feature_detected!("avx2") {
            // SAFETY: the avx2 feature was just detected at run time.
            unsafe { unmask_avx2(data, key) };
            return;
        }
        if data.len() >= 32 {
            // SAFETY: SSE2 is part of the x86_64 baseline.
            unsafe { unmask_sse2(data, key) };
            return;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if data.len() >= 32 {
            // SAFETY: NEON is part of the aarch64 baseline.
            unsafe { unmask_neon(data, key) };
            return;
        }
    }
    unmask_scalar(data, key);
}

/// Portable reference: 8 bytes per step, then the tail byte by byte.
pub fn unmask_scalar(data: &mut [u8], key: [u8; 4]) {
    let wide = u64::from_ne_bytes([
        key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3],
    ]);
    let mut chunks = data.chunks_exact_mut(8);
    for c in &mut chunks {
        let v = u64::from_ne_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]) ^ wide;
        c.copy_from_slice(&v.to_ne_bytes());
    }
    // 8 is a multiple of 4, so the tail starts at key phase 0.
    for (i, b) in chunks.into_remainder().iter_mut().enumerate() {
        *b ^= key[i & 3];
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn unmask_avx2(data: &mut [u8], key: [u8; 4]) {
    use std::arch::x86_64::{
        __m256i, _mm256_loadu_si256, _mm256_set1_epi32, _mm256_storeu_si256, _mm256_xor_si256,
    };
    let k = _mm256_set1_epi32(i32::from_ne_bytes(key));
    let mut chunks = data.chunks_exact_mut(32);
    for c in &mut chunks {
        let p = c.as_mut_ptr().cast::<__m256i>();
        // SAFETY: `c` is exactly 32 bytes; unaligned load/store are used.
        unsafe { _mm256_storeu_si256(p, _mm256_xor_si256(_mm256_loadu_si256(p), k)) };
    }
    unmask_scalar(chunks.into_remainder(), key);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn unmask_sse2(data: &mut [u8], key: [u8; 4]) {
    use std::arch::x86_64::{
        __m128i, _mm_loadu_si128, _mm_set1_epi32, _mm_storeu_si128, _mm_xor_si128,
    };
    let k = _mm_set1_epi32(i32::from_ne_bytes(key));
    let mut chunks = data.chunks_exact_mut(16);
    for c in &mut chunks {
        let p = c.as_mut_ptr().cast::<__m128i>();
        // SAFETY: `c` is exactly 16 bytes; unaligned load/store are used.
        unsafe { _mm_storeu_si128(p, _mm_xor_si128(_mm_loadu_si128(p), k)) };
    }
    unmask_scalar(chunks.into_remainder(), key);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn unmask_neon(data: &mut [u8], key: [u8; 4]) {
    use std::arch::aarch64::{veorq_u8, vld1q_u8, vst1q_u8};
    let wide = [
        key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3], key[0], key[1], key[2],
        key[3], key[0], key[1], key[2], key[3],
    ];
    // SAFETY: `wide` is 16 bytes.
    let k = unsafe { vld1q_u8(wide.as_ptr()) };
    let mut chunks = data.chunks_exact_mut(16);
    for c in &mut chunks {
        // SAFETY: `c` is exactly 16 bytes.
        unsafe { vst1q_u8(c.as_mut_ptr(), veorq_u8(vld1q_u8(c.as_ptr()), k)) };
    }
    unmask_scalar(chunks.into_remainder(), key);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(data: &[u8], mask: [u8; 4], offset: usize) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[(offset + i) & 3])
            .collect()
    }

    /// Small deterministic generator so the tests need no dependencies.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    #[test]
    fn matches_the_naive_loop_for_every_small_length_and_offset() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for len in 0..300 {
            for offset in 0..8 {
                let data = rng.bytes(len);
                let m = rng.bytes(4);
                let mask = [m[0], m[1], m[2], m[3]];
                let want = reference(&data, mask, offset);
                let mut got = data.clone();
                unmask(&mut got, mask, offset);
                assert_eq!(got, want, "len {len} offset {offset}");
            }
        }
    }

    #[test]
    fn matches_on_large_and_unaligned_buffers() {
        let mut rng = Rng(42);
        for len in [1000, 4096, 65_536, 65_537, 1_048_581] {
            for skew in 0..4 {
                let backing = rng.bytes(len + skew);
                let m = rng.bytes(4);
                let mask = [m[0], m[1], m[2], m[3]];
                let want = reference(&backing[skew..], mask, 1);
                let mut work = backing.clone();
                unmask(&mut work[skew..], mask, 1);
                assert_eq!(&work[skew..], &want[..], "len {len} skew {skew}");
                assert_eq!(
                    &work[..skew],
                    &backing[..skew],
                    "bytes before the slice were touched"
                );
            }
        }
    }

    #[test]
    fn unmasking_twice_restores_the_input() {
        let mut rng = Rng(7);
        let orig = rng.bytes(5000);
        let mut d = orig.clone();
        let mask = [0xde, 0xad, 0xbe, 0xef];
        unmask(&mut d, mask, 0);
        assert_ne!(d, orig);
        unmask(&mut d, mask, 0);
        assert_eq!(d, orig);
    }

    #[test]
    fn piecewise_unmask_equals_whole() {
        let mut rng = Rng(99);
        let orig = rng.bytes(1000);
        let mask = [1, 2, 3, 4];
        let mut whole = orig.clone();
        unmask(&mut whole, mask, 0);
        let mut parts = orig.clone();
        let mut at = 0;
        for step in [1usize, 2, 3, 5, 7, 100, 333, 549] {
            let end = (at + step).min(parts.len());
            unmask(&mut parts[at..end], mask, at);
            at = end;
        }
        assert_eq!(at, parts.len());
        assert_eq!(parts, whole);
    }

    #[test]
    fn scalar_path_agrees_with_dispatch() {
        let mut rng = Rng(5);
        let data = rng.bytes(777);
        let key = [9, 8, 7, 6];
        let mut a = data.clone();
        let mut b = data;
        unmask_scalar(&mut a, key);
        unmask(&mut b, key, 0);
        assert_eq!(a, b);
    }
}
