#![no_main]
//! The vectorised unmask agrees with the obvious byte-by-byte loop for every length, alignment and
//! starting offset. Input layout: 4 mask bytes, 1 offset byte, then the payload.

use rustwisp_proto::simd;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((head, payload)) = data.split_at_checked(5) else {
        return;
    };
    let mask = [head[0], head[1], head[2], head[3]];
    let offset = usize::from(head[4]);

    let mut fast = payload.to_vec();
    simd::unmask(&mut fast, mask, offset);

    let mut slow = payload.to_vec();
    for (i, b) in slow.iter_mut().enumerate() {
        *b ^= mask[(i + offset) % 4];
    }
    assert_eq!(fast, slow);

    simd::unmask(&mut fast, mask, offset);
    assert_eq!(fast, payload);

    if offset == 0 {
        let mut scalar = payload.to_vec();
        simd::unmask_scalar(&mut scalar, mask);
        assert_eq!(scalar, slow);
    }
});
