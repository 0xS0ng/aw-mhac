//! RFC 9380 hash-to-curve suites and hash_to_field for the scalar field.

use ff::Field;
use sha2::{Digest, Sha256};

use crate::common::{F, G1, G2};
use crate::update_counts;

pub fn hash_to_g1(message: &[u8], dst: &[u8]) -> G1 {
    update_counts(|c| c.hash_g1 += 1);
    G1::hash_to_curve(message, dst, b"")
}

pub fn hash_to_g2(message: &[u8], dst: &[u8]) -> G2 {
    update_counts(|c| c.hash_g2 += 1);
    G2::hash_to_curve(message, dst, b"")
}

pub fn expand_message_xmd(message: &[u8], dst: &[u8], length: usize) -> Vec<u8> {
    let count = length.div_ceil(32);
    assert!((1..=255).contains(&count));
    let long_dst;
    let dst = if dst.len() > 255 {
        let mut h = Sha256::new();
        h.update(b"H2C-OVERSIZE-DST-");
        h.update(dst);
        long_dst = h.finalize();
        &long_dst[..]
    } else {
        dst
    };
    let dst_length = [dst.len() as u8];
    let mut h = Sha256::new();
    h.update([0; 64]);
    h.update(message);
    h.update((length as u16).to_be_bytes());
    h.update([0]);
    h.update(dst);
    h.update(dst_length);
    let b0 = h.finalize();
    let mut bytes = Vec::with_capacity(count * 32);
    let mut block = [0; 32];
    for index in 1..=count {
        let mut input: [u8; 32] = b0.into();
        if index > 1 {
            for (x, y) in input.iter_mut().zip(block) {
                *x ^= y;
            }
        }
        let mut h = Sha256::new();
        h.update(input);
        h.update([index as u8]);
        h.update(dst);
        h.update(dst_length);
        block = h.finalize().into();
        bytes.extend_from_slice(&block);
    }
    bytes.truncate(length);
    bytes
}

pub fn hash_to_scalar(message: &[u8], dst: &[u8]) -> F {
    update_counts(|c| c.hash_scalar += 1);
    // RFC 9380, Section 5.2: L = ceil((255 + 128)/8) = 48.
    let expanded = expand_message_xmd(message, dst, 48);
    let radix = F::from(u64::MAX) + F::ONE;
    expanded.chunks_exact(8).fold(F::ZERO, |acc, word| {
        acc * radix + F::from(u64::from_be_bytes(word.try_into().unwrap()))
    })
}
