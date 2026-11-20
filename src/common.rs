//! Canonical BLS12-381 encodings and benchmark transcripts.

use ff::Field;
use sha2::{Digest, Sha256};

pub use blstrs::{G1Projective as G1, G2Projective as G2, Scalar as F};
pub use rand::rngs::StdRng as Rng;
pub type Res<T> = Result<T, String>;

#[derive(Clone)]
pub struct Transcript {
    dst: Vec<u8>,
    bytes: Vec<u8>,
}

impl Transcript {
    pub fn new(label: &str) -> Self {
        Self {
            dst: label.as_bytes().to_vec(),
            bytes: Vec::new(),
        }
    }
    pub fn add(&mut self, field: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(field);
        self
    }
    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.add(&value.to_be_bytes())
    }
    pub fn g1(&mut self, value: G1) -> &mut Self {
        self.add(&value.to_compressed())
    }
    pub fn g2(&mut self, value: G2) -> &mut Self {
        self.add(&value.to_compressed())
    }
    pub fn f(&mut self, value: F) -> &mut Self {
        self.add(&value.to_bytes_be())
    }
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update((self.dst.len() as u32).to_be_bytes());
        h.update(&self.dst);
        h.update(&self.bytes);
        h.finalize().into()
    }
    pub fn scalar(&self) -> F {
        crate::hash::hash_to_scalar(&self.bytes, &self.dst)
    }
}

pub fn rand_nonzero(rng: &mut Rng) -> F {
    loop {
        let v = F::random(&mut *rng);
        if v != F::ZERO {
            return v;
        }
    }
}

pub fn take<const N: usize>(input: &mut &[u8]) -> Res<[u8; N]> {
    if input.len() < N {
        return Err("truncated input".into());
    }
    let (head, tail) = input.split_at(N);
    *input = tail;
    Ok(head.try_into().expect("fixed width"))
}

pub fn read_g1(input: &mut &[u8]) -> Res<G1> {
    Option::from(G1::from_compressed(&take::<48>(input)?))
        .ok_or_else(|| "invalid G1 encoding or subgroup".into())
}

pub fn read_g2(input: &mut &[u8]) -> Res<G2> {
    Option::from(G2::from_compressed(&take::<96>(input)?))
        .ok_or_else(|| "invalid G2 encoding or subgroup".into())
}

pub fn read_f(input: &mut &[u8]) -> Res<F> {
    Option::from(F::from_bytes_be(&take::<32>(input)?)).ok_or_else(|| "noncanonical scalar".into())
}

pub fn uint_bytes(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

pub fn read_uint(input: &mut &[u8]) -> Res<u64> {
    let bytes = take::<32>(input)?;
    if bytes[..24].iter().any(|&byte| byte != 0) {
        return Err("integer exceeds supported weight range".into());
    }
    Ok(u64::from_be_bytes(bytes[24..].try_into().unwrap()))
}

pub fn eof(input: &[u8]) -> Res<()> {
    if input.is_empty() {
        Ok(())
    } else {
        Err("trailing input".into())
    }
}
