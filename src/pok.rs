//! Responses for linear Sigma protocols with shared witnesses.

use crate::common::{Rng, F};
use ff::Field;

pub fn masks(count: usize, rng: &mut Rng) -> Vec<F> {
    (0..count).map(|_| F::random(&mut *rng)).collect()
}

pub fn responses(masks: &[F], witnesses: &[F], challenge: F) -> Vec<F> {
    assert_eq!(masks.len(), witnesses.len());
    masks
        .iter()
        .zip(witnesses)
        .map(|(&r, &w)| r + challenge * w)
        .collect()
}
