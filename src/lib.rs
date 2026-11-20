//! Accountable Weighted Multi-Holder Anonymous Credentials.

pub mod aw_mhac;
pub mod baselines;
pub mod bbs;
pub mod common;
pub mod hash;
pub mod kzg;
pub mod pairing;
pub mod pok;
pub mod poly;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct OpCounts {
    pub g1_exp: usize,
    pub g2_exp: usize,
    pub g1_msm: Vec<usize>,
    pub g2_msm: Vec<usize>,
    pub pair_terms: usize,
    pub final_exps: usize,
    pub hash_g1: usize,
    pub hash_g2: usize,
    pub hash_scalar: usize,
    pub batch_inversions: usize,
}

#[cfg(feature = "op-count")]
thread_local! {
    static COUNTS: std::cell::RefCell<OpCounts> = Default::default();
}

pub fn update_counts(_apply: impl FnOnce(&mut OpCounts)) {
    #[cfg(feature = "op-count")]
    COUNTS.with_borrow_mut(_apply);
}

pub fn take_counts() -> OpCounts {
    #[cfg(feature = "op-count")]
    return COUNTS.with_borrow_mut(std::mem::take);
    #[cfg(not(feature = "op-count"))]
    OpCounts::default()
}
