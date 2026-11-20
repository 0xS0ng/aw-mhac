//! BLS12-381 group arithmetic wrappers and multi-pairing.

use blst::blst_fp12;
use blstrs::{G1Affine, G2Affine};
use group::Group;
use rand::RngCore;

use crate::common::{Rng, F, G1, G2};
use crate::update_counts;

pub fn g1_exp(point: G1, exponent: F) -> G1 {
    update_counts(|c| c.g1_exp += 1);
    point * exponent
}

pub fn g2_exp(point: G2, exponent: F) -> G2 {
    update_counts(|c| c.g2_exp += 1);
    point * exponent
}

pub fn g1_msm(points: &[G1], scalars: &[F]) -> G1 {
    assert_eq!(points.len(), scalars.len());
    if points.is_empty() {
        return G1::identity();
    }
    update_counts(|c| c.g1_msm.push(points.len()));
    G1::multi_exp(points, scalars)
}

pub fn g2_msm(points: &[G2], scalars: &[F]) -> G2 {
    assert_eq!(points.len(), scalars.len());
    if points.is_empty() {
        return G2::identity();
    }
    update_counts(|c| c.g2_msm.push(points.len()));
    G2::multi_exp(points, scalars)
}

pub fn pair_product(terms: &[(G1, G2)]) -> bool {
    // Identity factors contribute one. Count the executed backend terms.
    let (a, b): (Vec<_>, Vec<_>) = terms
        .iter()
        .filter(|(p, q)| !bool::from(p.is_identity() | q.is_identity()))
        .map(|&(p, q)| (*G1Affine::from(p).as_ref(), *G2Affine::from(q).as_ref()))
        .unzip();
    if a.is_empty() {
        return true;
    }
    update_counts(|c| {
        c.pair_terms += a.len();
        c.final_exps += 1;
    });
    blst_fp12::miller_loop_n(&b, &a).final_exp() == blst_fp12::default()
}

pub fn batch_coefficient(rng: &mut Rng) -> F {
    loop {
        let low = rng.next_u64();
        let high = rng.next_u64();
        if low != 0 || high != 0 {
            return F::from(low) + F::from(high) * (F::from(u64::MAX) + F::from(1));
        }
    }
}
