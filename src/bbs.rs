//! BBS signatures on scalar messages.

use crate::common::{Res, Rng, F, G1};
use crate::pairing::{g1_exp, g1_msm};
use ff::Field;

pub fn base(g0: G1, h_i: &[G1], attributes: &[F]) -> G1 {
    g0 + g1_msm(h_i, attributes)
}

pub fn sign_base(c: G1, isk: F, rng: &mut Rng) -> Res<(G1, F)> {
    if bool::from(group::Group::is_identity(&c)) {
        return Err("identity BBS base".into());
    }
    loop {
        let e = F::random(&mut *rng);
        if let Some(inverse) = Option::<F>::from((isk + e).invert()) {
            return Ok((g1_exp(c, inverse), e));
        }
    }
}
