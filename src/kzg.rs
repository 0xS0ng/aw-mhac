//! KZG commitments and opening quotients.

use crate::common::{Res, F, G1};
use crate::{pairing::g1_msm, poly::opening_quotient};

pub fn commit(srs: &[G1], coefficients: &[F]) -> G1 {
    g1_msm(&srs[..coefficients.len()], coefficients)
}

pub fn open_at_value(srs: &[G1], coefficients: &[F], point: F, value: F) -> Res<G1> {
    let quotient = opening_quotient(coefficients, point);
    if coefficients[0] + point * quotient[0] != value {
        return Err("KZG opening value differs from quotient remainder".into());
    }
    Ok(commit(srs, &quotient))
}
