//! Radix-two FFT and dense polynomials over the BLS12-381 scalar field.

use crate::common::{Res, F};
use ff::{Field, PrimeField};

pub fn root(n: usize) -> F {
    assert!(n.is_power_of_two() && n.trailing_zeros() <= F::S);
    F::ROOT_OF_UNITY.pow_vartime([1u64 << (F::S - n.trailing_zeros())])
}

pub fn vanishing(x: F, n: usize) -> F {
    x.pow_vartime([n as u64]) - F::ONE
}

pub fn eval(coeffs: &[F], x: F) -> F {
    coeffs
        .iter()
        .rev()
        .fold(F::ZERO, |value, &coefficient| value * x + coefficient)
}

pub fn fft(values: &mut [F], inverse: bool) {
    let n = values.len();
    if n == 1 {
        return;
    }
    let bits = n.trailing_zeros();
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS - bits);
        if i < j {
            values.swap(i, j);
        }
    }
    // All inverse twiddles and the normalization factor are known at once.
    let inverse_twiddles = inverse.then(|| {
        let mut values: Vec<_> = (1..=bits).map(|i| root(1 << i)).collect();
        values.push(F::from(n as u64));
        batch_invert(&mut values).expect("nonzero FFT roots and size");
        values
    });
    for i in 0..bits as usize {
        let len = 1 << (i + 1);
        let step = inverse_twiddles
            .as_ref()
            .map_or_else(|| root(len), |twiddles| twiddles[i]);
        for chunk in values.chunks_exact_mut(len) {
            let (left, right) = chunk.split_at_mut(len / 2);
            let mut w = F::ONE;
            for (u, v) in left.iter_mut().zip(right) {
                let t = *v * w;
                *v = *u - t;
                *u += t;
                w *= step;
            }
        }
    }
    if let Some(twiddles) = inverse_twiddles {
        let scale = twiddles[bits as usize];
        for value in values {
            *value *= scale;
        }
    }
}

pub fn interpolate(mut evaluations: Vec<F>) -> Vec<F> {
    fft(&mut evaluations, true);
    evaluations
}

pub fn polynomial_mul(left: &[F], right: &[F]) -> Vec<F> {
    let len = left.len() + right.len() - 1;
    let size = len.next_power_of_two();
    let mut a = left.to_vec();
    let mut b = right.to_vec();
    a.resize(size, F::ZERO);
    b.resize(size, F::ZERO);
    fft(&mut a, false);
    fft(&mut b, false);
    for (x, y) in a.iter_mut().zip(b) {
        *x *= y;
    }
    fft(&mut a, true);
    a.truncate(len);
    a
}

pub fn divide_vanishing(mut numerator: Vec<F>, n: usize) -> Res<Vec<F>> {
    let mut quotient = vec![F::ZERO; numerator.len() - n];
    for i in (n..numerator.len()).rev() {
        quotient[i - n] = numerator[i];
        let high = numerator[i];
        numerator[i - n] += high;
    }
    if numerator[..n].iter().any(|x| *x != F::ZERO) {
        return Err("selection polynomial division has a nonzero remainder".into());
    }
    Ok(quotient)
}

pub fn opening_quotient(poly: &[F], x: F) -> Vec<F> {
    let mut quotient = vec![F::ZERO; poly.len() - 1];
    let mut carry = F::ZERO;
    for (coefficient, output) in poly[1..].iter().zip(&mut quotient).rev() {
        carry = *coefficient + x * carry;
        *output = carry;
    }
    quotient
}

/// Replaces nonzero field elements by their reciprocals using one inversion.
pub fn batch_invert(values: &mut [F]) -> Res<()> {
    if values.is_empty() {
        return Ok(());
    }
    let mut prefixes = Vec::with_capacity(values.len());
    let mut prefix = F::ONE;
    for &x in values.iter() {
        if x == F::ZERO {
            return Err("zero denominator in batch inversion".into());
        }
        prefixes.push(prefix);
        prefix *= x;
    }
    crate::update_counts(|counts| counts.batch_inversions += 1);
    let mut inverse = Option::<F>::from(prefix.invert()).expect("product of nonzero elements");
    for (x, prefix) in values.iter_mut().zip(prefixes).rev() {
        let reciprocal = inverse * prefix;
        inverse *= *x;
        *x = reciprocal;
    }
    Ok(())
}
