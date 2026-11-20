use aw_mhac::{
    common::F,
    poly::{batch_invert, fft},
};
use ff::Field;

#[test]
fn batch_invert_matches_single_inversion() {
    let denominators: Vec<_> = (2..19).map(F::from).collect();
    let mut inverse = denominators.clone();
    batch_invert(&mut inverse).unwrap();
    for (denominator, inverse) in denominators.into_iter().zip(inverse) {
        assert_eq!(denominator * inverse, F::ONE);
    }
    let mut zero_denominator = [F::from(2), F::ZERO, F::ONE];
    let original = zero_denominator;
    assert!(batch_invert(&mut zero_denominator).is_err());
    assert_eq!(zero_denominator, original);
    batch_invert(&mut []).unwrap();
}

#[test]
fn inverse_fft_reverses_forward_fft() {
    for size in [2, 16, 128, 1024] {
        let values: Vec<_> = (0..size).map(|i| F::from(i * i + 9)).collect();
        let mut image = values.clone();
        fft(&mut image, false);
        fft(&mut image, true);
        assert_eq!(image, values);
    }
}
