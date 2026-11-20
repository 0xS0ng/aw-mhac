use aw_mhac::{
    baselines::hints::{
        aggregation_identity, hint_gen, kgen, partial_verify, preprocess, setup, sign,
    },
    common::{Rng, G1},
};
use group::Group;
use rand::SeedableRng;

#[test]
fn keys_hints_partial_signatures_and_aggregation_identity() {
    let mut rng = Rng::seed_from_u64(935);
    for weights in [vec![1, 1, 1], vec![2, 3, 9]] {
        let pp = setup(&weights, &mut rng).unwrap();
        let keys: Vec<_> = (0..weights.len()).map(|_| kgen(&mut rng)).collect();
        let pks: Vec<_> = keys
            .iter()
            .map(|key| key.pk_i.to_compressed().to_vec())
            .collect();
        let mut hints: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| hint_gen(&pp, i, key).unwrap())
            .collect();
        let hint_wires: Vec<_> = hints.iter().map(|hint| hint.encode()).collect();
        let (ak, vk) = preprocess(&pp, &pks, &hint_wires, &mut rng).unwrap();
        assert!(ak.excluded.is_empty());
        for mask in 1..(1 << weights.len()) {
            let slots: Vec<_> = (0..weights.len())
                .filter(|&slot| mask & (1 << slot) != 0)
                .collect();
            assert!(aggregation_identity(&pp, &ak, &vk, &slots).unwrap());
            let signatures: Vec<_> = slots
                .iter()
                .map(|&slot| sign(&keys[slot], b"context"))
                .collect();
            partial_verify(&ak, &slots, b"context", &signatures, &mut rng).unwrap();
            assert!(
                partial_verify(&ak, &slots, b"different context", &signatures, &mut rng).is_err()
            );
            let mut mixed = signatures.clone();
            mixed[0] = sign(&keys[slots[0]], b"different context");
            assert!(partial_verify(&ak, &slots, b"context", &mixed, &mut rng).is_err());
        }
        hints[1].q_x += G1::generator();
        let hint_wires: Vec<_> = hints.iter().map(|hint| hint.encode()).collect();
        let (ak, _) = preprocess(&pp, &pks, &hint_wires, &mut rng).unwrap();
        assert_eq!(ak.excluded, vec![1]);
        assert_eq!(ak.weights[1], 0);
    }
}

#[test]
fn received_hint_and_partial_signature_subgroups_are_checked() {
    use aw_mhac::baselines::hints::Hint;
    use aw_mhac::common::{F, G2};
    use ff::Field;

    let mut rng = Rng::seed_from_u64(501);
    let pp = setup(&[1, 1, 1], &mut rng).unwrap();
    let keys: Vec<_> = (0..3).map(|_| kgen(&mut rng)).collect();
    let pks: Vec<_> = keys
        .iter()
        .map(|key| key.pk_i.to_compressed().to_vec())
        .collect();
    let hints: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| hint_gen(&pp, i, key).unwrap().encode())
        .collect();
    let (ak, vk) = preprocess(&pp, &pks, &hints, &mut rng).unwrap();

    let mut wrong_g1 = [0; 48];
    wrong_g1[0] = 0x80;
    for x in 0..=255 {
        wrong_g1[47] = x;
        if bool::from(G1::from_compressed_unchecked(&wrong_g1).is_some())
            && !bool::from(G1::from_compressed(&wrong_g1).is_some())
        {
            break;
        }
    }
    assert!(bool::from(
        G1::from_compressed_unchecked(&wrong_g1).is_some()
    ));
    assert!(!bool::from(G1::from_compressed(&wrong_g1).is_some()));
    let mut wrong_g2 = [0; 96];
    wrong_g2[0] = 0x80;
    for x in 0..=255 {
        wrong_g2[95] = x;
        if bool::from(G2::from_compressed_unchecked(&wrong_g2).is_some())
            && !bool::from(G2::from_compressed(&wrong_g2).is_some())
        {
            break;
        }
    }
    assert!(bool::from(
        G2::from_compressed_unchecked(&wrong_g2).is_some()
    ));
    assert!(!bool::from(G2::from_compressed(&wrong_g2).is_some()));

    let mut changed = hints[0].clone();
    changed[..96].copy_from_slice(&wrong_g2);
    assert!(Hint::decode(&changed, pp.d).is_err());
    changed = hints[0].clone();
    changed[96..144].copy_from_slice(&wrong_g1);
    assert!(Hint::decode(&changed, pp.d).is_err());
    assert!(partial_verify(&ak, &[0], b"message", &[wrong_g2.to_vec()], &mut rng).is_err());
    assert!(aw_mhac::baselines::hints::sign_aggr(
        &pp,
        &ak,
        &vk,
        &[0],
        b"message",
        &[wrong_g2.to_vec()],
        &mut rng
    )
    .is_err());
    let mut trailing = sign(&keys[0], b"message");
    trailing.push(0);
    assert!(aw_mhac::baselines::hints::sign_aggr(
        &pp,
        &ak,
        &vk,
        &[0],
        b"message",
        &[trailing],
        &mut rng
    )
    .is_err());
    let mut noncanonical_scalar = [0xff; 32];
    assert!(Option::<F>::from(F::from_bytes_be(&noncanonical_scalar)).is_none());
    noncanonical_scalar = F::ONE.to_bytes_be();
    assert!(Option::<F>::from(F::from_bytes_be(&noncanonical_scalar)).is_some());
}

#[test]
fn deterministic_keys_and_hints() {
    let mut first = Rng::seed_from_u64(117);
    let mut second = Rng::seed_from_u64(117);
    let first_pp = setup(&[1, 3, 9], &mut first).unwrap();
    let second_pp = setup(&[1, 3, 9], &mut second).unwrap();
    for slot in 0..3 {
        let first_key = kgen(&mut first);
        let second_key = kgen(&mut second);
        assert_eq!(first_key.pk_i, second_key.pk_i);
        assert_eq!(
            hint_gen(&first_pp, slot, &first_key).unwrap().encode(),
            hint_gen(&second_pp, slot, &second_key).unwrap().encode()
        );
    }
}

#[cfg(feature = "op-count")]
#[test]
fn operation_counts_match_preimplementation_tally() {
    use aw_mhac::take_counts;
    let mut rng = Rng::seed_from_u64(111);
    let pp = setup(&[1, 2, 4], &mut rng).unwrap();
    take_counts();
    let key = kgen(&mut rng);
    let counts = take_counts();
    assert_eq!((counts.g1_exp, counts.g2_exp), (1, 0));
    hint_gen(&pp, 0, &key).unwrap();
    let counts = take_counts();
    assert_eq!((counts.g1_exp, counts.g2_exp), (pp.d + 2, 1));
    sign(&key, b"message");
    let counts = take_counts();
    assert_eq!((counts.g1_exp, counts.g2_exp, counts.hash_g2), (0, 1, 1));
}

#[cfg(feature = "op-count")]
#[test]
fn preprocessing_and_partial_verification_counts_in_two_universes() {
    use aw_mhac::baselines::hints::{sign_aggr, sign_aggr_with_partial_checks, verify};
    use aw_mhac::take_counts;
    let mut rng = Rng::seed_from_u64(434);
    for (u, k) in [(3, 2), (16, 8)] {
        let pp = setup(&vec![1; u], &mut rng).unwrap();
        let keys: Vec<_> = (0..u).map(|_| kgen(&mut rng)).collect();
        let pks: Vec<_> = keys
            .iter()
            .map(|key| key.pk_i.to_compressed().to_vec())
            .collect();
        let hints: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(slot, key)| hint_gen(&pp, slot, key).unwrap().encode())
            .collect();
        take_counts();
        let (ak, vk) = preprocess(&pp, &pks, &hints, &mut rng).unwrap();
        let counts = take_counts();
        assert_eq!(counts.g1_msm, vec![u * (pp.d + 2), pp.d]);
        let mut expected_g2_msm = vec![pp.d + 3; u];
        expected_g2_msm.push(u);
        assert_eq!(counts.g2_msm, expected_g2_msm);
        assert_eq!((counts.pair_terms, counts.final_exps), (u + 2, 1));
        assert_eq!((counts.g1_exp, counts.g2_exp), (0, 0));
        assert_eq!(counts.batch_inversions, 1);
        let slots: Vec<_> = (0..k).collect();
        let signatures: Vec<_> = slots
            .iter()
            .map(|&slot| sign(&keys[slot], b"message"))
            .collect();
        take_counts();
        partial_verify(&ak, &slots, b"message", &signatures, &mut rng).unwrap();
        let counts = take_counts();
        assert_eq!(counts.g1_msm, vec![k]);
        assert_eq!(counts.g2_msm, vec![k]);
        assert_eq!(
            (counts.pair_terms, counts.final_exps, counts.hash_g2),
            (2, 1, 1)
        );
        let wire = sign_aggr(&pp, &ak, &vk, &slots, b"message", &signatures, &mut rng).unwrap();
        let counts = take_counts();
        assert_eq!((counts.g1_exp, counts.g2_exp), (1, 1));
        assert_eq!(
            counts.g1_msm,
            vec![pp.d, pp.d, pp.d - 1, pp.d - 1, pp.d - 1]
        );
        assert!(counts.g2_msm.is_empty());
        assert_eq!(counts.batch_inversions, 7);
        assert_eq!(
            (
                counts.pair_terms,
                counts.final_exps,
                counts.hash_g2,
                counts.hash_scalar
            ),
            (0, 0, 0, 3)
        );
        let checked =
            sign_aggr_with_partial_checks(&pp, &ak, &vk, &slots, b"message", &signatures, &mut rng)
                .unwrap();
        assert_eq!(checked, wire);
        let counts = take_counts();
        assert_eq!((counts.g1_exp, counts.g2_exp), (1, 1));
        assert_eq!(
            counts.g1_msm,
            vec![k, pp.d, pp.d, pp.d - 1, pp.d - 1, pp.d - 1]
        );
        assert_eq!(counts.g2_msm, vec![k]);
        assert_eq!(
            (
                counts.pair_terms,
                counts.final_exps,
                counts.hash_g2,
                counts.hash_scalar
            ),
            (2, 1, 1, 3)
        );
        // The signing aggregator reuses H(m) across its Sign and SignAggr roles.
        let h = aw_mhac::baselines::hints::hash_message(b"message");
        let mut shared_partials = signatures.clone();
        shared_partials[0] = aw_mhac::baselines::hints::sign_with_hash(&keys[0], h);
        aw_mhac::baselines::hints::sign_aggr_with_hash(
            &pp,
            &ak,
            &vk,
            &slots,
            b"message",
            h,
            &shared_partials,
            &mut rng,
        )
        .unwrap();
        let counts = take_counts();
        assert_eq!(counts.hash_g2, 1);
        verify(&vk, b"message", k as u64, &wire, true, &mut rng).unwrap();
        let counts = take_counts();
        assert_eq!((counts.g1_exp, counts.g2_exp), (9, 0));
        assert_eq!(counts.g1_msm, vec![4, 3, 4]);
        assert_eq!(counts.batch_inversions, 1);
        assert_eq!(
            (
                counts.pair_terms,
                counts.final_exps,
                counts.hash_g2,
                counts.hash_scalar
            ),
            (6, 1, 1, 3)
        );
        verify(&vk, b"message", k as u64, &wire, false, &mut rng).unwrap();
        let counts = take_counts();
        assert_eq!((counts.g1_exp, counts.g2_exp), (5, 0));
        assert_eq!(counts.g1_msm, vec![4]);
        assert_eq!(counts.batch_inversions, 1);
        assert_eq!(
            (
                counts.pair_terms,
                counts.final_exps,
                counts.hash_g2,
                counts.hash_scalar
            ),
            (11, 5, 1, 3)
        );
    }
}

#[test]
fn optimized_signature_wire_format_is_720_bytes() {
    use aw_mhac::baselines::hints::Signature;
    use aw_mhac::common::{F, G2};
    use ff::Field;
    let signature = Signature {
        a_pk: G1::generator(),
        sigma: G2::generator(),
        weight: 8,
        b_c: G1::generator(),
        q_x_c: G1::generator(),
        q_z_c: G1::generator(),
        u: G1::generator(),
        par_sum_c: G1::generator(),
        q_c: G1::generator(),
        b_r: F::ONE,
        par_sum_r: F::ONE,
        par_sum_r_omega: F::ONE,
        w_r: F::ONE,
        q_r: F::ONE,
        open_r: G1::generator(),
        open_r_omega: G1::generator(),
    };
    let bytes = signature.encode();
    assert_eq!(bytes.len(), 720);
    assert_eq!(Signature::decode(&bytes).unwrap().encode(), bytes);
    assert!(Signature::decode(&bytes[..719]).is_err());
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(Signature::decode(&changed).is_err());
    changed = bytes.clone();
    changed[464..496].fill(0xff);
    assert!(Signature::decode(&changed).is_err());
}

#[test]
fn optimized_signature_honesty_tampering_and_thresholds() {
    use aw_mhac::baselines::hints::{sign_aggr, sign_aggr_with_partial_checks, verify, Signature};
    use aw_mhac::common::{F, G2};
    use ff::Field;

    let mut rng = Rng::seed_from_u64(6024);
    for weights in [vec![1, 1, 1], vec![3, 7, 13]] {
        let pp = setup(&weights, &mut rng).unwrap();
        let keys: Vec<_> = (0..weights.len()).map(|_| kgen(&mut rng)).collect();
        let pks: Vec<_> = keys
            .iter()
            .map(|key| key.pk_i.to_compressed().to_vec())
            .collect();
        let hints: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(slot, key)| hint_gen(&pp, slot, key).unwrap().encode())
            .collect();
        let (ak, vk) = preprocess(&pp, &pks, &hints, &mut rng).unwrap();
        assert_eq!(pp.hint_check_equalities_per_signer(), pp.d + 3);
        for mask in 1..(1 << weights.len()) {
            let slots: Vec<_> = (0..weights.len())
                .filter(|slot| mask & (1 << slot) != 0)
                .collect();
            let signatures: Vec<_> = slots
                .iter()
                .map(|&slot| sign(&keys[slot], b"context"))
                .collect();
            let wire = sign_aggr(&pp, &ak, &vk, &slots, b"context", &signatures, &mut rng).unwrap();
            assert_eq!(wire.len(), 720);
            let original = Signature::decode(&wire).unwrap();
            for merged in [false, true] {
                verify(&vk, b"context", original.weight, &wire, merged, &mut rng).unwrap();
                assert!(verify(
                    &vk,
                    b"different context",
                    original.weight,
                    &wire,
                    merged,
                    &mut rng
                )
                .is_err());
                assert!(verify(
                    &vk,
                    b"context",
                    original.weight + 1,
                    &wire,
                    merged,
                    &mut rng
                )
                .is_err());
            }
            macro_rules! changed {
                ($field:ident, $value:expr) => {{
                    let mut signature = original.clone();
                    signature.$field = $value;
                    for merged in [false, true] {
                        assert!(
                            verify(&vk, b"context", 1, &signature.encode(), merged, &mut rng)
                                .is_err(),
                            "accepted mutated {}",
                            stringify!($field)
                        );
                    }
                }};
            }
            let random_g1 = G1::generator() * F::random(&mut rng);
            let random_g2 = G2::generator() * F::random(&mut rng);
            changed!(a_pk, random_g1);
            changed!(sigma, random_g2);
            changed!(weight, original.weight + 1);
            changed!(b_c, random_g1);
            changed!(q_x_c, random_g1);
            changed!(q_z_c, random_g1);
            changed!(u, random_g1);
            changed!(par_sum_c, random_g1);
            changed!(q_c, random_g1);
            changed!(b_r, original.b_r + F::ONE);
            changed!(par_sum_r, original.par_sum_r + F::ONE);
            changed!(par_sum_r_omega, original.par_sum_r_omega + F::ONE);
            changed!(w_r, original.w_r + F::ONE);
            changed!(q_r, original.q_r + F::ONE);
            changed!(open_r, random_g1);
            changed!(open_r_omega, random_g1);
            let mut mixed = signatures.clone();
            mixed[0] = sign(&keys[slots[0]], b"different context");
            let mixed_wire =
                sign_aggr(&pp, &ak, &vk, &slots, b"context", &mixed, &mut rng).unwrap();
            for merged in [false, true] {
                assert!(verify(
                    &vk,
                    b"context",
                    original.weight,
                    &mixed_wire,
                    merged,
                    &mut rng
                )
                .is_err());
            }
            assert!(sign_aggr_with_partial_checks(
                &pp, &ak, &vk, &slots, b"context", &mixed, &mut rng
            )
            .is_err());
            assert_eq!(
                sign_aggr(&pp, &ak, &vk, &slots, b"context", &signatures, &mut rng).unwrap(),
                wire
            );
        }
    }
}

#[test]
fn sixteen_real_signers_use_a_32_point_domain_with_a_separate_dummy() {
    use aw_mhac::baselines::hints::{sign_aggr, verify};
    let mut rng = Rng::seed_from_u64(8084);
    let pp = setup(&vec![1; 16], &mut rng).unwrap();
    assert_eq!((pp.u, pp.d), (16, 32));
    let keys = (0..16).map(|_| kgen(&mut rng)).collect::<Vec<_>>();
    assert!(hint_gen(&pp, 16, &keys[0]).is_err());
    let public_keys = keys
        .iter()
        .map(|key| key.pk_i.to_compressed().to_vec())
        .collect::<Vec<_>>();
    let hint_wires = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| hint_gen(&pp, slot, key).unwrap().encode())
        .collect::<Vec<_>>();
    let (ak, vk) = preprocess(&pp, &public_keys, &hint_wires, &mut rng).unwrap();
    let host_first = [11, 2, 8, 5, 14, 0, 7, 15];
    let mut parts = host_first
        .iter()
        .map(|&id| (id, sign(&keys[id], b"native domain")))
        .collect::<Vec<_>>();
    parts.sort_unstable_by_key(|(id, _)| *id);
    let (ids, signatures): (Vec<_>, Vec<_>) = parts.into_iter().unzip();
    let wire = sign_aggr(&pp, &ak, &vk, &ids, b"native domain", &signatures, &mut rng).unwrap();
    verify(&vk, b"native domain", 8, &wire, true, &mut rng).unwrap();
    assert_eq!(wire.len(), 720);
}
