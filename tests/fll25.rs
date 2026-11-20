use aw_mhac::baselines::fll25::{self, Fault, Parameters, Session};
use aw_mhac::common::{F, G1};
use ff::Field;
use group::Group;
use rand::{rngs::StdRng, SeedableRng};

fn fixture(
    holders: usize,
    threshold: usize,
    attributes: usize,
) -> (Parameters, Vec<fll25::Share>, Session, StdRng) {
    fixture_mode(false, holders, threshold, attributes)
}

fn fixture_mode(
    optimized: bool,
    holders: usize,
    threshold: usize,
    attributes: usize,
) -> (Parameters, Vec<fll25::Share>, Session, StdRng) {
    let mut rng = StdRng::seed_from_u64(2026111901);
    let (mut parameters, mut key) = Parameters::setup(attributes, &mut rng);
    if optimized {
        parameters.enable_optimization(&mut key, &mut rng);
    }
    let issue = if optimized {
        fll25::issue_opt
    } else {
        fll25::issue
    };
    let accept = if optimized {
        fll25::accept_opt
    } else {
        fll25::accept
    };
    let values: Vec<_> = (0..attributes).map(|i| F::from(i as u64 + 4)).collect();
    let issued = issue(&parameters, &key, &values, holders, threshold, &mut rng).unwrap();
    let accepted = issued
        .iter()
        .map(|share| {
            accept(
                &parameters,
                &share.encode(),
                attributes,
                holders,
                threshold,
                share.holder_index,
            )
            .unwrap()
        })
        .collect();
    let session = Session {
        id: [5; 32],
        nonce: [6; 32],
        disclosed: values
            .iter()
            .enumerate()
            .map(|(i, value)| (i < 3).then_some(*value))
            .collect(),
    };
    (parameters, accepted, session, rng)
}

#[test]
fn honest_execution_storage_and_all_links() {
    for (holders, threshold, attributes) in [(16, 8, 10), (16, 2, 5), (16, 16, 20)] {
        let (parameters, shares, session, mut rng) = fixture(holders, threshold, attributes);
        let result = fll25::show(&parameters, &shares[..threshold], &session, &mut rng).unwrap();
        fll25::verify(&parameters, &session, &result.wire).unwrap();
        let hidden = attributes - 3;
        let broadcast_bytes = 112 * threshold + 32 * hidden + 64;
        assert_eq!(result.wire.len(), 192 + 32 * hidden);
        assert_eq!(result.logical_bytes(), broadcast_bytes + result.wire.len());
        assert_eq!(
            result.link_bytes(),
            broadcast_bytes * (threshold - 1) + result.wire.len()
        );
        assert_eq!(result.broadcasts.len(), 3 * threshold + 1);
        assert_eq!(
            shares[0].encode().len(),
            48 * holders + 32 * (attributes + 1)
        );
        assert_eq!(
            shares[0].stored_bytes(),
            48 * (holders + 1) + 32 * (attributes + 1)
        );
    }
}

#[test]
fn request_codec_uses_the_shared_one_based_attribute_indices() {
    let (_, _, session, _) = fixture(16, 8, 10);
    let wire = session.request_bytes();
    assert_eq!(wire.len(), 68 + 3 * 36);
    for i in 0..3 {
        assert_eq!(
            &wire[68 + i * 36..72 + i * 36],
            &((i + 1) as u32).to_be_bytes()
        );
    }
}

#[test]
fn malformed_inputs_contexts_and_identifiable_abort() {
    let (parameters, shares, session, mut rng) = fixture(16, 8, 10);
    let selected = &shares[..8];
    let result = fll25::show(&parameters, selected, &session, &mut rng).unwrap();
    let mut context = session.clone();
    context.nonce[0] ^= 1;
    assert!(fll25::verify(&parameters, &context, &result.wire).is_err());
    assert!(fll25::show(&parameters, &selected[..7], &session, &mut rng).is_err());
    let mut duplicated = selected.to_vec();
    duplicated[1] = duplicated[0].clone();
    assert!(fll25::show(&parameters, &duplicated, &session, &mut rng).is_err());
    for fault in [
        Fault::ChangedOpening { participant: 2 },
        Fault::ChangedResponse { participant: 3 },
    ] {
        let error = match fll25::show_with_fault(&parameters, selected, &session, fault, &mut rng) {
            Err(error) => error,
            Ok(_) => panic!("a changed message must abort"),
        };
        assert!(error.contains("identifiable abort"));
    }
    let old_response = result
        .broadcasts
        .iter()
        .find(|message| message.sender == 3 && message.phase == fll25::BroadcastPhase::Response)
        .unwrap()
        .payload
        .clone();
    let error = match fll25::show_with_fault(
        &parameters,
        selected,
        &context,
        Fault::ReplayedResponse {
            participant: 3,
            payload: &old_response,
        },
        &mut rng,
    ) {
        Err(error) => error,
        Ok(_) => panic!("another context's response must abort"),
    };
    assert!(error.contains("response participant 3"));
    let torsion = (1u32..512)
        .find_map(|x| {
            let mut bytes = [0u8; 48];
            bytes[0] = 0x80;
            bytes[44..].copy_from_slice(&x.to_be_bytes());
            (bool::from(G1::from_compressed_unchecked(&bytes).is_some())
                && bool::from(G1::from_compressed(&bytes).is_none()))
            .then_some(bytes)
        })
        .unwrap();
    let mut encoded = result.wire;
    encoded[..48].copy_from_slice(&torsion);
    assert!(fll25::verify(&parameters, &session, &encoded).is_err());
}

#[test]
fn every_presentation_component_is_bound() {
    let (parameters, shares, session, mut rng) = fixture(16, 8, 10);
    let result = fll25::show(&parameters, &shares[..8], &session, &mut rng).unwrap();
    for component in 0..5 + result.presentation.responses_attributes.len() {
        let mut changed = result.presentation.clone();
        match component {
            0 => changed.a = G1::generator() * F::random(&mut rng),
            1 => changed.b = G1::generator() * F::random(&mut rng),
            2 => changed.challenge += F::ONE,
            3 => changed.response_r += F::ONE,
            4 => changed.response_e += F::ONE,
            i => changed.responses_attributes[i - 5] += F::ONE,
        }
        assert!(fll25::verify(&parameters, &session, &changed.encode()).is_err());
    }
}

#[test]
fn host_first_nonconsecutive_ids_preserve_registration_mapping() {
    let ids = [11, 2, 8, 5, 14, 0, 7, 15];
    let (parameters, shares, session, mut rng) = fixture(16, ids.len(), 10);
    let selected = ids.iter().map(|&id| shares[id].clone()).collect::<Vec<_>>();
    assert_eq!(
        selected.iter().map(|s| s.holder_index).collect::<Vec<_>>(),
        ids
    );
    let result = fll25::show(&parameters, &selected, &session, &mut rng).unwrap();
    fll25::verify(&parameters, &session, &result.wire).unwrap();
}

#[test]
fn fixed_seed_reproduces_objects() {
    let (p1, s1, c1, mut r1) = fixture(16, 8, 10);
    let (p2, s2, c2, mut r2) = fixture(16, 8, 10);
    assert_eq!(s1[0].encode(), s2[0].encode());
    assert_eq!(
        fll25::show(&p1, &s1[..8], &c1, &mut r1).unwrap().wire,
        fll25::show(&p2, &s2[..8], &c2, &mut r2).unwrap().wire
    );
}

#[test]
fn batched_lagrange_matches_individual_inverses() {
    for ids in [vec![0, 1], vec![11, 2, 8, 5], (0..16).collect()] {
        let actual = fll25::lagrange_coefficients(&ids).unwrap();
        let points = ids
            .iter()
            .map(|i| F::from(*i as u64 + 1))
            .collect::<Vec<_>>();
        for (i, x) in points.iter().enumerate() {
            let mut numerator = F::ONE;
            let mut denominator = F::ONE;
            for (j, y) in points.iter().enumerate() {
                if i != j {
                    numerator *= -*y;
                    denominator *= *x - *y;
                }
            }
            assert_eq!(actual[i], numerator * denominator.invert().unwrap());
        }
    }
}

#[test]
fn certified_shares_preserve_mapping_checks_and_final_encoding() {
    for (b, k, n) in [(16, 2, 5), (16, 8, 10), (16, 16, 20)] {
        let (p, shares, session, mut rng) = fixture_mode(true, b, k, n);
        let ids = [11, 2, 8, 5, 14, 0, 7, 15, 1, 3, 4, 6, 9, 10, 12, 13];
        let selected = ids[..k]
            .iter()
            .map(|&id| shares[id].clone())
            .collect::<Vec<_>>();
        let result = fll25::show(&p, &selected, &session, &mut rng).unwrap();
        fll25::verify(&p, &session, &result.wire).unwrap();
        let h = n - 3;
        let broadcasts = 112 * k + 32 * h + 64 + 96 * k;
        assert_eq!(result.wire.len(), 192 + 32 * h);
        assert_eq!(result.logical_bytes(), broadcasts + result.wire.len());
        assert_eq!(
            result.link_bytes(),
            broadcasts * (k - 1) + result.wire.len()
        );
        assert_eq!(shares[0].encode().len(), 3 * 48 + 32 * (n + 1));
        assert_eq!(shares[0].stored_bytes(), 4 * 48 + 32 * (n + 1));
        assert!(fll25::show_with_fault(
            &p,
            &selected,
            &session,
            Fault::ChangedResponse { participant: 1 },
            &mut rng
        )
        .is_err());
        assert!(fll25::show_with_fault(
            &p,
            &selected,
            &session,
            Fault::ChangedOpening { participant: 1 },
            &mut rng
        )
        .is_err());
        let mut changed = result.presentation;
        changed.response_e += F::ONE;
        assert!(fll25::verify(&p, &session, &changed.encode()).is_err());
    }
    for n in [5, 10, 20, 30, 40, 50] {
        let (_, shares, _, _) = fixture_mode(true, 16, 8, n);
        assert_eq!(shares[0].stored_bytes(), 192 + 32 * (n + 1));
    }
}

#[test]
fn certificates_bind_holder_index_d_and_shared_credential() {
    let (p, shares, session, mut rng) = fixture_mode(true, 16, 8, 10);
    // A canonical certificate for a different holder cannot be relabelled.
    let mut wire = shares[1].encode();
    wire[80..176].copy_from_slice(&shares[2].encode()[80..176]);
    let mut selected = shares[..8].to_vec();
    selected[1] = fll25::accept_opt(&p, &wire, 10, 16, 8, 1).unwrap();
    let error = fll25::show(&p, &selected, &session, &mut rng)
        .err()
        .unwrap();
    assert!(error.contains("signature batch failed"));
    // Keep D but replace its certificate by a different canonical G1 element.
    let mut wire = shares[1].encode();
    wire[128..176].copy_from_slice(&G1::generator().to_compressed());
    selected[1] = fll25::accept_opt(&p, &wire, 10, 16, 8, 1).unwrap();
    assert!(fll25::show(&p, &selected, &session, &mut rng).is_err());
    // Change one hidden public attribute consistently for every received share.
    // The old certificates no longer certify this shared credential context.
    let changed = shares[..8]
        .iter()
        .map(|share| {
            let mut wire = share.encode();
            let end = wire.len();
            wire[end - 32..].copy_from_slice(&(share.attributes[9] + F::ONE).to_bytes_be());
            fll25::accept_opt(&p, &wire, 10, 16, 8, share.holder_index).unwrap()
        })
        .collect::<Vec<_>>();
    assert!(fll25::show(&p, &changed, &session, &mut rng).is_err());
    let mut malformed = shares[0].encode();
    malformed[80..128].fill(0);
    assert!(fll25::accept_opt(&p, &malformed, 10, 16, 8, 0).is_err());
}

#[test]
fn certified_and_original_modes_reproduce_the_same_presentation() {
    let mut rng = StdRng::seed_from_u64(8601);
    let (mut p, mut key) = Parameters::setup(10, &mut rng);
    let values = (0..10).map(|i| F::from(i + 1)).collect::<Vec<_>>();
    assert!(fll25::issue_opt(&p, &key, &values, 16, 8, &mut rng).is_err());
    p.enable_optimization(&mut key, &mut rng);
    let original = fll25::issue(&p, &key, &values, 16, 8, &mut rng.clone()).unwrap();
    let certified = fll25::issue_opt(&p, &key, &values, 16, 8, &mut rng).unwrap();
    assert_eq!(original[0].a, certified[0].a);
    let session = Session {
        id: [1; 32],
        nonce: [2; 32],
        disclosed: values
            .iter()
            .enumerate()
            .map(|(i, &v)| (i < 3).then_some(v))
            .collect(),
    };
    let first = fll25::show(&p, &original[..8], &session, &mut rng.clone()).unwrap();
    let second = fll25::show(&p, &certified[..8], &session, &mut rng).unwrap();
    assert_eq!(first.wire, second.wire);
    fll25::verify(&p, &session, &second.wire).unwrap();
}

#[cfg(feature = "op-count")]
#[test]
fn certified_share_operation_counts_are_original_plus_peer_certificates() {
    for (k, n, h) in [(8, 10, 7), (16, 20, 17)] {
        let mut rng = StdRng::seed_from_u64(8602);
        let (mut p, mut key) = Parameters::setup(n, &mut rng);
        p.enable_optimization(&mut key, &mut rng);
        let attrs = (0..n).map(|i| F::from(i as u64 + 1)).collect::<Vec<_>>();
        aw_mhac::take_counts();
        let original = fll25::issue(&p, &key, &attrs, 16, k, &mut rng.clone()).unwrap();
        let count = aw_mhac::take_counts();
        assert_eq!((count.g1_exp, count.g2_exp, count.hash_g1), (17, 0, 0));
        assert_eq!(count.g1_msm, vec![n]);
        let shares = fll25::issue_opt(&p, &key, &attrs, 16, k, &mut rng).unwrap();
        assert_eq!(original[0].a, shares[0].a);
        let count = aw_mhac::take_counts();
        assert_eq!((count.g1_exp, count.g2_exp, count.hash_g1), (33, 0, 16));
        assert_eq!(count.g1_msm, vec![n]);
        let accepted = fll25::accept_opt(&p, &shares[0].encode(), n, 16, k, 0).unwrap();
        assert_eq!(accepted.stored_bytes(), 192 + 32 * (n + 1));
        let count = aw_mhac::take_counts();
        assert_eq!(count.g1_msm, vec![n]);
        assert_eq!((count.pair_terms, count.final_exps), (0, 0));
        let session = Session {
            id: [4; 32],
            nonce: [9; 32],
            disclosed: attrs
                .iter()
                .enumerate()
                .map(|(i, &v)| (i < n - h).then_some(v))
                .collect(),
        };
        let result = fll25::show(&p, &shares[..k], &session, &mut rng).unwrap();
        let total = aw_mhac::take_counts();
        for (i, role) in result.parties.iter().enumerate() {
            let mut expected_msm = vec![n - h];
            if i == 0 {
                expected_msm.push(h + 2);
            }
            expected_msm.extend([k - 1, k - 1]);
            if i != 0 {
                expected_msm.push(h + 3);
            }
            expected_msm.extend(vec![2; if i == 0 { k - 1 } else { k - 2 }]);
            assert_eq!(role.online_counts.g1_msm, expected_msm);
            assert_eq!(
                role.online_counts.g1_exp,
                if i == 0 { k + 2 } else { k + 3 }
            );
            assert_eq!(role.online_counts.g2_exp, 0);
            assert!(role.online_counts.g2_msm.is_empty());
            assert_eq!(
                (role.online_counts.hash_g2, role.online_counts.hash_scalar),
                (0, 1)
            );
            assert_eq!(
                role.online_counts.g1_exp + role.online_counts.g1_msm.iter().sum::<usize>(),
                n + 3 * k + 2 + 2 * (k - 1)
            );
            assert_eq!(role.online_counts.hash_g1, k - 1);
            assert_eq!(
                (role.online_counts.pair_terms, role.online_counts.final_exps),
                (2, 1)
            );
            assert_eq!(role.online_counts.batch_inversions, 1);
        }
        assert_eq!(
            (total.pair_terms, total.final_exps, total.hash_g1),
            (2 * k, k, k * (k - 1))
        );
        fll25::verify(&p, &session, &result.wire).unwrap();
        let count = aw_mhac::take_counts();
        assert_eq!(count.g1_msm, vec![n - h, h + 3]);
        assert_eq!((count.pair_terms, count.final_exps), (2, 1));
    }
}

#[cfg(feature = "op-count")]
#[test]
fn original_cached_protocol_counts_match() {
    for (holders, k, n, h) in [(16, 8, 10, 7), (16, 16, 20, 17)] {
        let (p, shares, mut context, mut rng) = fixture(holders, k, n);
        context.disclosed = shares[0]
            .attributes
            .iter()
            .enumerate()
            .map(|(i, a)| (i < n - h).then_some(*a))
            .collect();
        aw_mhac::take_counts();
        let restored = fll25::accept(&p, &shares[0].encode(), n, holders, k, 0).unwrap();
        assert_eq!(restored.encode(), shares[0].encode());
        let count = aw_mhac::take_counts();
        assert_eq!(count.g1_msm, vec![n]);
        let result = fll25::show(&p, &shares[..k], &context, &mut rng).unwrap();
        let total = aw_mhac::take_counts();
        for (i, role) in result.parties.iter().enumerate() {
            let mut expected_msm = vec![n - h, if i == 0 { h + 2 } else { h + 3 }];
            expected_msm.extend(vec![2; if i == 0 { k - 1 } else { k - 2 }]);
            assert_eq!(role.online_counts.g1_msm, expected_msm);
            assert_eq!(
                role.online_counts.g1_exp,
                if i == 0 { k + 2 } else { k + 3 }
            );
            assert_eq!(
                role.online_counts.g1_exp + role.online_counts.g1_msm.iter().sum::<usize>(),
                n + 3 * k + 2
            );
            assert_eq!(role.online_counts.batch_inversions, 1);
        }
        assert_eq!(total.batch_inversions, k);
        fll25::verify(&p, &context, &result.wire).unwrap();
        let count = aw_mhac::take_counts();
        assert_eq!(count.g1_msm, vec![n - h, h + 3]);
        assert_eq!((count.pair_terms, count.final_exps), (2, 1));
    }
}
