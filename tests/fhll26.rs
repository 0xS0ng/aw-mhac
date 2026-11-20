use aw_mhac::baselines::fhll26::{
    self, DeviceKey, Host, IssuerKey, Parameters, Presentation, UserState,
};
use aw_mhac::common::{Rng, F, G1, G2};
use ff::Field;
use group::Group;
use rand::SeedableRng;

struct Fixture {
    pp: Parameters,
    issuer: IssuerKey,
    device: DeviceKey,
    host: Host,
    state: UserState,
    request: Vec<u8>,
    disclosed: Vec<usize>,
}

impl Fixture {
    fn new(n: usize, h: usize, rng: &mut Rng) -> Self {
        let pp = fhll26::setup(n);
        let issuer = fhll26::iss_kgen(&pp, rng);
        let device = fhll26::dev_kgen(&pp, rng);
        let attrs = (0..n).map(|_| F::random(&mut *rng)).collect::<Vec<_>>();
        let credential =
            fhll26::issue(&pp, &issuer, &device.pk.to_compressed(), &attrs, rng).unwrap();
        assert_eq!(credential.encode().len(), 80);
        let host = fhll26::accept(
            &pp,
            &issuer.pk.to_compressed(),
            &device.pk.to_compressed(),
            &credential.encode(),
            &attrs,
        )
        .unwrap();
        let (state, request) = fhll26::show_user1(&pp, &host, rng);
        let disclosed = (h..n).collect();
        Self {
            pp,
            issuer,
            device,
            host,
            state,
            request,
            disclosed,
        }
    }

    fn presentation(&self, context: &[u8], rng: &mut Rng) -> Vec<u8> {
        let response = fhll26::show_se(&self.pp, &self.device, &self.request, context).unwrap();
        assert_eq!(response.len(), 96);
        fhll26::show_user2(
            &self.pp,
            &self.host,
            &self.state,
            context,
            &self.disclosed,
            &response,
            rng,
        )
        .unwrap()
    }

    fn verify(
        &self,
        wire: &[u8],
        context: &[u8],
        batched: bool,
        rng: &mut Rng,
    ) -> Result<(), String> {
        let disclosed = self
            .disclosed
            .iter()
            .map(|&i| (i, self.host.attrs[i]))
            .collect::<Vec<_>>();
        fhll26::verify(
            &self.pp,
            &self.issuer.pk.to_compressed(),
            context,
            &disclosed,
            wire,
            batched,
            rng,
        )
    }
}

#[test]
fn honest_execution_and_sizes() {
    let mut rng = Rng::seed_from_u64(26);
    for (n, h) in [(5, 0), (10, 7), (20, 20)] {
        let fixture = Fixture::new(n, h, &mut rng);
        assert_eq!(fixture.request.len(), 48);
        let wire = fixture.presentation(b"presentation context", &mut rng);
        assert_eq!(wire.len(), 448 + 32 * h);
        for batched in [false, true] {
            fixture
                .verify(&wire, b"presentation context", batched, &mut rng)
                .unwrap();
        }
        let one = fhll26::show_se(
            &fixture.pp,
            &fixture.device,
            &fixture.request,
            b"deterministic",
        )
        .unwrap();
        let two = fhll26::show_se(
            &fixture.pp,
            &fixture.device,
            &fixture.request,
            b"deterministic",
        )
        .unwrap();
        assert_eq!(one, two);
    }
}

#[test]
fn context_binding_and_host_signature_check() {
    let mut rng = Rng::seed_from_u64(27);
    let fixture = Fixture::new(10, 7, &mut rng);
    let wire = fixture.presentation(b"expected context", &mut rng);
    for batched in [false, true] {
        assert!(fixture
            .verify(&wire, b"other context", batched, &mut rng)
            .is_err());
    }
    let wrong_response = fhll26::show_se(
        &fixture.pp,
        &fixture.device,
        &fixture.request,
        b"other context",
    )
    .unwrap();
    let result = fhll26::show_user2(
        &fixture.pp,
        &fixture.host,
        &fixture.state,
        b"expected context",
        &fixture.disclosed,
        &wrong_response,
        &mut rng,
    );
    assert!(result.unwrap_err().contains("host device signature"));
    let mut changed = Presentation::decode(&wire, 7).unwrap();
    let q = {
        let mut bytes = fixture.state.dpk_bar.to_compressed().to_vec();
        bytes.extend_from_slice(&(b"other context".len() as u32).to_be_bytes());
        bytes.extend_from_slice(b"other context");
        aw_mhac::hash::hash_to_g2(
            &bytes,
            b"FHLL26_BBS_BLS_SIGN_BLS12381G2_XMD:SHA-256_SSWU_RO_",
        )
    };
    changed.pi_se = q * (fixture.device.sk + fixture.state.r_key);
    for batched in [false, true] {
        assert!(fixture
            .verify(&changed.encode(), b"expected context", batched, &mut rng)
            .is_err());
    }
}

#[test]
fn each_presentation_component_is_bound() {
    let mut rng = Rng::seed_from_u64(28);
    let fixture = Fixture::new(10, 7, &mut rng);
    let context = b"component checks";
    let wire = fixture.presentation(context, &mut rng);
    for (offset, group) in [(0, 1), (48, 2), (144, 1), (192, 1), (240, 1)] {
        let replacement = if group == 1 {
            (G1::generator() * F::random(&mut rng))
                .to_compressed()
                .to_vec()
        } else {
            (G2::generator() * F::random(&mut rng))
                .to_compressed()
                .to_vec()
        };
        let mut changed = wire.clone();
        changed[offset..offset + replacement.len()].copy_from_slice(&replacement);
        for batched in [false, true] {
            assert!(
                fixture
                    .verify(&changed, context, batched, &mut rng)
                    .is_err(),
                "offset {offset}"
            );
        }
    }
    for offset in (288..wire.len()).step_by(32) {
        let mut changed = wire.clone();
        let value = F::from_bytes_be(wire[offset..offset + 32].try_into().unwrap()).unwrap();
        changed[offset..offset + 32].copy_from_slice(&(value + F::ONE).to_bytes_be());
        for batched in [false, true] {
            assert!(
                fixture
                    .verify(&changed, context, batched, &mut rng)
                    .is_err(),
                "offset {offset}"
            );
        }
    }
}

#[test]
fn input_checks_reject_invalid_subgroups_and_identity_signature() {
    let mut rng = Rng::seed_from_u64(29);
    let fixture = Fixture::new(10, 7, &mut rng);
    let wire = fixture.presentation(b"subgroup checks", &mut rng);
    let wrong_g1 = (1..1000u16)
        .find_map(|value| {
            let mut encoded = [0u8; 48];
            encoded[0] = 0x80;
            encoded[46..].copy_from_slice(&value.to_be_bytes());
            (bool::from(blstrs::G1Affine::from_compressed_unchecked(&encoded).is_some())
                && bool::from(blstrs::G1Affine::from_compressed(&encoded).is_none()))
            .then_some(encoded)
        })
        .expect("a deterministic on-curve point outside the G1 subgroup");
    assert!(fhll26::show_se(&fixture.pp, &fixture.device, &wrong_g1, b"subgroup checks").is_err());

    let wrong_g2 = (1..1000u16)
        .find_map(|value| {
            let mut encoded = [0u8; 96];
            encoded[0] = 0x80;
            encoded[94..].copy_from_slice(&value.to_be_bytes());
            (bool::from(blstrs::G2Affine::from_compressed_unchecked(&encoded).is_some())
                && bool::from(blstrs::G2Affine::from_compressed(&encoded).is_none()))
            .then_some(encoded)
        })
        .expect("a deterministic on-curve point outside the G2 subgroup");
    assert!(fhll26::show_user2(
        &fixture.pp,
        &fixture.host,
        &fixture.state,
        b"subgroup checks",
        &fixture.disclosed,
        &wrong_g2,
        &mut rng,
    )
    .is_err());

    for (offset, bytes) in [(0, wrong_g1.as_slice()), (48, wrong_g2.as_slice())] {
        let mut changed = wire.clone();
        changed[offset..offset + bytes.len()].copy_from_slice(bytes);
        assert!(fixture
            .verify(&changed, b"subgroup checks", true, &mut rng)
            .is_err());
    }
    let mut changed = wire.clone();
    changed[144..192].copy_from_slice(&G1::identity().to_compressed());
    assert!(fixture
        .verify(&changed, b"subgroup checks", true, &mut rng)
        .unwrap_err()
        .contains("identity"));
    let mut changed = wire;
    changed[288..320].fill(0xff);
    assert!(fixture
        .verify(&changed, b"subgroup checks", true, &mut rng)
        .is_err());
}

#[test]
fn fixed_seed_reproduces_objects() {
    let mut first_rng = Rng::seed_from_u64(30);
    let mut second_rng = Rng::seed_from_u64(30);
    let first = Fixture::new(10, 7, &mut first_rng);
    let second = Fixture::new(10, 7, &mut second_rng);
    assert_eq!(
        first.host.credential.encode(),
        second.host.credential.encode()
    );
    assert_eq!(first.request, second.request);
    assert_eq!(
        first.presentation(b"reproducible", &mut first_rng),
        second.presentation(b"reproducible", &mut second_rng),
    );
}

#[cfg(feature = "op-count")]
#[test]
fn operation_counts_match_the_protocol() {
    use aw_mhac::{take_counts, OpCounts};
    fn check(name: &str, expected: OpCounts) -> OpCounts {
        let actual = take_counts();
        assert_eq!(actual, expected, "{name}");
        eprintln!("FHLL26 {name} {actual:?}");
        actual
    }
    for (n, h) in [(10, 7), (5, 2)] {
        let mut rng = Rng::seed_from_u64(26);
        take_counts();
        let pp = fhll26::setup(n);
        check(
            "Setup",
            OpCounts {
                hash_g1: n + 1,
                ..Default::default()
            },
        );
        let issuer = fhll26::iss_kgen(&pp, &mut rng);
        check(
            "IssKGen",
            OpCounts {
                g2_exp: 1,
                ..Default::default()
            },
        );
        let device = fhll26::dev_kgen(&pp, &mut rng);
        check(
            "DevKGen",
            OpCounts {
                g1_exp: 1,
                ..Default::default()
            },
        );
        let attrs = (0..n).map(|_| F::random(&mut rng)).collect::<Vec<_>>();
        let credential =
            fhll26::issue(&pp, &issuer, &device.pk.to_compressed(), &attrs, &mut rng).unwrap();
        check(
            "Issue",
            OpCounts {
                g1_exp: 1,
                g1_msm: vec![n],
                ..Default::default()
            },
        );
        let host = fhll26::accept(
            &pp,
            &issuer.pk.to_compressed(),
            &device.pk.to_compressed(),
            &credential.encode(),
            &attrs,
        )
        .unwrap();
        check(
            "VfCred/cache",
            OpCounts {
                g2_exp: 1,
                g1_msm: vec![n],
                pair_terms: 2,
                final_exps: 1,
                ..Default::default()
            },
        );
        let (state, request) = fhll26::show_user1(&pp, &host, &mut rng);
        let show_user1 = check(
            "ShowUser1",
            OpCounts {
                g1_exp: 1,
                ..Default::default()
            },
        );
        let response = fhll26::show_se(&pp, &device, &request, b"count").unwrap();
        check(
            "ShowSE",
            OpCounts {
                g2_exp: 1,
                hash_g2: 1,
                ..Default::default()
            },
        );
        let indices = (h..n).collect::<Vec<_>>();
        let proof = fhll26::show_user2(&pp, &host, &state, b"count", &indices, &response, &mut rng)
            .unwrap();
        let show_user2 = check(
            "ShowUser2",
            OpCounts {
                g1_exp: 2,
                g2_exp: 1,
                g1_msm: vec![2, n - h, h + 2, 2],
                pair_terms: 2,
                final_exps: 1,
                hash_g2: 1,
                hash_scalar: 1,
                ..Default::default()
            },
        );
        let g1_bases = show_user1.g1_exp
            + show_user2.g1_exp
            + show_user1
                .g1_msm
                .iter()
                .chain(&show_user2.g1_msm)
                .sum::<usize>();
        assert_eq!(g1_bases, n + 9);
        assert_eq!(show_user1.g2_exp + show_user2.g2_exp, 1);
        assert_eq!(show_user1.pair_terms + show_user2.pair_terms, 2);
        assert_eq!(show_user1.hash_g2 + show_user2.hash_g2, 1);
        let disclosed = indices.iter().map(|&i| (i, attrs[i])).collect::<Vec<_>>();
        for batched in [false, true] {
            fhll26::verify(
                &pp,
                &issuer.pk.to_compressed(),
                b"count",
                &disclosed,
                &proof,
                batched,
                &mut rng,
            )
            .unwrap();
            check(
                if batched {
                    "Verify/batched"
                } else {
                    "Verify/separate"
                },
                OpCounts {
                    g1_exp: if batched { 4 } else { 0 },
                    g1_msm: vec![n - h, h + 3, 3],
                    pair_terms: 4,
                    final_exps: if batched { 1 } else { 2 },
                    hash_g2: 1,
                    hash_scalar: 1,
                    ..Default::default()
                },
            );
        }
    }
}
