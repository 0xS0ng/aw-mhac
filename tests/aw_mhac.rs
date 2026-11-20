use std::time::Duration;

use aw_mhac::{
    aw_mhac::*,
    common::{Rng, F, G1, G2},
};
use ff::Field;
use group::Group;
use rand::{RngCore, SeedableRng};

struct Fixture {
    pp: Parameters,
    keys: Vec<HolderKey>,
    ipk: G2,
    apk: [G1; 2],
    ask: [F; 2],
    attrs: Vec<F>,
    reg: Registry,
    host: Host,
    ctx: Context,
    rho_size: usize,
}

fn fixture(n_slots: usize, b: usize, n: usize, h: usize, seed: u64) -> Fixture {
    fixture_registered(n_slots, &(0..b).collect::<Vec<_>>(), n, h, seed)
}

fn fixture_registered(
    n_slots: usize,
    registered: &[usize],
    n: usize,
    h: usize,
    seed: u64,
) -> Fixture {
    let mut rng = Rng::seed_from_u64(seed);
    let weights: Vec<_> = (0..n_slots).map(|_| 1 + rng.next_u32() % 127).collect();
    let pp = setup(&weights, n, &mut rng).unwrap();
    let (isk, ipk) = ikeygen(&pp, &mut rng);
    let (ask, apk) = akeygen(&pp, &mut rng);
    let mut keys = vec![];
    let mut rho = vec![];
    let mut pks = vec![];
    for &slot in registered {
        let (mut holder, registration) = hkeygen(&pp, slot, &mut rng).unwrap();
        holder.precompute(&pp);
        keys.push(holder);
        rho.push((slot, registration.encode()));
        pks.push((slot, registration.pk_k.to_compressed()));
    }
    let rho_size = rho[0].1.len();
    let attrs: Vec<_> = (0..n).map(|_| F::random(&mut rng)).collect();
    let mut reg = Registry::new();
    let cred = issue(&pp, isk, &attrs, &rho, &mut reg, &mut rng).unwrap();
    pks.sort_unstable_by_key(|(slot, _)| *slot);
    let host = accept(&pp, ipk, &attrs, &pks, &cred.encode(), &mut rng).unwrap();
    let ctx = Context {
        verifier: [2; 32],
        nonce: [3; 32],
        disclosed: attrs
            .iter()
            .enumerate()
            .map(|(i, &x)| (i >= h).then_some(x))
            .collect(),
        threshold: 1,
    };
    Fixture {
        pp,
        keys,
        ipk,
        apk,
        ask,
        attrs,
        reg,
        host,
        ctx,
        rho_size,
    }
}

impl Fixture {
    fn parts(&self, ctx: &Context, j: &[usize], rng: &mut Rng) -> Vec<(usize, Vec<u8>)> {
        j.iter()
            .map(|&i| {
                let key = self.keys.iter().find(|key| key.slot == i).unwrap();
                (i, part_sign(key, &ctx.encode(), rng).unwrap())
            })
            .collect()
    }

    fn show(&self, ctx: &Context, j: &[usize], rng: &mut Rng) -> Presentation {
        show(
            &self.pp,
            self.ipk,
            self.apk,
            &self.host,
            &self.attrs,
            ctx,
            &self.parts(ctx, j, rng),
            rng,
        )
        .unwrap()
    }

    fn verdict(&self, ctx: &Context, wire: &[u8], rng: &mut Rng, expected: bool) {
        for merged in [true, false] {
            assert_eq!(
                verify(&self.pp, self.ipk, self.apk, ctx, wire, merged, rng).is_ok(),
                expected
            );
        }
    }
}

#[test]
fn complete_roundtrip_and_sizes() {
    let mut rng = Rng::seed_from_u64(101);
    for (n_slots, b, n, h) in [(8, 4, 5, 0), (32, 16, 10, 7), (512, 8, 50, 50)] {
        let f = fixture(n_slots, b, n, h, 11);
        let j = vec![0, b / 2];
        let p = f.show(&f.ctx, &j, &mut rng);
        let wire = p.encode();
        f.verdict(&f.ctx, &wire, &mut rng, true);
        let theta = trace(
            &f.pp,
            f.ipk,
            f.apk,
            f.ask,
            &f.ctx,
            &wire,
            &f.reg,
            Duration::from_secs(600),
            &mut rng,
        )
        .unwrap();
        assert_eq!(theta.theta.slots, j);
        assert_eq!(theta.table_entries, 1 << (b / 2));
        let audit_wire = theta.theta.encode(n_slots).unwrap();
        judge(
            &f.pp,
            f.ipk,
            f.apk,
            &f.ctx,
            &wire,
            &audit_wire,
            &f.reg,
            &mut rng,
        )
        .unwrap();
        assert_eq!(f.rho_size, 48 * n_slots + 160);
        assert_eq!(f.host.cred.encode().len(), 48 * (b + 2) + 96 + 32);
        assert_eq!(wire.len(), 12 * 48 + 2 * 96 + (h + 9) * 32);
        assert_eq!(audit_wire.len(), 192 + n_slots.div_ceil(8));
        assert_eq!(f.parts(&f.ctx, &j, &mut rng)[0].1.len(), 144);
        assert_eq!(
            f.pp.encode().len(),
            48 * (2 * n_slots + n + 9) + 96 + 32 * n_slots
        );
        assert_eq!(
            f.reg.values().next().unwrap().1.len(),
            144 * (b + 1) + 64 * b
        );
        assert_eq!(f.keys[0].encode().unwrap().len(), 80);
        let mut wrong = theta.theta;
        wrong.slots[1] += 1;
        assert!(judge(
            &f.pp,
            f.ipk,
            f.apk,
            &f.ctx,
            &wire,
            &wrong.encode(n_slots).unwrap(),
            &f.reg,
            &mut rng
        )
        .is_err());
    }
}

#[test]
fn wrong_context_partial_and_threshold_are_rejected() {
    let f = fixture(32, 16, 10, 7, 55);
    let mut rng = Rng::seed_from_u64(687);
    let mut other = f.ctx.clone();
    other.nonce[0] ^= 1;
    let j = [0, 2, 7];
    let p = f.show(&f.ctx, &j, &mut rng);
    f.verdict(&other, &p.encode(), &mut rng, false);
    let mut parts = f.parts(&f.ctx, &j, &mut rng);
    parts[1].1 = part_sign(&f.keys[2], &other.encode(), &mut rng).unwrap();
    let changed = show(
        &f.pp, f.ipk, f.apk, &f.host, &f.attrs, &f.ctx, &parts, &mut rng,
    )
    .unwrap();
    f.verdict(&f.ctx, &changed.encode(), &mut rng, false);
    let mut high = f.ctx.clone();
    high.threshold = p.w + 1;
    let p = f.show(&high, &j, &mut rng);
    f.verdict(&high, &p.encode(), &mut rng, false);
}

#[test]
fn every_component_and_required_input_checks() {
    let f = fixture(8, 8, 5, 2, 411);
    let mut rng = Rng::seed_from_u64(782);
    let p = f.show(&f.ctx, &[0, 2, 4, 6], &mut rng);
    macro_rules! altered {
        ($field:ident,$increment:expr) => {{
            let mut changed = p.clone();
            changed.$field += $increment;
            f.verdict(&f.ctx, &changed.encode(), &mut rng, false);
        }};
    }
    macro_rules! random_g1 {
        ($field:ident) => {
            altered!($field, G1::generator() * F::random(&mut rng))
        };
    }
    macro_rules! random_g2 {
        ($field:ident) => {
            altered!($field, G2::generator() * F::random(&mut rng))
        };
    }
    random_g1!(a_bar);
    random_g1!(b_bar);
    random_g1!(k_bar);
    random_g2!(vk_bar);
    random_g1!(v);
    random_g1!(s_bar);
    random_g2!(r_bar);
    random_g1!(c_f);
    random_g1!(c_q);
    random_g1!(u);
    random_g1!(e1);
    random_g1!(e2);
    random_g1!(omega_0);
    random_g1!(omega_1);
    altered!(w, 1);
    altered!(f_zeta, F::ONE);
    altered!(challenge, F::ONE);
    for i in 0..p.response.len() {
        let mut changed = p.clone();
        changed.response[i] += F::ONE;
        f.verdict(&f.ctx, &changed.encode(), &mut rng, false);
    }
    let mut identity = p.clone();
    identity.u = G1::identity();
    f.verdict(&f.ctx, &identity.encode(), &mut rng, false);
    identity = p.clone();
    identity.a_bar = G1::identity();
    f.verdict(&f.ctx, &identity.encode(), &mut rng, false);
    let g1 = (1..1000u16)
        .find_map(|x| {
            let mut bytes = [0; 48];
            bytes[0] = 0x80;
            bytes[46..].copy_from_slice(&x.to_be_bytes());
            (bool::from(blstrs::G1Affine::from_compressed_unchecked(&bytes).is_some())
                && bool::from(blstrs::G1Affine::from_compressed(&bytes).is_none()))
            .then_some(bytes)
        })
        .unwrap();
    let g2 = (1..1000u16)
        .find_map(|x| {
            let mut bytes = [0; 96];
            bytes[0] = 0x80;
            bytes[94..].copy_from_slice(&x.to_be_bytes());
            (bool::from(blstrs::G2Affine::from_compressed_unchecked(&bytes).is_some())
                && bool::from(blstrs::G2Affine::from_compressed(&bytes).is_none()))
            .then_some(bytes)
        })
        .unwrap();
    let mut wire = p.encode();
    wire[32..80].copy_from_slice(&g1);
    f.verdict(&f.ctx, &wire, &mut rng, false);
    let mut wire = p.encode();
    wire[176..272].copy_from_slice(&g2);
    f.verdict(&f.ctx, &wire, &mut rng, false);
}

#[test]
fn fixed_seed_reproduces_bytes() {
    let f = fixture(32, 16, 10, 7, 9);
    let g = fixture(32, 16, 10, 7, 9);
    assert_eq!(f.pp.encode(), g.pp.encode());
    assert_eq!(f.host.cred.encode(), g.host.cred.encode());
    let a = f
        .show(&f.ctx, &[3, 8, 10], &mut Rng::seed_from_u64(791))
        .encode();
    let b = g
        .show(&g.ctx, &[3, 8, 10], &mut Rng::seed_from_u64(791))
        .encode();
    assert_eq!(a, b);
}

#[cfg(feature = "op-count")]
#[test]
fn measured_operation_counts() {
    use aw_mhac::take_counts;
    let mut rng = Rng::seed_from_u64(93);
    for (n_slots, b, k, n, h) in [(32, 16, 8, 10, 7), (64, 8, 4, 20, 10)] {
        let f = fixture(n_slots, b, n, h, 487);
        let base = |c: &aw_mhac::OpCounts| c.g1_exp + c.g1_msm.iter().sum::<usize>();
        take_counts();
        let (mut holder, _) = hkeygen(&f.pp, 0, &mut rng).unwrap();
        holder.precompute(&f.pp);
        let costs = take_counts();
        println!("{n_slots},{b},{k},{n},{h},HKeyGen,{costs:?}");
        assert_eq!((base(&costs), costs.g2_exp), (n_slots + 1, 2));
        assert_eq!(costs.g1_exp, n_slots + 1);
        assert!(costs.g1_msm.is_empty());
        holder.precompute(&f.pp);
        let cached_cost = take_counts();
        assert_eq!((cached_cost.g1_exp, cached_cost.g2_exp), (1, 0));
        let j: Vec<_> = (0..k).collect();
        let parts = f.parts(&f.ctx, &j, &mut rng);
        let costs = take_counts();
        println!("{n_slots},{b},{k},{n},{h},PartSign x{k},{costs:?}");
        assert_eq!((base(&costs), costs.g2_exp, costs.hash_g1), (k, k, k));
        let p = show(
            &f.pp, f.ipk, f.apk, &f.host, &f.attrs, &f.ctx, &parts, &mut rng,
        )
        .unwrap()
        .encode();
        let counts = take_counts();
        println!("{n_slots},{b},{k},{n},{h},Show,{counts:?}");
        assert_eq!(
            (base(&counts), counts.g2_exp, counts.hash_g1),
            (3 * n_slots + h + 33, 2, 1)
        );
        for merged in [false, true] {
            verify(&f.pp, f.ipk, f.apk, &f.ctx, &p, merged, &mut rng).unwrap();
            let counts = take_counts();
            println!("{n_slots},{b},{k},{n},{h},Verify merged={merged},{counts:?}");
            assert_eq!(
                (
                    base(&counts),
                    counts.pair_terms,
                    counts.final_exps,
                    counts.hash_g1
                ),
                if merged {
                    (n + 30, 5, 1, 1)
                } else {
                    (n + 21, 9, 4, 1)
                }
            );
        }
        let theta = trace(
            &f.pp,
            f.ipk,
            f.apk,
            f.ask,
            &f.ctx,
            &p,
            &f.reg,
            Duration::from_secs(600),
            &mut rng,
        )
        .unwrap();
        let trace_counts = take_counts();
        println!("{n_slots},{b},{k},{n},{h},Trace,{trace_counts:?}");
        assert_eq!(base(&trace_counts), n + 36);
        judge(
            &f.pp,
            f.ipk,
            f.apk,
            &f.ctx,
            &p,
            &theta.theta.encode(n_slots).unwrap(),
            &f.reg,
            &mut rng,
        )
        .unwrap();
        let judge_counts = take_counts();
        println!("{n_slots},{b},{k},{n},{h},Judge,{judge_counts:?}");
        assert_eq!(
            (
                base(&judge_counts),
                judge_counts.g2_exp,
                judge_counts.pair_terms
            ),
            (n + 38 + 2 * (k + 1), 2 * k, 5 + k + 2)
        );
    }
}

#[cfg(feature = "op-count")]
#[test]
fn issuance_and_accept_operation_counts() {
    use aw_mhac::take_counts;
    let mut rng = Rng::seed_from_u64(213);
    for (n_slots, b, n) in [(32, 16, 10), (64, 8, 20)] {
        let pp = setup(&vec![1; n_slots], n, &mut rng).unwrap();
        let (isk, ipk) = ikeygen(&pp, &mut rng);
        let rho: Vec<_> = (0..b)
            .map(|j| (j, hkeygen(&pp, j, &mut rng).unwrap().1))
            .collect();
        let wire = rho
            .iter()
            .map(|(j, x)| (*j, x.encode()))
            .collect::<Vec<_>>();
        let registered = rho
            .iter()
            .map(|(j, x)| (*j, x.pk_k.to_compressed()))
            .collect::<Vec<_>>();
        let a = (0..n).map(|_| F::random(&mut rng)).collect::<Vec<_>>();
        let mut reg = Registry::new();
        take_counts();
        let cred = issue(&pp, isk, &a, &wire, &mut reg, &mut rng).unwrap();
        let issue_count = take_counts();
        println!("{n_slots},{b},{n},Issue,{issue_count:?}");
        let g1_total = |c: &aw_mhac::OpCounts| c.g1_exp + c.g1_msm.iter().sum::<usize>();
        assert_eq!(g1_total(&issue_count), 2 * b * n_slots + n + b + 2);
        assert_eq!(
            (
                issue_count.g2_exp,
                issue_count.pair_terms,
                issue_count.final_exps,
                issue_count.hash_scalar
            ),
            (2 * b + 1, b + 1, 1, b)
        );
        accept(&pp, ipk, &a, &registered, &cred.encode(), &mut rng).unwrap();
        let accept_count = take_counts();
        println!("{n_slots},{b},{n},Accept,{accept_count:?}");
        assert_eq!(g1_total(&accept_count), n + 2 * b + 4);
        assert_eq!(
            (
                accept_count.g2_exp,
                accept_count.pair_terms,
                accept_count.final_exps
            ),
            (1, b + 3, 1)
        );
    }
}

#[cfg(feature = "op-count")]
#[test]
fn verify_counts_are_independent_of_slot_count() {
    use aw_mhac::take_counts;
    let mut rng = Rng::seed_from_u64(137);
    let mut expected = None;
    for n_slots in [8, 32, 512] {
        let f = fixture(n_slots, 8, 10, 7, 197);
        let wire = f.show(&f.ctx, &[0, 1, 2, 3, 4, 5, 6, 7], &mut rng).encode();
        take_counts();
        verify(&f.pp, f.ipk, f.apk, &f.ctx, &wire, true, &mut rng).unwrap();
        let counts = take_counts();
        println!("Verify, N={n_slots}, n=10, h=7, {counts:?}");
        assert_eq!(counts.batch_inversions, 1);
        if let Some(reference) = &expected {
            assert_eq!(reference, &counts);
        } else {
            expected = Some(counts);
        }
    }
}

#[cfg(feature = "op-count")]
#[test]
fn trace_visits_the_latest_mask_for_fixed_participant_counts() {
    let f = fixture(32, 16, 10, 7, 681);
    let mut rng = Rng::seed_from_u64(322);
    for k in [2, 4, 8, 16] {
        let slots: Vec<_> = (16 - k..16).collect();
        let wire = f.show(&f.ctx, &slots, &mut rng).encode();
        let recovered = trace(
            &f.pp,
            f.ipk,
            f.apk,
            f.ask,
            &f.ctx,
            &wire,
            &f.reg,
            Duration::from_secs(600),
            &mut rng,
        )
        .unwrap();
        assert_eq!(recovered.theta.slots, slots);
        let expected = if k < 8 {
            (1 << 8) - (1 << (8 - k)) + 1
        } else {
            1 << 8
        };
        assert_eq!(recovered.right_visited, expected);
    }
}

#[test]
fn trace_progress_survives_timeout_and_matches_success() {
    let f = fixture(32, 16, 10, 7, 685);
    let mut rng = Rng::seed_from_u64(326);
    for participants in [vec![0], vec![15], (8..16).collect()] {
        let wire = f.show(&f.ctx, &participants, &mut rng).encode();
        let mut progress = TraceProgress {
            left_visited: 9,
            right_visited: 7,
            ..Default::default()
        };
        let error = trace_with_progress(
            &f.pp,
            f.ipk,
            f.apk,
            f.ask,
            &f.ctx,
            &wire,
            &f.reg,
            Duration::ZERO,
            &mut rng,
            &mut progress,
        )
        .err()
        .unwrap();
        assert_eq!(error, "trace timed out");
        assert_eq!(progress, TraceProgress::default());
        let recovered = trace_with_progress(
            &f.pp,
            f.ipk,
            f.apk,
            f.ask,
            &f.ctx,
            &wire,
            &f.reg,
            Duration::from_secs(600),
            &mut rng,
            &mut progress,
        )
        .unwrap();
        assert_eq!(recovered.theta.slots, participants);
        assert_eq!(progress.left_visited, 256);
        assert_eq!(
            progress.right_visited,
            if participants == [0] {
                1
            } else if participants == [15] {
                129
            } else {
                256
            }
        );
        judge(
            &f.pp,
            f.ipk,
            f.apk,
            &f.ctx,
            &wire,
            &recovered.theta.encode(32).unwrap(),
            &f.reg,
            &mut rng,
        )
        .unwrap();
        #[cfg(feature = "op-count")]
        {
            assert_eq!(recovered.left_generated, 256);
            assert_eq!(recovered.right_generated, 256);
            assert_eq!(recovered.converted_points, 512);
            assert_eq!(recovered.right_visited, progress.right_visited);
            let total_weight: u64 = participants
                .iter()
                .map(|&slot| u64::from(f.pp.weights[slot]))
                .sum();
            let expected_lookups = (0..progress.right_visited)
                .filter(|mask| {
                    let weight: u64 = (0..8)
                        .filter(|bit| mask & (1 << bit) != 0)
                        .map(|bit| u64::from(f.pp.weights[8 + bit]))
                        .sum();
                    weight <= total_weight
                })
                .count();
            assert_eq!(recovered.right_lookups, expected_lookups);
            assert!(recovered.right_generated - recovered.right_visited < TRACE_BATCH_SIZE);
        }
    }
}

#[test]
fn trace_reports_no_subset_when_a_participant_is_missing_from_the_search_record() {
    let mut f = fixture(32, 16, 10, 7, 686);
    let mut rng = Rng::seed_from_u64(327);
    let wire = f.show(&f.ctx, &[15], &mut rng).encode();
    // Negative registry-consistency validation, without changing the proof.
    f.reg.values_mut().for_each(|(slots, _)| {
        slots.pop();
    });
    let mut progress = TraceProgress::default();
    let error = trace_with_progress(
        &f.pp,
        f.ipk,
        f.apk,
        f.ask,
        &f.ctx,
        &wire,
        &f.reg,
        Duration::from_secs(600),
        &mut rng,
        &mut progress,
    )
    .err()
    .unwrap();
    assert_eq!(error, "no participating subset");
    assert_eq!(progress.left_visited, 128);
    assert_eq!(progress.right_visited, 256);
}

// Independent reference for the former full-record decoding path. This reader
// deliberately visits every entry and does not call the new selected decoder.
fn read_all_record_reference(mut wire: &[u8], slots: &[usize]) -> aw_mhac::common::Res<Record> {
    use aw_mhac::common::{eof, read_f, read_g1, read_g2};
    let k = read_g1(&mut wire)?;
    let vk = read_g2(&mut wire)?;
    let mut entries = Vec::new();
    for &slot in slots {
        entries.push(Entry {
            slot,
            pk_j: read_g2(&mut wire)?,
            u_j: read_g1(&mut wire)?,
            pi_j: Proof {
                challenge: read_f(&mut wire)?,
                response: read_f(&mut wire)?,
            },
        });
    }
    eof(wire)?;
    Ok(Record { k, vk, entries })
}

fn judge_full_decode_reference(
    f: &Fixture,
    wire: &[u8],
    theta_wire: &[u8],
    registry: &Registry,
    rng: &mut Rng,
) -> aw_mhac::common::Res<()> {
    use aw_mhac::{
        common::Transcript,
        pairing::{batch_coefficient, g1_exp, g1_msm, g2_exp, pair_product},
    };
    let theta = TraceOutput::decode(theta_wire, f.pp.n_slots)?;
    let presentation = verify(&f.pp, f.ipk, f.apk, &f.ctx, wire, true, rng)?;
    // Reconstruct the unchanged public transcript from public inputs, rather
    // than sharing private proof-validation or record-decode helpers.
    let digest = Transcript::new("AW-MHAC-Public-Parameters")
        .u32(f.pp.n_slots as u32)
        .u32((f.pp.h_i.len() - 1) as u32)
        .add(&f.pp.encode())
        .digest();
    let g = G1::generator();
    let challenge = theta.challenge;
    let [s1, s2] = theta.response;
    let first = [
        g1_msm(&[g, -f.apk[0]], &[s1, challenge]),
        g1_msm(
            &[presentation.u, theta.m - presentation.e1],
            &[s1, challenge],
        ),
        g1_msm(&[g, -f.apk[1]], &[s2, challenge]),
        g1_msm(
            &[presentation.u, theta.k - presentation.e2],
            &[s2, challenge],
        ),
    ];
    let mut transcript = Transcript::new("AW-MHAC-Audit-Proof");
    transcript
        .add(&digest)
        .g2(f.ipk)
        .g1(f.apk[0])
        .g1(f.apk[1])
        .add(&f.ctx.encode())
        .add(wire)
        .g1(theta.m)
        .g1(theta.k);
    for point in first {
        transcript.g1(point);
    }
    if challenge != transcript.scalar() {
        return Err("invalid audit proof".into());
    }
    let (slots, bytes) = registry
        .get(&theta.k.to_compressed())
        .ok_or("missing registration record")?;
    let record = read_all_record_reference(bytes, slots)?;
    if record.k != theta.k
        || theta
            .slots
            .iter()
            .any(|slot| slots.binary_search(slot).is_err())
    {
        return Err("invalid registered subset".into());
    }
    let weight: u64 = theta
        .slots
        .iter()
        .map(|&slot| u64::from(f.pp.weights[slot]))
        .sum();
    let product = theta
        .slots
        .iter()
        .fold(G1::identity(), |sum, &slot| sum + f.pp.ell[slot]);
    if weight != presentation.w || product != presentation.v - theta.m {
        return Err("invalid audited participation".into());
    }
    let coefficient = batch_coefficient(rng);
    let mut bases = vec![record.k];
    let mut coefficients = vec![coefficient];
    let mut pairs = vec![(g1_exp(-f.pp.h_i[0], coefficient), record.vk)];
    for slot in theta.slots {
        let entry = &record.entries[slots.binary_search(&slot).unwrap()];
        let first =
            g2_exp(G2::generator(), entry.pi_j.response) - g2_exp(entry.pk_j, entry.pi_j.challenge);
        let expected = Transcript::new("AW-MHAC-Holder-Proof")
            .add(&digest)
            .u32(slot as u32)
            .g2(entry.pk_j)
            .g2(first)
            .scalar();
        if entry.pi_j.challenge != expected {
            return Err("invalid registered holder proof".into());
        }
        let coefficient = batch_coefficient(rng);
        bases.push(entry.u_j);
        coefficients.push(coefficient);
        pairs.push((g1_exp(-f.pp.ell[slot], coefficient), record.vk - entry.pk_j));
    }
    pairs.push((g1_msm(&bases, &coefficients), G2::generator()));
    if !pair_product(&pairs) {
        return Err("invalid registration binding".into());
    }
    Ok(())
}

fn compare_record_judges(
    f: &Fixture,
    wire: &[u8],
    theta: &[u8],
    registry: &Registry,
    expected: bool,
) {
    let old = judge_full_decode_reference(f, wire, theta, registry, &mut Rng::seed_from_u64(191));
    let new = judge(
        &f.pp,
        f.ipk,
        f.apk,
        &f.ctx,
        wire,
        theta,
        registry,
        &mut Rng::seed_from_u64(191),
    );
    assert_eq!(old.is_ok(), expected, "full-decode reference: {old:?}");
    assert_eq!(new.is_ok(), expected, "selected-decode Judge: {new:?}");
}

#[test]
fn selected_judge_matches_independent_full_decode_on_all_audit_vectors() {
    let mut vectors: Vec<_> = [8, 12, 16, 20, 24, 28, 32]
        .into_iter()
        .map(|b| (32, b, 8, 10, 7))
        .collect();
    vectors.extend([
        (32, 16, 2, 10, 7),
        (32, 16, 4, 10, 7),
        (32, 16, 16, 10, 7),
        (8, 4, 2, 5, 0),
        (512, 8, 2, 50, 50),
        (64, 8, 4, 20, 10),
    ]);
    for (n_slots, b, k, n, h) in vectors {
        // Unsorted, generally noncontiguous registration order exercises the
        // position in Issue's sorted I, rather than position in this vector.
        let registered: Vec<_> = (0..b).map(|i| (13 * i + 7) % n_slots).collect();
        let f = fixture_registered(n_slots, &registered, n, h, 861 + b as u64 + k as u64);
        let mut sorted = registered.clone();
        sorted.sort_unstable();
        let selected = &sorted[b - k..];
        let mut rng = Rng::seed_from_u64(862);
        let wire = f.show(&f.ctx, selected, &mut rng).encode();
        let theta = trace(
            &f.pp,
            f.ipk,
            f.apk,
            f.ask,
            &f.ctx,
            &wire,
            &f.reg,
            Duration::from_secs(600),
            &mut rng,
        )
        .unwrap()
        .theta
        .encode(n_slots)
        .unwrap();
        assert_eq!(f.reg.values().next().unwrap().1.len(), 144 + 208 * b);
        compare_record_judges(&f, &wire, &theta, &f.reg, true);
        #[cfg(feature = "op-count")]
        {
            aw_mhac::take_counts();
            judge_full_decode_reference(&f, &wire, &theta, &f.reg, &mut Rng::seed_from_u64(192))
                .unwrap();
            let old = aw_mhac::take_counts();
            judge(
                &f.pp,
                f.ipk,
                f.apk,
                &f.ctx,
                &wire,
                &theta,
                &f.reg,
                &mut Rng::seed_from_u64(192),
            )
            .unwrap();
            assert_eq!(
                aw_mhac::take_counts(),
                old,
                "Judge count changed for b={b},k={k}"
            );
        }
    }
}

#[test]
fn selected_judge_rejects_header_selected_entry_length_and_j_mutations() {
    let f = fixture_registered(
        32,
        &[27, 2, 19, 7, 31, 11, 23, 5, 17, 29, 13, 3, 25, 9, 21, 15],
        10,
        7,
        863,
    );
    let selected = [17, 19, 21, 23, 25, 27, 29, 31];
    let mut rng = Rng::seed_from_u64(864);
    let wire = f.show(&f.ctx, &selected, &mut rng).encode();
    let theta = trace(
        &f.pp,
        f.ipk,
        f.apk,
        f.ask,
        &f.ctx,
        &wire,
        &f.reg,
        Duration::from_secs(600),
        &mut rng,
    )
    .unwrap()
    .theta;
    let theta_wire = theta.encode(32).unwrap();
    let (key, (slots, bytes)) = f.reg.iter().next().unwrap();
    let record = read_all_record_reference(bytes, slots).unwrap();
    for header in [0, 1] {
        let mut changed = record.clone();
        if header == 0 {
            changed.k += G1::generator();
        } else {
            changed.vk += G2::generator();
        }
        let mut registry = f.reg.clone();
        registry.get_mut(key).unwrap().1 = changed.encode();
        compare_record_judges(&f, &wire, &theta_wire, &registry, false);
    }
    for &slot in &selected {
        let position = slots.binary_search(&slot).unwrap();
        for field in 0..4 {
            let mut changed = record.clone();
            let entry = &mut changed.entries[position];
            match field {
                0 => entry.pk_j += G2::generator(),
                1 => entry.u_j += G1::generator(),
                2 => entry.pi_j.challenge += F::ONE,
                _ => entry.pi_j.response += F::ONE,
            }
            let mut registry = f.reg.clone();
            registry.get_mut(key).unwrap().1 = changed.encode();
            compare_record_judges(&f, &wire, &theta_wire, &registry, false);
        }
        for (offset, width) in [(0, 96), (96, 48), (144, 32), (176, 32)] {
            let mut registry = f.reg.clone();
            registry.get_mut(key).unwrap().1
                [144 + 208 * position + offset..144 + 208 * position + offset + width]
                .fill(0xff);
            compare_record_judges(&f, &wire, &theta_wire, &registry, false);
        }
    }
    for altered in [
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.as_slice(), &[0]].concat(),
        bytes[..144].to_vec(),
    ] {
        let mut registry = f.reg.clone();
        registry.get_mut(key).unwrap().1 = altered;
        compare_record_judges(&f, &wire, &theta_wire, &registry, false);
    }
    for selected in [vec![0], vec![2], Vec::new()] {
        let mut altered = theta.clone();
        altered.slots = selected;
        compare_record_judges(&f, &wire, &altered.encode(32).unwrap(), &f.reg, false);
    }
    // A compressed on-curve point outside the prime-order subgroup must
    // continue to be rejected in any selected G1 entry.
    // blst explicitly rejects the x=0 small-order encoding even on its
    // unchecked path. Find a canonical on-curve non-subgroup test point with
    // a different x; it is used only as rejected decoder input.
    let torsion = (1_u16..4096)
        .find_map(|x| {
            let mut encoded = [0; 48];
            encoded[0] = 0x80;
            encoded[46..].copy_from_slice(&x.to_be_bytes());
            (bool::from(G1::from_compressed_unchecked(&encoded).is_some())
                && bool::from(G1::from_compressed(&encoded).is_none()))
            .then_some(encoded)
        })
        .expect("non-subgroup G1 decoder fixture");
    assert!(bool::from(G1::from_compressed(&torsion).is_none()));
    let position = slots.binary_search(&selected[0]).unwrap();
    let mut registry = f.reg.clone();
    registry.get_mut(key).unwrap().1[144 + 208 * position + 96..144 + 208 * position + 144]
        .copy_from_slice(&torsion);
    compare_record_judges(&f, &wire, &theta_wire, &registry, false);
}

#[test]
fn selected_judge_ignores_unselected_payload_but_still_checks_total_length() {
    let f = fixture(32, 16, 10, 7, 865);
    let selected = [8, 9, 10, 11, 12, 13, 14, 15];
    let mut rng = Rng::seed_from_u64(866);
    let wire = f.show(&f.ctx, &selected, &mut rng).encode();
    let theta = trace(
        &f.pp,
        f.ipk,
        f.apk,
        f.ask,
        &f.ctx,
        &wire,
        &f.reg,
        Duration::from_secs(600),
        &mut rng,
    )
    .unwrap()
    .theta
    .encode(32)
    .unwrap();
    let (key, (slots, bytes)) = f.reg.iter().next().unwrap();
    let record = read_all_record_reference(bytes, slots).unwrap();
    for position in 0..8 {
        let mut changed = record.clone();
        changed.entries[position].pk_j += G2::generator();
        changed.entries[position].u_j += G1::generator();
        changed.entries[position].pi_j.challenge += F::ONE;
        changed.entries[position].pi_j.response += F::ONE;
        let mut registry = f.reg.clone();
        registry.get_mut(key).unwrap().1 = changed.encode();
        compare_record_judges(&f, &wire, &theta, &registry, true);
        for (offset, width) in [(0, 96), (96, 48), (144, 32), (176, 32)] {
            let mut registry = f.reg.clone();
            registry.get_mut(key).unwrap().1
                [144 + 208 * position + offset..144 + 208 * position + offset + width]
                .fill(0xff);
            assert!(judge(&f.pp, f.ipk, f.apk, &f.ctx, &wire, &theta, &registry, &mut rng).is_ok());
            // This intentional difference is only for malformed unused bytes:
            // old full decoding rejected them; selected decoding ignores them.
            assert!(judge_full_decode_reference(&f, &wire, &theta, &registry, &mut rng).is_err());
        }
    }
}

#[test]
fn optional_batch_partial_check_matches_individual_checks_and_rejects_bad_inputs() {
    let f = fixture_registered(
        32,
        &[17, 3, 29, 5, 23, 7, 19, 11, 31, 13, 2, 27, 9, 21, 15, 25],
        10,
        7,
        867,
    );
    let mut rng = Rng::seed_from_u64(868);
    let (slots, record) = f.reg.values().next().unwrap();
    let pks: Vec<_> = read_all_record_reference(record, slots)
        .unwrap()
        .entries
        .iter()
        .map(|entry| (entry.slot, entry.pk_j))
        .collect();
    for selected in [
        vec![3],
        vec![3, 11, 19, 31],
        vec![2, 3, 5, 7, 9, 11, 13, 15],
    ] {
        let parts = f.parts(&f.ctx, &selected, &mut rng);
        for (slot, wire) in &parts {
            check_partial(
                &f.pp,
                pks.iter().find(|(j, _)| j == slot).unwrap().1,
                *slot,
                &f.ctx.encode(),
                wire,
            )
            .unwrap();
        }
        check_partials(&f.pp, &pks, &f.ctx.encode(), &parts, &mut rng).unwrap();
        let mut wrong_context = f.ctx.clone();
        wrong_context.nonce[0] ^= 1;
        assert!(check_partials(&f.pp, &pks, &wrong_context.encode(), &parts, &mut rng).is_err());
        for index in 0..parts.len() {
            let mut changed = parts.clone();
            let mut input = &changed[index].1[96..];
            let s = aw_mhac::common::read_g1(&mut input).unwrap() + G1::generator();
            changed[index].1[96..].copy_from_slice(&s.to_compressed());
            assert!(check_partials(&f.pp, &pks, &f.ctx.encode(), &changed, &mut rng).is_err());
            let mut malformed = parts.clone();
            malformed[index].1[0..96].fill(0xff);
            assert!(check_partials(&f.pp, &pks, &f.ctx.encode(), &malformed, &mut rng).is_err());
        }
        let mut duplicate = parts.clone();
        duplicate.push(parts[0].clone());
        assert!(check_partials(&f.pp, &pks, &f.ctx.encode(), &duplicate, &mut rng).is_err());
        let missing: Vec<_> = pks
            .iter()
            .copied()
            .filter(|(j, _)| *j != selected[0])
            .collect();
        assert!(check_partials(&f.pp, &missing, &f.ctx.encode(), &parts, &mut rng).is_err());
        let mut duplicate_keys = pks.clone();
        duplicate_keys.push(pks[0]);
        assert!(check_partials(&f.pp, &duplicate_keys, &f.ctx.encode(), &parts, &mut rng).is_err());
        let mut trailing = parts.clone();
        trailing[0].1.push(0);
        assert!(check_partials(&f.pp, &pks, &f.ctx.encode(), &trailing, &mut rng).is_err());
        // Default Show remains the original aggregation entry point, and the
        // optional check consumes its own RNG rather than changing its output.
        let a = show(
            &f.pp,
            f.ipk,
            f.apk,
            &f.host,
            &f.attrs,
            &f.ctx,
            &parts,
            &mut Rng::seed_from_u64(869),
        )
        .unwrap()
        .encode();
        check_partials(&f.pp, &pks, &f.ctx.encode(), &parts, &mut rng).unwrap();
        let b = show(
            &f.pp,
            f.ipk,
            f.apk,
            &f.host,
            &f.attrs,
            &f.ctx,
            &parts,
            &mut Rng::seed_from_u64(869),
        )
        .unwrap()
        .encode();
        assert_eq!(a, b);
    }
    assert!(check_partials(&f.pp, &pks, &f.ctx.encode(), &[], &mut rng).is_err());
}

#[cfg(feature = "op-count")]
#[test]
fn optional_partial_batch_check_uses_one_pair_product_and_128_bit_coefficients() {
    use aw_mhac::{pairing::batch_coefficient, take_counts};
    let f = fixture(32, 16, 10, 7, 870);
    let mut rng = Rng::seed_from_u64(871);
    let (slots, record) = f.reg.values().next().unwrap();
    let pks: Vec<_> = read_all_record_reference(record, slots)
        .unwrap()
        .entries
        .iter()
        .map(|entry| (entry.slot, entry.pk_j))
        .collect();
    for k in [1, 2, 4, 8, 16] {
        let parts = f.parts(&f.ctx, &(0..k).collect::<Vec<_>>(), &mut rng);
        take_counts();
        check_partials(&f.pp, &pks, &f.ctx.encode(), &parts, &mut rng).unwrap();
        let counts = take_counts();
        assert_eq!(counts.g1_exp, k);
        assert_eq!(counts.g1_msm, vec![k]);
        assert_eq!(counts.g2_exp, 0);
        assert_eq!(counts.g2_msm, vec![k]);
        assert_eq!(
            (counts.pair_terms, counts.final_exps, counts.hash_g1),
            (k + 2, 1, 1)
        );
    }
    for _ in 0..64 {
        let coefficient = batch_coefficient(&mut rng);
        assert_ne!(coefficient, F::ZERO);
        assert!(coefficient.to_bytes_be()[..16]
            .iter()
            .all(|&byte| byte == 0));
    }
}
