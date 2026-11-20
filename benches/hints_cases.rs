//! hinTS with its native signer universe and separate virtual domain point.
use crate::{attrs, bits_bytes, disclosure, Case};
use aw_mhac::{
    baselines::hints::{self, AggregationKey, Parameters, SecretKey, VerificationKey},
    common::{Res, Rng},
};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};
struct Fixture {
    pp: Parameters,
    ak: AggregationKey,
    vk: VerificationKey,
    keys: Vec<SecretKey>,
    ids: Vec<usize>,
    message: Vec<u8>,
    public_keys: Vec<Vec<u8>>,
    hint_wires: Vec<Vec<u8>>,
}
fn fixture(c: &Case) -> Res<Fixture> {
    let (b, k, n, h) = (c.dim(1), c.dim(2), c.dim(3), c.dim(4));
    if k < 2 || k > b || h > n {
        return Err("invalid hinTS dimensions".into());
    }
    let pp = hints::setup(&vec![1; b], &mut c.fixture_rng("setup"))?;
    if pp.d != c.dim(0) {
        return Err("hinTS native domain differs from configured domain".into());
    }
    let mut key_rng = c.fixture_rng("keys");
    let keys = (0..b)
        .map(|_| hints::kgen(&mut key_rng))
        .collect::<Vec<_>>();
    let hint_wires = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| Ok(hints::hint_gen(&pp, slot, key)?.encode()))
        .collect::<Res<Vec<_>>>()?;
    let public_keys = keys
        .iter()
        .map(|key| key.pk_i.to_compressed().to_vec())
        .collect::<Vec<_>>();
    let (ak, vk) = hints::preprocess(
        &pp,
        &public_keys,
        &hint_wires,
        &mut c.fixture_rng("preprocess"),
    )?;
    let ids = c.participants();
    if ids.len() != k || ids.iter().any(|&id| id >= b) {
        return Err("hinTS participant outside real signer universe".into());
    }
    let a = attrs(n, &mut c.fixture_rng("attributes"));
    let mut request_rng = c.fixture_rng("request");
    let message = aw_mhac::aw_mhac::Context {
        verifier: bits_bytes(&mut request_rng),
        nonce: bits_bytes(&mut request_rng),
        disclosed: disclosure(&a, h),
        threshold: k as u64,
    }
    .encode();
    Ok(Fixture {
        pp,
        ak,
        vk,
        keys,
        ids,
        message,
        public_keys,
        hint_wires,
    })
}
fn fixture_parts(f: &Fixture) -> (Vec<usize>, Vec<Vec<u8>>) {
    let mut parts = f
        .ids
        .iter()
        .map(|&id| (id, hints::sign(&f.keys[id], &f.message)))
        .collect::<Vec<_>>();
    parts.sort_unstable_by_key(|(id, _)| *id);
    parts.into_iter().unzip()
}
pub fn comparison(c: &Case) -> Res<Box<dyn FnMut(&mut Rng) -> Res<Vec<Duration>>>> {
    let f = fixture(c)?;
    Ok(Box::new(move |rng| {
        let started = Instant::now();
        let h = hints::hash_message(&f.message);
        let host_id = f.ids[0];
        let host_signature = hints::sign_with_hash(&f.keys[host_id], h);
        let mut host_time = started.elapsed();
        let mut others_time = Duration::ZERO;
        let mut parts = vec![(host_id, host_signature)];
        for &id in f.ids.iter().skip(1) {
            let started = Instant::now();
            let signature = hints::sign(&f.keys[id], &f.message);
            others_time += started.elapsed();
            parts.push((id, signature));
        }
        let started = Instant::now();
        parts.sort_unstable_by_key(|(id, _)| *id);
        let (ids, signatures): (Vec<_>, Vec<_>) = parts.into_iter().unzip();
        let wire =
            hints::sign_aggr_with_hash(&f.pp, &f.ak, &f.vk, &ids, &f.message, h, &signatures, rng)?;
        host_time += started.elapsed();
        black_box(wire);
        Ok(vec![
            others_time / (f.ids.len() as u32 - 1),
            host_time,
            others_time + host_time,
        ])
    }))
}
pub fn run(c: &Case) -> Res<()> {
    if c.experiment == "compare_holder_storage" {
        let key = hints::kgen(&mut c.fixture_rng("keys"));
        c.bytes(
            "Storage",
            "holder",
            key.sk_i.to_bytes_be().len(),
            "signer scalar",
        );
        return Ok(());
    }
    let f = fixture(c)?;
    let (ids, parts) = fixture_parts(&f);
    let wire = hints::sign_aggr(
        &f.pp,
        &f.ak,
        &f.vk,
        &ids,
        &f.message,
        &parts,
        &mut c.fixture_rng("proof"),
    )?;
    hints::verify(
        &f.vk,
        &f.message,
        c.dim(2) as u64,
        &wire,
        true,
        &mut c.fixture_rng("verify-fixture"),
    )?;
    if c.experiment == "compare_link_bytes" {
        let other_bytes = f
            .ids
            .iter()
            .skip(1)
            .map(|&id| hints::sign(&f.keys[id], &f.message).len())
            .sum::<usize>();
        let threshold_bytes = 32;
        c.bytes(
            "LinkBytes",
            "link",
            threshold_bytes * f.ids.len() + other_bytes + wire.len(),
            "threshold on each request link non-host signatures and final aggregate",
        );
        c.bytes(
            "LogicalBytes",
            "communication",
            threshold_bytes + other_bytes + wire.len(),
            "threshold once non-host signatures once and final aggregate",
        );
        c.bytes(
            "ContextBytes",
            "verifier",
            f.message.len() - threshold_bytes,
            "identical request identifier nonce and disclosed attributes excluded",
        );
        c.bytes(
            "OneWayMessages",
            "communication",
            2 * f.ids.len(),
            "verifier request holder requests responses and final aggregate",
        );
        return Ok(());
    }
    if c.experiment == "compare_computation" {
        let mut operation = comparison(c)?;
        return c.sample_group(
            &[("PartSign", "holder"), ("Show", "host"), ("Total", "total")],
            move |rng| operation(rng),
        );
    }
    if c.experiment == "aggregation_checks" {
        return c.timed("ShowWithPartialChecks", "host", |rng| {
            hints::sign_aggr_with_partial_checks(&f.pp, &f.ak, &f.vk, &ids, &f.message, &parts, rng)
        });
    }
    if c.experiment != "time_cost_table" {
        return Err("unsupported hinTS experiment".into());
    }
    c.bytes(
        "Presentation",
        "host",
        wire.len(),
        "actual encoded verifier presentation",
    );
    c.timed("HKeyGen", "holder", |rng| {
        let key = hints::kgen(rng);
        let hint = hints::hint_gen(&f.pp, f.ids[0], &key)?.encode();
        Ok((key, hint))
    })?;
    c.timed("Issue", "issuer", |rng| {
        hints::preprocess(&f.pp, &f.public_keys, &f.hint_wires, rng)
    })?;
    c.timed("PartSign", "holder", |_rng| {
        Ok(hints::sign(&f.keys[f.ids[1]], &f.message))
    })?;
    c.timed("Show", "host", |rng| {
        hints::sign_aggr(&f.pp, &f.ak, &f.vk, &ids, &f.message, &parts, rng)
    })?;
    c.timed("Verify", "verifier", |rng| {
        hints::verify(&f.vk, &f.message, c.dim(2) as u64, &wire, true, rng)
    })?;
    c.timed("VerifyUnmerged", "verifier", |rng| {
        hints::verify(&f.vk, &f.message, c.dim(2) as u64, &wire, false, rng)
    })?;
    Ok(())
}
