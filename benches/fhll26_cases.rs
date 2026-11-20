//! FHLL26 BBS-BLS with the combined host-side showing boundary.

use crate::{attrs, bits_bytes, disclosure, Case};
use aw_mhac::{baselines::fhll26, common::Res};
use std::{hint::black_box, time::Instant};

pub fn run(c: &Case) -> Res<()> {
    let n = c.dim(3);
    let h = c.dim(4);
    let pp = fhll26::setup(n);
    if c.experiment == "compare_holder_storage" {
        let key = fhll26::dev_kgen(&pp, &mut c.fixture_rng("device-key"));
        c.bytes(
            "Storage",
            "holder",
            key.sk.to_bytes_be().len(),
            "secure element private key",
        );
        return Ok(());
    }
    if c.experiment != "time_cost_table" {
        return Err("unsupported FHLL26 experiment".into());
    }
    let a = attrs(n, &mut c.fixture_rng("attributes"));
    let issuer = fhll26::iss_kgen(&pp, &mut c.fixture_rng("issuer-key"));
    let device = fhll26::dev_kgen(&pp, &mut c.fixture_rng("device-key"));
    let ipk = issuer.pk.to_compressed();
    let dpk = device.pk.to_compressed();
    let cred = fhll26::issue(&pp, &issuer, &dpk, &a, &mut c.fixture_rng("issue"))?.encode();
    let host = fhll26::accept(&pp, &ipk, &dpk, &cred, &a)?;
    let disclosed_vector = disclosure(&a, h);
    let disclosed = disclosed_vector
        .iter()
        .enumerate()
        .filter_map(|(index, value)| value.map(|value| (index, value)))
        .collect::<Vec<_>>();
    let indices = disclosed
        .iter()
        .map(|&(index, _)| index)
        .collect::<Vec<_>>();
    let mut request_rng = c.fixture_rng("request");
    let context = aw_mhac::aw_mhac::Context {
        verifier: bits_bytes(&mut request_rng),
        nonce: bits_bytes(&mut request_rng),
        disclosed: disclosed_vector,
        threshold: 1,
    }
    .encode();
    let (state, request) = fhll26::show_user1(&pp, &host, &mut c.fixture_rng("proof-request"));
    let response = fhll26::show_se(&pp, &device, &request, &context)?;
    let wire = fhll26::show_user2(
        &pp,
        &host,
        &state,
        &context,
        &indices,
        &response,
        &mut c.fixture_rng("proof"),
    )?;
    fhll26::verify(
        &pp,
        &ipk,
        &context,
        &disclosed,
        &wire,
        true,
        &mut c.fixture_rng("verify-fixture"),
    )?;

    c.bytes(
        "Presentation",
        "host",
        wire.len(),
        "actual encoded verifier presentation",
    );

    c.timed("HKeyGen", "device", |rng| Ok(fhll26::dev_kgen(&pp, rng)))?;
    c.timed("Issue", "issuer", |rng| {
        Ok(fhll26::issue(&pp, &issuer, &dpk, &a, rng)?.encode())
    })?;
    c.timed("Accept", "host", |_rng| {
        fhll26::accept(&pp, &ipk, &dpk, &cred, &a)
    })?;
    c.timed("PartSign", "secure_element", |_rng| {
        fhll26::show_se(&pp, &device, &request, &context)
    })?;
    c.sample_group(&[("ShowUser1", "host"), ("Show", "host")], |rng| {
        let started = Instant::now();
        let (state, request) = fhll26::show_user1(&pp, &host, rng);
        let user1 = started.elapsed();
        let response = fhll26::show_se(&pp, &device, &request, &context)?;
        let started = Instant::now();
        let wire = fhll26::show_user2(&pp, &host, &state, &context, &indices, &response, rng)?;
        let user2 = started.elapsed();
        black_box(wire);
        Ok(vec![user1, user1 + user2])
    })?;
    c.timed("Verify", "verifier", |rng| {
        fhll26::verify(&pp, &ipk, &context, &disclosed, &wire, true, rng)
    })?;
    c.timed("VerifyUnmerged", "verifier", |rng| {
        fhll26::verify(&pp, &ipk, &context, &disclosed, &wire, false, rng)
    })?;
    Ok(())
}
