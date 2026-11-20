//! Accountable Weighted Multi-Holder Anonymous Credentials for the Internet of Things, Section V.

use ff::Field;
use group::Group;
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use crate::{
    bbs,
    common::{
        eof, rand_nonzero, read_f, read_g1, read_g2, read_uint, uint_bytes, Res, Rng, Transcript,
        F, G1, G2,
    },
    hash::hash_to_g1,
    kzg,
    pairing::{batch_coefficient, g1_exp, g1_msm, g2_exp, g2_msm, pair_product},
    pok,
    poly::{batch_invert, divide_vanishing, eval, interpolate, polynomial_mul, root, vanishing},
};

pub struct Parameters {
    pub n_slots: usize,
    pub weights: Vec<u32>,
    pub omega: F,
    pub srs: Vec<G1>,
    pub tau_g2: G2,
    pub ell: Vec<G1>,
    pub z: [G1; 2],
    pub g0: G1,
    pub h_i: Vec<G1>,
    w: Vec<F>,
    pp_digest: [u8; 32],
}

impl Parameters {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for &w in &self.weights {
            bytes.extend_from_slice(&uint_bytes(w.into()));
        }
        for point in &self.srs {
            bytes.extend_from_slice(&point.to_compressed());
        }
        bytes.extend_from_slice(&self.tau_g2.to_compressed());
        for point in self
            .ell
            .iter()
            .chain(&self.z)
            .chain(std::iter::once(&self.g0))
            .chain(&self.h_i)
        {
            bytes.extend_from_slice(&point.to_compressed());
        }
        bytes
    }

    fn n_attrs(&self) -> usize {
        self.h_i.len() - 1
    }
}

pub fn setup(weights: &[u32], n_attrs: usize, rng: &mut Rng) -> Res<Parameters> {
    let n_slots = weights.len();
    if !n_slots.is_power_of_two()
        || n_slots < 2
        || n_slots > 512
        || weights.contains(&0)
        || n_attrs == 0
    {
        return Err("invalid layout or attribute count".into());
    }
    let tau = loop {
        let tau = rand_nonzero(rng);
        if vanishing(tau, n_slots) != F::ZERO {
            break tau;
        }
    };
    let g1 = G1::generator();
    let g2 = G2::generator();
    let omega = root(n_slots);
    let mut power = F::ONE;
    let mut srs = Vec::with_capacity(n_slots + 5);
    for _ in 0..=n_slots + 4 {
        srs.push(g1_exp(g1, power));
        power *= tau;
    }
    // Setup: evaluate the Lagrange bases and masking terms at tau.
    let z_tau = vanishing(tau, n_slots);
    let omega_j = std::iter::successors(Some(F::ONE), |x| Some(*x * omega))
        .take(n_slots)
        .collect::<Vec<_>>();
    let mut denominators: Vec<_> = omega_j.iter().map(|&x| tau - x).collect();
    batch_invert(&mut denominators)?;
    let ell = weights
        .iter()
        .zip(omega_j)
        .zip(denominators)
        .map(|((&w, x), inv)| g1_exp(g1, F::from(u64::from(w)) * x * z_tau * inv))
        .collect();
    let z = [g1_exp(g1, tau * z_tau), g1_exp(g1, tau * tau * z_tau)];
    let g0 = g1_exp(g1, rand_nonzero(rng));
    let h_i = (0..=n_attrs)
        .map(|_| g1_exp(g1, rand_nonzero(rng)))
        .collect();
    let w = interpolate(
        weights
            .iter()
            .map(|&w| F::from(n_slots as u64 * u64::from(w)))
            .collect(),
    );
    let mut pp = Parameters {
        n_slots,
        weights: weights.to_vec(),
        omega,
        srs,
        tau_g2: g2_exp(g2, tau),
        ell,
        z,
        g0,
        h_i,
        w,
        pp_digest: [0; 32],
    };
    // Setup: commit to the canonical public parameter encoding once for Fiat-Shamir.
    pp.pp_digest = Transcript::new("AW-MHAC-Public-Parameters")
        .u32(n_slots as u32)
        .u32(n_attrs as u32)
        .add(&pp.encode())
        .digest();
    Ok(pp)
}

pub fn ikeygen(_pp: &Parameters, rng: &mut Rng) -> (F, G2) {
    let isk = F::random(rng);
    (isk, g2_exp(G2::generator(), isk))
}

pub fn akeygen(_pp: &Parameters, rng: &mut Rng) -> ([F; 2], [G1; 2]) {
    let ask = [F::random(&mut *rng), F::random(rng)];
    (ask, ask.map(|y| g1_exp(G1::generator(), y)))
}

pub struct HolderKey {
    pub slot: usize,
    alpha_k: F,
    ell_alpha: Option<G1>,
}

impl HolderKey {
    pub fn precompute(&mut self, pp: &Parameters) -> G1 {
        let point = g1_exp(pp.ell[self.slot], self.alpha_k);
        self.ell_alpha = Some(point);
        point
    }
    pub fn encode(&self) -> Res<Vec<u8>> {
        let mut bytes = self.alpha_k.to_bytes_be().to_vec();
        bytes.extend_from_slice(
            &self
                .ell_alpha
                .ok_or("missing holder precomputation")?
                .to_compressed(),
        );
        Ok(bytes)
    }
}

#[derive(Clone, Copy)]
pub struct Proof {
    pub challenge: F,
    pub response: F,
}

impl Proof {
    fn write(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.challenge.to_bytes_be());
        bytes.extend_from_slice(&self.response.to_bytes_be());
    }
    fn read(input: &mut &[u8]) -> Res<Self> {
        Ok(Self {
            challenge: read_f(input)?,
            response: read_f(input)?,
        })
    }
}

pub struct Registration {
    pub pk_k: G2,
    pub k_k: G1,
    pub u_kj: Vec<G1>,
    pub pi_k: Proof,
}

impl Registration {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.pk_k.to_compressed().to_vec();
        bytes.extend_from_slice(&self.k_k.to_compressed());
        for hint in &self.u_kj {
            bytes.extend_from_slice(&hint.to_compressed());
        }
        self.pi_k.write(&mut bytes);
        bytes
    }
    pub fn decode(pp: &Parameters, mut input: &[u8]) -> Res<Self> {
        let out = Self {
            pk_k: read_g2(&mut input)?,
            k_k: read_g1(&mut input)?,
            u_kj: (1..pp.n_slots)
                .map(|_| read_g1(&mut input))
                .collect::<Res<_>>()?,
            pi_k: Proof::read(&mut input)?,
        };
        eof(input)?;
        Ok(out)
    }
    fn hint(&self, owner: usize, slot: usize) -> G1 {
        assert_ne!(owner, slot);
        self.u_kj[slot - usize::from(owner < slot)]
    }
}

fn reg_challenge(pp: &Parameters, slot: usize, pk: G2, first: G2) -> F {
    Transcript::new("AW-MHAC-Holder-Proof")
        .add(&pp.pp_digest)
        .u32(slot as u32)
        .g2(pk)
        .g2(first)
        .scalar()
}

fn reg_valid(pp: &Parameters, slot: usize, pk: G2, proof: Proof) -> bool {
    let first = g2_exp(G2::generator(), proof.response) - g2_exp(pk, proof.challenge);
    proof.challenge == reg_challenge(pp, slot, pk, first)
}

pub fn hkeygen(pp: &Parameters, slot: usize, rng: &mut Rng) -> Res<(HolderKey, Registration)> {
    if slot >= pp.n_slots {
        return Err("slot out of range".into());
    }
    // HKeyGen, steps 1-3: holder key, binding value, and the values u_{k,j}.
    let alpha_k = F::random(&mut *rng);
    let pk_k = g2_exp(G2::generator(), alpha_k);
    let k_k = g1_exp(pp.h_i[0], alpha_k);
    let u_kj = pp
        .ell
        .iter()
        .enumerate()
        .filter(|(j, _)| *j != slot)
        .map(|(_, &ell)| g1_exp(ell, alpha_k))
        .collect();
    // HKeyGen, steps 4-5: proof of knowledge and registration message.
    let random = F::random(rng);
    let challenge = reg_challenge(pp, slot, pk_k, g2_exp(G2::generator(), random));
    Ok((
        HolderKey {
            slot,
            alpha_k,
            ell_alpha: None,
        },
        Registration {
            pk_k,
            k_k,
            u_kj,
            pi_k: Proof {
                challenge,
                response: random + challenge * alpha_k,
            },
        },
    ))
}

#[derive(Clone)]
pub struct Credential {
    pub a: G1,
    pub e: F,
    pub k: G1,
    pub vk: G2,
    pub u: Vec<(usize, G1)>,
}

impl Credential {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.a.to_compressed().to_vec();
        bytes.extend_from_slice(&self.e.to_bytes_be());
        bytes.extend_from_slice(&self.k.to_compressed());
        bytes.extend_from_slice(&self.vk.to_compressed());
        for (_, u_j) in &self.u {
            bytes.extend_from_slice(&u_j.to_compressed());
        }
        bytes
    }
    fn decode(mut input: &[u8], slots: &[usize]) -> Res<Self> {
        let out = Self {
            a: read_g1(&mut input)?,
            e: read_f(&mut input)?,
            k: read_g1(&mut input)?,
            vk: read_g2(&mut input)?,
            u: slots
                .iter()
                .map(|&j| Ok((j, read_g1(&mut input)?)))
                .collect::<Res<_>>()?,
        };
        eof(input)?;
        Ok(out)
    }
}

#[derive(Clone)]
pub struct Entry {
    pub slot: usize,
    pub pk_j: G2,
    pub u_j: G1,
    pub pi_j: Proof,
}
#[derive(Clone)]
pub struct Record {
    pub k: G1,
    pub vk: G2,
    pub entries: Vec<Entry>,
}

impl Record {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.k.to_compressed().to_vec();
        bytes.extend_from_slice(&self.vk.to_compressed());
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.pk_j.to_compressed());
            bytes.extend_from_slice(&entry.u_j.to_compressed());
            entry.pi_j.write(&mut bytes);
        }
        bytes
    }
    fn decode_selected(input: &[u8], slots: &[usize], selected: &[usize]) -> Res<Self> {
        const HEADER_BYTES: usize = 144;
        const ENTRY_BYTES: usize = 208;
        let expected = slots
            .len()
            .checked_mul(ENTRY_BYTES)
            .and_then(|size| size.checked_add(HEADER_BYTES))
            .ok_or("registration record length overflow")?;
        if input.len() != expected {
            return Err("invalid registration record length".into());
        }
        let mut header = &input[..HEADER_BYTES];
        let k = read_g1(&mut header)?;
        let vk = read_g2(&mut header)?;
        eof(header)?;
        let mut entries = Vec::with_capacity(selected.len());
        for &slot in selected {
            let position = slots
                .binary_search(&slot)
                .map_err(|_| "invalid registered subset")?;
            let offset = HEADER_BYTES + position * ENTRY_BYTES;
            let mut entry = &input[offset..offset + ENTRY_BYTES];
            entries.push(Entry {
                slot,
                pk_j: read_g2(&mut entry)?,
                u_j: read_g1(&mut entry)?,
                pi_j: Proof::read(&mut entry)?,
            });
            eof(entry)?;
        }
        // The registered slot list is sorted by Issue. Entries outside J have
        // fixed-width storage but are intentionally neither read nor decoded.
        Ok(Self { k, vk, entries })
    }
}

pub type Registry = HashMap<[u8; 48], (Vec<usize>, Vec<u8>)>;

pub fn issue(
    pp: &Parameters,
    isk: F,
    attrs: &[F],
    messages: &[(usize, Vec<u8>)],
    reg: &mut Registry,
    rng: &mut Rng,
) -> Res<Credential> {
    if attrs.len() != pp.n_attrs() || messages.is_empty() {
        return Err("invalid issue inputs".into());
    }
    let g2 = G2::generator();
    let mut registrations = Vec::with_capacity(messages.len());
    let mut slots = HashSet::new();
    let mut keys = HashSet::new();
    for (slot, data) in messages {
        if *slot >= pp.n_slots || !slots.insert(*slot) {
            return Err("invalid registered slots".into());
        }
        let row = Registration::decode(pp, data)?;
        if !keys.insert(row.pk_k.to_compressed()) || !reg_valid(pp, *slot, row.pk_k, row.pi_k) {
            return Err("invalid registration proof or repeated public key".into());
        }
        registrations.push((*slot, row));
    }
    registrations.sort_unstable_by_key(|(slot, _)| *slot);
    // Issue, steps 6–7: batch the binding value and hint equations.
    let mut left = G1::identity();
    let mut pairs = Vec::with_capacity(registrations.len() + 1);
    for (slot, row) in &registrations {
        let bases = std::iter::once(pp.h_i[0])
            .chain(
                pp.ell
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| j != slot)
                    .map(|(_, &ell)| ell),
            )
            .collect::<Vec<_>>();
        let points = std::iter::once(row.k_k)
            .chain(row.u_kj.iter().copied())
            .collect::<Vec<_>>();
        let coeff = (0..pp.n_slots)
            .map(|_| batch_coefficient(rng))
            .collect::<Vec<_>>();
        left += g1_msm(&points, &coeff);
        pairs.push((-g1_msm(&bases, &coeff), row.pk_k));
    }
    pairs.push((left, g2));
    if !pair_product(&pairs) {
        return Err("invalid registration pairing".into());
    }

    // Issue, steps 8-10: placeholder key, aggregate keys, and BBS signature.
    let alpha_star = F::random(&mut *rng);
    let vk = registrations
        .iter()
        .fold(g2_exp(g2, alpha_star), |a, (_, row)| a + row.pk_k);
    let k = registrations
        .iter()
        .fold(g1_exp(pp.h_i[0], alpha_star), |a, (_, row)| a + row.k_k);
    let c = bbs::base(pp.g0 + k, &pp.h_i[1..], attrs);
    let (a, e) = bbs::sign_base(c, isk, rng)?;
    // Issue, steps 11-13: the values u_j, registry record, and credential.
    let entries: Vec<_> = registrations
        .iter()
        .map(|(j, row)| {
            let u = registrations
                .iter()
                .filter(|(slot, _)| slot != j)
                .fold(g1_exp(pp.ell[*j], alpha_star), |acc, (slot, other)| {
                    acc + other.hint(*slot, *j)
                });
            Entry {
                slot: *j,
                pk_j: row.pk_k,
                u_j: u,
                pi_j: row.pi_k,
            }
        })
        .collect();
    let u = entries
        .iter()
        .map(|entry| (entry.slot, entry.u_j))
        .collect();
    let rec = Record { k, vk, entries };
    let key = k.to_compressed();
    if reg.contains_key(&key) {
        return Err("duplicate credential binding".into());
    }
    reg.insert(
        key,
        (rec.entries.iter().map(|x| x.slot).collect(), rec.encode()),
    );
    Ok(Credential { a, e, k, vk, u })
}

pub struct Host {
    pub cred: Credential,
    c: G1,
}

pub fn accept(
    pp: &Parameters,
    ipk: G2,
    attrs: &[F],
    registered_keys: &[(usize, [u8; 96])],
    wire: &[u8],
    rng: &mut Rng,
) -> Res<Host> {
    if attrs.len() != pp.n_attrs()
        || registered_keys.is_empty()
        || registered_keys.iter().any(|(j, _)| *j >= pp.n_slots)
        || registered_keys.windows(2).any(|w| w[0].0 >= w[1].0)
    {
        return Err("invalid host layout".into());
    }
    let slots = registered_keys.iter().map(|(j, _)| *j).collect::<Vec<_>>();
    // Accept, step 14: check the credential and cache its attribute product.
    let cred = Credential::decode(wire, &slots)?;
    if bool::from(cred.a.is_identity()) {
        return Err("identity credential".into());
    }
    let c = bbs::base(pp.g0 + cred.k, &pp.h_i[1..], attrs);
    let g2 = G2::generator();
    let d = batch_coefficient(rng);
    let f = batch_coefficient(rng);
    let mut bases = vec![-c, cred.k];
    let mut weights = vec![d, f];
    let mut pairs = vec![
        (g1_exp(cred.a, d), ipk + g2_exp(g2, cred.e)),
        (g1_exp(-pp.h_i[0], f), cred.vk),
    ];
    // Accept, steps 15-16: batch aggregate-key and completed-hint checks.
    for ((j, bytes), (_, u_j)) in registered_keys.iter().zip(&cred.u) {
        let pk = read_g2(&mut &bytes[..])?;
        let b = batch_coefficient(rng);
        bases.push(*u_j);
        weights.push(b);
        pairs.push((g1_exp(-pp.ell[*j], b), cred.vk - pk));
    }
    pairs.push((g1_msm(&bases, &weights), g2));
    if !pair_product(&pairs) {
        return Err("invalid credential or holder hint".into());
    }
    Ok(Host { cred, c })
}

#[derive(Clone)]
pub struct Context {
    pub verifier: [u8; 32],
    pub nonce: [u8; 32],
    pub disclosed: Vec<Option<F>>,
    pub threshold: u64,
}

impl Context {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.verifier.to_vec();
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&uint_bytes(self.threshold));
        bytes.extend_from_slice(&(self.disclosed.iter().flatten().count() as u32).to_be_bytes());
        for (index, value) in self.disclosed.iter().enumerate() {
            if let Some(a) = value {
                bytes.extend_from_slice(&((index + 1) as u32).to_be_bytes());
                bytes.extend_from_slice(&a.to_bytes_be());
            }
        }
        bytes
    }
    fn hidden(&self) -> impl Iterator<Item = usize> + '_ {
        self.disclosed
            .iter()
            .enumerate()
            .filter_map(|(i, x)| x.is_none().then_some(i))
    }
    fn disclosed_base(&self, pp: &Parameters) -> G1 {
        let (points, exps): (Vec<_>, Vec<_>) = self
            .disclosed
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.map(|x| (pp.h_i[i + 1], x)))
            .unzip();
        pp.g0 + g1_msm(&points, &exps)
    }
}

fn message_point(message: &[u8]) -> Res<G1> {
    let point = hash_to_g1(message, b"AW-MHAC-H1-BLS12381G1_XMD:SHA-256_SSWU_RO_");
    if bool::from(point.is_identity()) {
        return Err("identity context point".into());
    }
    Ok(point)
}

pub fn part_sign(sk_k: &HolderKey, message: &[u8], rng: &mut Rng) -> Res<Vec<u8>> {
    // PartSign, step 2: produce the holder signature on the verifier context.
    let h = message_point(message)?;
    let eta = F::random(rng);
    let r_j = g2_exp(G2::generator(), eta);
    let s_j = sk_k.ell_alpha.ok_or("missing holder precomputation")? + g1_exp(h, eta);
    let mut bytes = r_j.to_compressed().to_vec();
    bytes.extend_from_slice(&s_j.to_compressed());
    Ok(bytes)
}

pub fn check_partial(
    pp: &Parameters,
    pk: G2,
    slot: usize,
    message: &[u8],
    mut part: &[u8],
) -> Res<()> {
    let r_j = read_g2(&mut part)?;
    let s_j = read_g1(&mut part)?;
    eof(part)?;
    let ell = pp.ell.get(slot).ok_or("invalid partial slot")?;
    if !pair_product(&[
        (s_j, G2::generator()),
        (-message_point(message)?, r_j),
        (-*ell, pk),
    ]) {
        return Err("partial signature does not match the context".into());
    }
    Ok(())
}

/// Optional validation of received partial signatures, separate from Show.
/// Public keys are already decoded public inputs; each partial retains the
/// same canonical encoding and subgroup checks as `check_partial`.
pub fn check_partials(
    pp: &Parameters,
    public_keys: &[(usize, G2)],
    message: &[u8],
    parts: &[(usize, Vec<u8>)],
    rng: &mut Rng,
) -> Res<()> {
    if parts.is_empty() {
        return Err("no partial signatures".into());
    }
    let mut keys = HashMap::with_capacity(public_keys.len());
    for &(slot, pk) in public_keys {
        if slot >= pp.n_slots || keys.insert(slot, pk).is_some() {
            return Err("invalid or duplicate partial public-key slot".into());
        }
    }
    let mut seen = HashSet::with_capacity(parts.len());
    let mut signatures = Vec::with_capacity(parts.len());
    let mut randomizers = Vec::with_capacity(parts.len());
    let mut selected = Vec::with_capacity(parts.len());
    for (slot, wire) in parts {
        let ell = *pp.ell.get(*slot).ok_or("invalid partial slot")?;
        if !seen.insert(*slot) {
            return Err("repeated partial signing slot".into());
        }
        let pk = *keys.get(slot).ok_or("missing partial public key")?;
        let mut input = wire.as_slice();
        randomizers.push(read_g2(&mut input)?);
        signatures.push(read_g1(&mut input)?);
        eof(input)?;
        selected.push((ell, pk));
    }
    let h = message_point(message)?;
    // Independent nonzero 128-bit coefficients, sampled only after every
    // received input has been decoded. Combine the common G2 and H factors.
    let coefficients: Vec<_> = (0..parts.len()).map(|_| batch_coefficient(rng)).collect();
    let sum_s = g1_msm(&signatures, &coefficients);
    let sum_r = g2_msm(&randomizers, &coefficients);
    let mut pairs = Vec::with_capacity(parts.len() + 2);
    pairs.push((sum_s, G2::generator()));
    pairs.push((-h, sum_r));
    for ((ell, pk), coefficient) in selected.into_iter().zip(coefficients) {
        pairs.push((g1_exp(-ell, coefficient), pk));
    }
    if !pair_product(&pairs) {
        return Err("partial signature does not match the context".into());
    }
    Ok(())
}

#[derive(Clone)]
pub struct Presentation {
    pub w: u64,
    pub a_bar: G1,
    pub b_bar: G1,
    pub k_bar: G1,
    pub vk_bar: G2,
    pub v: G1,
    pub s_bar: G1,
    pub r_bar: G2,
    pub c_f: G1,
    pub c_q: G1,
    pub u: G1,
    pub e1: G1,
    pub e2: G1,
    pub omega_0: G1,
    pub omega_1: G1,
    pub f_zeta: F,
    pub challenge: F,
    pub response: Vec<F>,
}

impl Presentation {
    fn tr_bytes(&self) -> Vec<u8> {
        let mut bytes = uint_bytes(self.w).to_vec();
        for p in [self.a_bar, self.b_bar, self.k_bar] {
            bytes.extend_from_slice(&p.to_compressed());
        }
        bytes.extend_from_slice(&self.vk_bar.to_compressed());
        for p in [self.v, self.s_bar] {
            bytes.extend_from_slice(&p.to_compressed());
        }
        bytes.extend_from_slice(&self.r_bar.to_compressed());
        for p in [self.c_f, self.c_q, self.u, self.e1, self.e2] {
            bytes.extend_from_slice(&p.to_compressed());
        }
        bytes
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.tr_bytes();
        bytes.extend_from_slice(&self.omega_0.to_compressed());
        bytes.extend_from_slice(&self.omega_1.to_compressed());
        bytes.extend_from_slice(&self.f_zeta.to_bytes_be());
        bytes.extend_from_slice(&self.challenge.to_bytes_be());
        for x in &self.response {
            bytes.extend_from_slice(&x.to_bytes_be());
        }
        bytes
    }
    pub fn decode(mut input: &[u8], hidden: usize) -> Res<Self> {
        let out = Self {
            w: read_uint(&mut input)?,
            a_bar: read_g1(&mut input)?,
            b_bar: read_g1(&mut input)?,
            k_bar: read_g1(&mut input)?,
            vk_bar: read_g2(&mut input)?,
            v: read_g1(&mut input)?,
            s_bar: read_g1(&mut input)?,
            r_bar: read_g2(&mut input)?,
            c_f: read_g1(&mut input)?,
            c_q: read_g1(&mut input)?,
            u: read_g1(&mut input)?,
            e1: read_g1(&mut input)?,
            e2: read_g1(&mut input)?,
            omega_0: read_g1(&mut input)?,
            omega_1: read_g1(&mut input)?,
            f_zeta: read_f(&mut input)?,
            challenge: read_f(&mut input)?,
            response: (0..6 + hidden)
                .map(|_| read_f(&mut input))
                .collect::<Res<_>>()?,
        };
        eof(input)?;
        Ok(out)
    }
}

fn prefix(pp: &Parameters, ipk: G2, apk: [G1; 2], m: &[u8], label: &str) -> Transcript {
    let mut t = Transcript::new(label);
    t.add(&pp.pp_digest).g2(ipk).g1(apk[0]).g1(apk[1]).add(m);
    t
}

struct ShowTranscript<'a> {
    pp: &'a Parameters,
    ipk: G2,
    apk: [G1; 2],
    message: &'a [u8],
    tr: Vec<u8>,
}

impl ShowTranscript<'_> {
    fn start(&self, label: &str) -> Transcript {
        let mut t = prefix(self.pp, self.ipk, self.apk, self.message, label);
        t.add(&self.tr);
        t
    }
    fn zeta(&self, p: &Presentation) -> Res<F> {
        let zeta = self.start("AW-MHAC-Zeta").g1(p.omega_0).scalar();
        if vanishing(zeta, self.pp.n_slots) == F::ZERO {
            return Err("challenge belongs to evaluation domain".into());
        }
        Ok(zeta)
    }
    fn beta(&self, p: &Presentation, zeta: F) -> F {
        self.start("AW-MHAC-Beta")
            .g1(p.omega_0)
            .f(zeta)
            .f(p.f_zeta)
            .scalar()
    }
    fn gamma(&self, p: &Presentation, zeta: F, beta: F) -> F {
        self.start("AW-MHAC-Gamma")
            .g1(p.omega_0)
            .f(zeta)
            .f(p.f_zeta)
            .f(beta)
            .g1(p.omega_1)
            .scalar()
    }
    fn challenge(&self, p: &Presentation, gamma: F, first: [G1; 5]) -> F {
        let mut t = self.start("AW-MHAC-Show-Proof");
        t.g1(p.omega_0).f(p.f_zeta).g1(p.omega_1).f(gamma);
        for point in first {
            t.g1(point);
        }
        t.scalar()
    }
}

fn proof_commitments(
    pp: &Parameters,
    apk: [G1; 2],
    m_hash: G1,
    p: &Presentation,
    ctx: &Context,
    x: &[F],
) -> [G1; 5] {
    let [r1, r2, delta, s, mu1, mu2] = x[..6].try_into().unwrap();
    let mut bases = vec![p.b_bar, p.a_bar, pp.h_i[0]];
    bases.extend(ctx.hidden().map(|i| -pp.h_i[i + 1]));
    let mut exponents = vec![r1, r2, delta];
    exponents.extend_from_slice(&x[6..]);
    [
        g1_msm(&bases, &exponents),
        g1_msm(&[m_hash, -pp.z[0], -pp.z[1]], &[s, mu1, mu2]),
        g1_exp(G1::generator(), r1),
        g1_msm(&[m_hash, apk[0]], &[s, r1]),
        g1_msm(&[-pp.h_i[0], apk[1]], &[delta, r1]),
    ]
}

pub fn show(
    pp: &Parameters,
    ipk: G2,
    apk: [G1; 2],
    host: &Host,
    attrs: &[F],
    ctx: &Context,
    parts: &[(usize, Vec<u8>)],
    rng: &mut Rng,
) -> Res<Presentation> {
    if ctx.disclosed.len() != pp.n_attrs() || attrs.len() != pp.n_attrs() || parts.is_empty() {
        return Err("invalid show inputs".into());
    }
    // Show, step 4: W and P also determine the evaluation vector on H.
    let mut f_on_h = vec![F::ZERO; pp.n_slots];
    let mut w = 0_u64;
    let mut p = G1::identity();
    let mut r_sum = G2::identity();
    let mut s_sum = G1::identity();
    for (slot, wire) in parts {
        let (_, u_j) = host
            .cred
            .u
            .iter()
            .find(|(j, _)| j == slot)
            .ok_or("unregistered signing slot")?;
        let node = &mut f_on_h[*slot];
        if *node != F::ZERO {
            return Err("repeated signing slot".into());
        }
        let w_j = u64::from(pp.weights[*slot]);
        *node = F::from(w_j * pp.n_slots as u64);
        w += w_j;
        p += pp.ell[*slot];
        let mut input = &wire[..];
        r_sum += read_g2(&mut input)?;
        s_sum += read_g1(&mut input)? + u_j;
        eof(input)?;
    }
    let message = ctx.encode();
    let h = message_point(&message)?;
    // Show, steps 3-4: sample and derive the blinding scalars.
    let r = rand_nonzero(rng);
    let r1 = Option::<F>::from(r.invert()).unwrap();
    let r2 = host.cred.e * r1;
    let delta = F::random(&mut *rng);
    let s = F::random(&mut *rng);
    let mu1 = F::random(&mut *rng);
    let mu2 = F::random(&mut *rng);
    // Show, steps 5-6: interpolate f and form the quotient q.
    let mut f = interpolate(f_on_h);
    f.resize(pp.n_slots + 3, F::ZERO);
    f[1] -= mu1;
    f[2] -= mu2;
    f[pp.n_slots + 1] += mu1;
    f[pp.n_slots + 2] += mu2;
    let mut difference = f.clone();
    for (f_i, w_i) in difference.iter_mut().zip(&pp.w) {
        *f_i -= w_i;
    }
    let q = divide_vanishing(polynomial_mul(&f, &difference), pp.n_slots)?;
    // Show, step 7: randomize the BBS credential.
    let a_bar = g1_exp(host.cred.a, r);
    let b_bar = g1_msm(&[host.c, a_bar], &[r, -host.cred.e]);
    // Show, step 8: K_bar, vk_bar, and V.
    let k_bar = host.cred.k + g1_exp(pp.h_i[0], delta);
    let vk_bar = host.cred.vk + g2_exp(G2::generator(), delta);
    let h_s = g1_exp(h, s);
    let v = p + h_s;
    // Show, step 9: S_bar and R_bar.
    let s_bar = s_sum + g1_exp(v, delta);
    let r_bar = r_sum + g2_exp(host.cred.vk, -s);
    // Show, step 10: auditor ciphertexts.
    let u = g1_exp(G1::generator(), r1);
    let e1 = h_s + g1_exp(apk[0], r1);
    let e2 = host.cred.k + g1_exp(apk[1], r1);
    // Show, step 11: C_f, C_q, and Omega_0.
    let c_f = p + g1_msm(&pp.z, &[mu1, mu2]);
    let c_q = kzg::commit(&pp.srs, &q);
    let omega_0 = kzg::open_at_value(&pp.srs, &f, F::ZERO, F::from(w))?;
    let mut presentation = Presentation {
        w,
        a_bar,
        b_bar,
        k_bar,
        vk_bar,
        v,
        s_bar,
        r_bar,
        c_f,
        c_q,
        u,
        e1,
        e2,
        omega_0,
        omega_1: G1::identity(),
        f_zeta: F::ZERO,
        challenge: F::ZERO,
        response: Vec::new(),
    };
    // Show, steps 12-16: public transcript, challenges, and Omega_1.
    let transcript = ShowTranscript {
        pp,
        ipk,
        apk,
        message: &message,
        tr: presentation.tr_bytes(),
    };
    let zeta = transcript.zeta(&presentation)?;
    presentation.f_zeta = eval(&f, zeta);
    let v_q = eval(&q, zeta);
    let beta = transcript.beta(&presentation, zeta);
    let mut combined: Vec<F> = q.into_iter().map(|q_i| q_i * beta).collect();
    for (q_i, f_i) in combined.iter_mut().zip(f) {
        *q_i += f_i;
    }
    presentation.omega_1 =
        kzg::open_at_value(&pp.srs, &combined, zeta, presentation.f_zeta + beta * v_q)?;
    let gamma = transcript.gamma(&presentation, zeta, beta);
    // Show, steps 17-18: shared-witness proof and presentation.
    let mut witness = vec![r1, r2, delta, s, mu1, mu2];
    witness.extend(ctx.hidden().map(|i| attrs[i]));
    let mask = pok::masks(witness.len(), rng);
    let first = proof_commitments(pp, apk, h, &presentation, ctx, &mask);
    presentation.challenge = transcript.challenge(&presentation, gamma, first);
    presentation.response = pok::responses(&mask, &witness, presentation.challenge);
    Ok(presentation)
}

// Verify, step 19: barycentric evaluation of w and the inverse of Z(zeta).
fn weight_at(pp: &Parameters, zeta: F, z: F) -> Res<(F, F)> {
    let mut omega_j = F::ONE;
    let mut denominators = Vec::with_capacity(pp.n_slots + 1);
    for _ in 0..pp.n_slots {
        denominators.push(zeta - omega_j);
        omega_j *= pp.omega;
    }
    denominators.push(z);
    batch_invert(&mut denominators)?;
    let z_inv = denominators.pop().expect("Z(zeta) denominator");
    let mut w_zeta = F::ZERO;
    omega_j = F::ONE;
    for (&w, inverse) in pp.weights.iter().zip(denominators) {
        w_zeta += F::from(u64::from(w)) * omega_j * inverse;
        omega_j *= pp.omega;
    }
    Ok((w_zeta * z, z_inv))
}

pub fn verify(
    pp: &Parameters,
    ipk: G2,
    apk: [G1; 2],
    ctx: &Context,
    wire: &[u8],
    merged: bool,
    rng: &mut Rng,
) -> Res<Presentation> {
    if ctx.disclosed.len() != pp.n_attrs() {
        return Err("invalid context attribute count".into());
    }
    // Verify, steps 19-21: decode and check the public values and proof.
    let p = Presentation::decode(wire, ctx.hidden().count())?;
    if bool::from(p.a_bar.is_identity() | p.u.is_identity()) {
        return Err("identity A-bar or U".into());
    }
    if ctx.threshold == 0
        || p.w < ctx.threshold
        || p.w > pp.weights.iter().map(|&w| u64::from(w)).sum()
    {
        return Err("threshold or total weight out of range".into());
    }
    let message = ctx.encode();
    let h = message_point(&message)?;
    let tr = ShowTranscript {
        pp,
        ipk,
        apk,
        message: &message,
        tr: p.tr_bytes(),
    };
    let zeta = tr.zeta(&p)?;
    let beta = tr.beta(&p, zeta);
    let gamma = tr.gamma(&p, zeta, beta);
    let mut first = proof_commitments(pp, apk, h, &p, ctx, &p.response);
    let public = [
        ctx.disclosed_base(pp) + p.k_bar,
        p.v - p.c_f,
        p.u,
        p.e1,
        p.e2 - p.k_bar,
    ];
    for (r, y) in first.iter_mut().zip(public) {
        *r -= g1_exp(y, p.challenge);
    }
    if p.challenge != tr.challenge(&p, gamma, first) {
        return Err("invalid presentation proof".into());
    }
    let z = vanishing(zeta, pp.n_slots);
    let (w_zeta, z_inv) = weight_at(pp, zeta, z)?;
    let v_q = (p.f_zeta.square() - w_zeta * p.f_zeta) * z_inv;
    let lhs = p.omega_1 + g1_exp(p.omega_0, gamma);
    let rhs = g1_msm(
        &[p.omega_1, p.c_f, p.c_q, G1::generator()],
        &[
            zeta,
            F::ONE + gamma,
            beta,
            -p.f_zeta - beta * v_q - gamma * F::from(p.w),
        ],
    );
    let g2 = G2::generator();
    // Verify, steps 22-25: four pairing equations, with optional batching.
    let valid = if merged {
        let b1 = batch_coefficient(rng);
        let b2 = batch_coefficient(rng);
        let b3 = batch_coefficient(rng);
        let b4 = batch_coefficient(rng);
        pair_product(&[
            (g1_exp(p.a_bar, b1), ipk),
            (
                g1_msm(&[-p.b_bar, p.k_bar, p.s_bar, -rhs], &[b1, b2, b3, b4]),
                g2,
            ),
            (g1_msm(&[-pp.h_i[0], -p.v], &[b2, b3]), p.vk_bar),
            (g1_exp(-h, b3), p.r_bar),
            (g1_exp(lhs, b4), pp.tau_g2),
        ])
    } else {
        let eq1 = pair_product(&[(p.a_bar, ipk), (-p.b_bar, g2)]);
        let eq2 = pair_product(&[(p.k_bar, g2), (-pp.h_i[0], p.vk_bar)]);
        let eq3 = pair_product(&[(p.s_bar, g2), (-h, p.r_bar), (-p.v, p.vk_bar)]);
        let eq4 = pair_product(&[(lhs, pp.tau_g2), (-rhs, g2)]);
        eq1 && eq2 && eq3 && eq4
    };
    if !valid {
        return Err("invalid presentation pairing".into());
    }
    Ok(p)
}

#[derive(Clone)]
pub struct TraceOutput {
    pub slots: Vec<usize>,
    pub k: G1,
    pub m: G1,
    pub challenge: F,
    pub response: [F; 2],
}

impl TraceOutput {
    pub fn encode(&self, n_slots: usize) -> Res<Vec<u8>> {
        let mut bytes = vec![0; n_slots.div_ceil(8)];
        for &j in &self.slots {
            if j >= n_slots || bytes[j / 8] & (1 << (j % 8)) != 0 {
                return Err("invalid trace bitmap".into());
            }
            bytes[j / 8] |= 1 << (j % 8);
        }
        bytes.extend_from_slice(&self.k.to_compressed());
        bytes.extend_from_slice(&self.m.to_compressed());
        bytes.extend_from_slice(&self.challenge.to_bytes_be());
        for x in self.response {
            bytes.extend_from_slice(&x.to_bytes_be());
        }
        Ok(bytes)
    }
    pub fn decode(mut input: &[u8], n_slots: usize) -> Res<Self> {
        let count = n_slots.div_ceil(8);
        if input.len() < count {
            return Err("truncated trace bitmap".into());
        }
        let (bitmap, tail) = input.split_at(count);
        if (n_slots..8 * count).any(|j| bitmap[j / 8] & (1 << (j % 8)) != 0) {
            return Err("noncanonical trace bitmap".into());
        }
        let slots = (0..n_slots)
            .filter(|&j| bitmap[j / 8] & (1 << (j % 8)) != 0)
            .collect();
        input = tail;
        let result = Self {
            slots,
            k: read_g1(&mut input)?,
            m: read_g1(&mut input)?,
            challenge: read_f(&mut input)?,
            response: [read_f(&mut input)?, read_f(&mut input)?],
        };
        eof(input)?;
        Ok(result)
    }
}

fn audit_challenge(
    pp: &Parameters,
    ipk: G2,
    apk: [G1; 2],
    ctx: &Context,
    wire: &[u8],
    m: G1,
    k: G1,
    first: [G1; 4],
) -> F {
    let mut t = prefix(pp, ipk, apk, &ctx.encode(), "AW-MHAC-Audit-Proof");
    t.add(wire).g1(m).g1(k);
    for p in first {
        t.g1(p);
    }
    t.scalar()
}

fn subset_walk<T>(
    points: &[(G1, u64)],
    p_j: G1,
    weight: u64,
    mask: u32,
    visit: &mut impl FnMut(G1, u64, u32) -> Res<Option<T>>,
) -> Res<Option<T>> {
    let Some(((point, w), rest)) = points.split_last() else {
        return visit(p_j, weight, mask);
    };
    if let Some(hit) = subset_walk(rest, p_j, weight, mask, visit)? {
        return Ok(Some(hit));
    }
    subset_walk(
        rest,
        p_j + point,
        weight + w,
        mask | (1 << rest.len()),
        visit,
    )
}

/// Maximum number of subset points converted in one Trace batch.
/// blst 0.3.17 uses a 1536-point internal G1 stride, so this size requires
/// exactly one Fp inversion for each batch containing nonidentity points.
pub const TRACE_BATCH_SIZE: usize = 1024;

type SubsetPoint = (G1, u64, u32);

fn compress_trace_batch(batch: &[SubsetPoint]) -> Vec<[u8; 48]> {
    let mut encoded = vec![[0_u8; 48]; batch.len()];
    let mut positions = Vec::with_capacity(batch.len());
    let mut pointers: Vec<*const blst::blst_p1> = Vec::with_capacity(batch.len());
    for (index, (point, _, _)) in batch.iter().enumerate() {
        if bool::from(point.is_identity()) {
            // Canonical compressed infinity, including the empty subset. Do
            // not include zero Z coordinates in the batch inversion inputs.
            encoded[index][0] = 0xc0;
        } else {
            positions.push(index);
            pointers.push(point.as_ref() as *const blst::blst_p1);
        }
    }
    if !pointers.is_empty() {
        let mut affine = vec![blst::blst_p1_affine::default(); pointers.len()];
        // SAFETY: the non-null pointers borrow live G1 values throughout this
        // call; output has exactly n initialized, properly aligned elements.
        // Use the actual blst batch routine, not group::Curve's pointwise
        // default batch_normalize implementation in the pinned blstrs 0.7.1.
        unsafe {
            blst::blst_p1s_to_affine(affine.as_mut_ptr(), pointers.as_ptr(), pointers.len());
        }
        for (index, point) in positions.into_iter().zip(&affine) {
            // SAFETY: both the 48-byte output and affine input are valid for
            // the complete call. This performs encoding, without inversion.
            unsafe {
                blst::blst_p1_affine_compress(encoded[index].as_mut_ptr(), point);
            }
        }
    }
    encoded
}

fn subset_walk_batched<T>(
    points: &[(G1, u64)],
    initial: G1,
    deadline: &impl Fn() -> Res<()>,
    visit: &mut impl FnMut(&[SubsetPoint], &[[u8; 48]]) -> Option<T>,
) -> Res<Option<T>> {
    let mut batch = Vec::with_capacity(TRACE_BATCH_SIZE);
    let mut flush = |batch: &mut Vec<SubsetPoint>| -> Res<Option<T>> {
        let encoded = compress_trace_batch(batch);
        let hit = visit(batch, &encoded);
        // A hit is accepted only after the batch's post-deadline check.
        deadline()?;
        batch.clear();
        Ok(hit)
    };
    let hit = subset_walk(points, initial, 0, 0, &mut |point, weight, mask| {
        if batch.is_empty() {
            // Check before generating each batch, including a final short one.
            deadline()?;
        }
        batch.push((point, weight, mask));
        if batch.len() == TRACE_BATCH_SIZE {
            flush(&mut batch)
        } else {
            Ok(None)
        }
    })?;
    if hit.is_some() || batch.is_empty() {
        Ok(hit)
    } else {
        flush(&mut batch)
    }
}

/// Actual progress, retained by `trace_with_progress` on both success and
/// timeout. `right_visited` counts processed masks, including overweight masks;
/// actual hash-table lookups are a separate, diagnostic-only counter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TraceProgress {
    pub left_visited: usize,
    pub right_visited: usize,
    #[cfg(feature = "op-count")]
    pub left_generated: usize,
    #[cfg(feature = "op-count")]
    pub right_generated: usize,
    /// Canonical encodings produced, including directly encoded infinity;
    /// only the nonidentity members are passed to blst_p1s_to_affine.
    #[cfg(feature = "op-count")]
    pub converted_points: usize,
    #[cfg(feature = "op-count")]
    pub right_lookups: usize,
}

pub struct TraceResult {
    pub theta: TraceOutput,
    pub table_entries: usize,
    #[cfg(feature = "op-count")]
    pub right_visited: usize,
    #[cfg(feature = "op-count")]
    pub left_generated: usize,
    #[cfg(feature = "op-count")]
    pub right_generated: usize,
    /// Canonical encodings produced, including directly encoded infinity;
    /// only the nonidentity members are passed to blst_p1s_to_affine.
    #[cfg(feature = "op-count")]
    pub converted_points: usize,
    #[cfg(feature = "op-count")]
    pub right_lookups: usize,
}

pub fn trace(
    pp: &Parameters,
    ipk: G2,
    apk: [G1; 2],
    ask: [F; 2],
    ctx: &Context,
    wire: &[u8],
    reg: &Registry,
    timeout: Duration,
    rng: &mut Rng,
) -> Res<TraceResult> {
    trace_with_progress(
        pp,
        ipk,
        apk,
        ask,
        ctx,
        wire,
        reg,
        timeout,
        rng,
        &mut TraceProgress::default(),
    )
}

/// Same protocol result and errors as `trace`, with progress available even
/// when the unchanged error string is `"trace timed out"`.
pub fn trace_with_progress(
    pp: &Parameters,
    ipk: G2,
    apk: [G1; 2],
    ask: [F; 2],
    ctx: &Context,
    wire: &[u8],
    reg: &Registry,
    timeout: Duration,
    rng: &mut Rng,
    progress: &mut TraceProgress,
) -> Res<TraceResult> {
    *progress = TraceProgress::default();
    // Trace, steps 1-2: verify and decrypt the auditor ciphertexts.
    let start = Instant::now();
    let p = verify(pp, ipk, apk, ctx, wire, true, rng)?;
    let m = p.e1 - g1_exp(p.u, ask[0]);
    let k = p.e2 - g1_exp(p.u, ask[1]);
    let (slots, _) = reg
        .get(&k.to_compressed())
        .ok_or("missing registration record")?;
    if slots.len() > 32 {
        return Err("trace table supports up to 32 registered holders".into());
    }
    // Trace, step 3: recover J by matching products and weights. The existing
    // recursion still enumerates masks in increasing binary order and keeps
    // the first left mask for each (canonical 48-byte encoding, weight) key.
    let middle = slots.len() / 2;
    let points = slots
        .iter()
        .map(|&j| (pp.ell[j], u64::from(pp.weights[j])))
        .collect::<Vec<_>>();
    let mut table = HashMap::with_capacity(1 << middle);
    let deadline = || -> Res<()> {
        if start.elapsed() >= timeout {
            Err("trace timed out".into())
        } else {
            Ok(())
        }
    };
    subset_walk_batched(
        &points[..middle],
        G1::identity(),
        &deadline,
        &mut |batch, encoded| {
            #[cfg(feature = "op-count")]
            {
                progress.left_generated += batch.len();
                progress.converted_points += batch.len();
            }
            for ((_, weight, mask), code) in batch.iter().zip(encoded) {
                table.entry((*code, *weight)).or_insert(*mask);
            }
            progress.left_visited += batch.len();
            None::<()>
        },
    )?;
    let table_entries = table.len();
    let right: Vec<_> = points[middle..]
        .iter()
        .map(|&(point, w)| (-point, w))
        .collect();
    let combined = subset_walk_batched(&right, p.v - m, &deadline, &mut |batch, encoded| {
        #[cfg(feature = "op-count")]
        {
            progress.right_generated += batch.len();
            progress.converted_points += batch.len();
        }
        for (index, ((_, weight, mask), code)) in batch.iter().zip(encoded).enumerate() {
            if let Some(left) = p.w.checked_sub(*weight) {
                #[cfg(feature = "op-count")]
                {
                    progress.right_lookups += 1;
                }
                if let Some(first) = table.get(&(*code, left)) {
                    progress.right_visited += index + 1;
                    return Some(first | (mask << middle));
                }
            }
        }
        progress.right_visited += batch.len();
        None
    })?
    .ok_or("no participating subset")?;
    deadline()?;
    let slots = slots
        .iter()
        .enumerate()
        .filter_map(|(i, &j)| (combined & (1 << i) != 0).then_some(j))
        .collect();
    // Trace, steps 4-5: prove correct decryption and return theta.
    let r = [F::random(&mut *rng), F::random(rng)];
    let g = G1::generator();
    let first = [
        g1_exp(g, r[0]),
        g1_exp(p.u, r[0]),
        g1_exp(g, r[1]),
        g1_exp(p.u, r[1]),
    ];
    let challenge = audit_challenge(pp, ipk, apk, ctx, wire, m, k, first);
    let theta = TraceOutput {
        slots,
        k,
        m,
        challenge,
        response: [r[0] + challenge * ask[0], r[1] + challenge * ask[1]],
    };
    Ok(TraceResult {
        theta,
        table_entries,
        #[cfg(feature = "op-count")]
        right_visited: progress.right_visited,
        #[cfg(feature = "op-count")]
        left_generated: progress.left_generated,
        #[cfg(feature = "op-count")]
        right_generated: progress.right_generated,
        #[cfg(feature = "op-count")]
        converted_points: progress.converted_points,
        #[cfg(feature = "op-count")]
        right_lookups: progress.right_lookups,
    })
}

pub fn judge(
    pp: &Parameters,
    ipk: G2,
    apk: [G1; 2],
    ctx: &Context,
    wire: &[u8],
    theta_wire: &[u8],
    reg: &Registry,
    rng: &mut Rng,
) -> Res<()> {
    // Judge, step 6: verify the presentation and decryption proof.
    let theta = TraceOutput::decode(theta_wire, pp.n_slots)?;
    let p = verify(pp, ipk, apk, ctx, wire, true, rng)?;
    let g = G1::generator();
    let c = theta.challenge;
    let [s1, s2] = theta.response;
    let first = [
        g1_msm(&[g, -apk[0]], &[s1, c]),
        g1_msm(&[p.u, theta.m - p.e1], &[s1, c]),
        g1_msm(&[g, -apk[1]], &[s2, c]),
        g1_msm(&[p.u, theta.k - p.e2], &[s2, c]),
    ];
    if c != audit_challenge(pp, ipk, apk, ctx, wire, theta.m, theta.k, first) {
        return Err("invalid audit proof".into());
    }
    // Judge, steps 7-8: check J against the registry, P, and W.
    let (slots, record) = reg
        .get(&theta.k.to_compressed())
        .ok_or("missing registration record")?;
    let rec = Record::decode_selected(record, slots, &theta.slots)?;
    if rec.k != theta.k {
        return Err("invalid registered subset".into());
    }
    let w: u64 = theta.slots.iter().map(|&j| u64::from(pp.weights[j])).sum();
    let p_j = theta
        .slots
        .iter()
        .fold(G1::identity(), |a, &j| a + pp.ell[j]);
    if w != p.w || p_j != p.v - theta.m {
        return Err("invalid audited participation".into());
    }
    // Judge, steps 9-11: registered public keys, proofs, and the values u_j.
    let r = batch_coefficient(rng);
    let mut bases = vec![rec.k];
    let mut coeff = vec![r];
    let mut pairs = vec![(g1_exp(-pp.h_i[0], r), rec.vk)];
    for entry in &rec.entries {
        let j = entry.slot;
        if !reg_valid(pp, j, entry.pk_j, entry.pi_j) {
            return Err("invalid registered holder proof".into());
        }
        let r = batch_coefficient(rng);
        bases.push(entry.u_j);
        coeff.push(r);
        pairs.push((g1_exp(-pp.ell[j], r), rec.vk - entry.pk_j));
    }
    pairs.push((g1_msm(&bases, &coeff), G2::generator()));
    if !pair_product(&pairs) {
        return Err("invalid registration binding".into());
    }
    Ok(())
}

pub fn public_issuer_key(mut bytes: &[u8]) -> Res<G2> {
    let point = read_g2(&mut bytes)?;
    eof(bytes)?;
    Ok(point)
}

pub fn public_auditor_key(mut bytes: &[u8]) -> Res<[G1; 2]> {
    let key = [read_g1(&mut bytes)?, read_g1(&mut bytes)?];
    eof(bytes)?;
    Ok(key)
}

#[cfg(test)]
mod trace_batch_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn compression_matches_pointwise_for_infinity_negatives_and_batch_edges() {
        assert!(compress_trace_batch(&[]).is_empty());
        let g = G1::generator();
        let mut current = g;
        let mut points = Vec::new();
        for index in 0..(2 * TRACE_BATCH_SIZE + 17) {
            let point = if [0, TRACE_BATCH_SIZE - 1, TRACE_BATCH_SIZE].contains(&index) {
                G1::identity()
            } else if index % 3 == 0 {
                -current
            } else {
                current
            };
            points.push((point, index as u64, index as u32));
            current += g;
        }
        // Explicit opposites, cancellation to infinity, and all-infinity batch.
        points[5].0 = g;
        points[6].0 = -g;
        points[7].0 = g + (-g);
        for batch in points.chunks(TRACE_BATCH_SIZE) {
            let encoded = compress_trace_batch(batch);
            for ((point, _, _), code) in batch.iter().zip(encoded) {
                assert_eq!(code, point.to_compressed());
            }
        }
        let identities = [(G1::identity(), 0, 0); 4];
        assert!(compress_trace_batch(&identities)
            .iter()
            .all(|code| *code == G1::identity().to_compressed()));
    }

    #[test]
    fn batch_walk_preserves_order_first_hit_and_final_partial_batch() {
        let g = G1::generator();
        let points: Vec<_> = (0..11)
            .map(|index| (g * F::from((index + 1) as u64), (index + 1) as u64))
            .collect();
        let mut reference = Vec::new();
        subset_walk(&points, g, 0, 0, &mut |point, weight, mask| {
            reference.push((point.to_compressed(), weight, mask));
            Ok(None::<()>)
        })
        .unwrap();
        for target in [0, 1023, 1024, 2047, 2048] {
            let mut seen = Vec::new();
            let mut generated = 0;
            let found = subset_walk_batched(&points, g, &|| Ok(()), &mut |batch, encoded| {
                generated += batch.len();
                for ((_, weight, mask), code) in batch.iter().zip(encoded) {
                    seen.push((*code, *weight, *mask));
                    if *mask == target {
                        return Some(*mask);
                    }
                }
                None
            })
            .unwrap();
            let processed = ((target as usize) + 1).min(reference.len());
            assert_eq!(seen, reference[..processed]);
            assert_eq!(found, (target < 2048).then_some(target));
            assert_eq!(
                generated,
                processed.div_ceil(TRACE_BATCH_SIZE) * TRACE_BATCH_SIZE
            );
            assert!(generated - processed < TRACE_BATCH_SIZE);
        }
        // A five-bit domain gives one final short batch instead of 1024 points.
        let mut lengths = Vec::new();
        subset_walk_batched(&points[..5], G1::identity(), &|| Ok(()), &mut |batch, _| {
            lengths.push(batch.len());
            None::<()>
        })
        .unwrap();
        assert_eq!(lengths, [32]);
    }

    #[test]
    fn deadline_is_checked_before_and_after_batches_and_keeps_completed_progress() {
        let points = vec![(G1::generator(), 1); 11];
        let checks = Cell::new(0);
        let deadline = || {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                Err("trace timed out".into())
            } else {
                Ok(())
            }
        };
        let mut visited = 0;
        let error = subset_walk_batched(&points, G1::identity(), &deadline, &mut |batch, _| {
            visited += batch.len();
            None::<()>
        })
        .unwrap_err();
        assert_eq!(error, "trace timed out");
        assert_eq!(checks.get(), 2);
        assert_eq!(visited, TRACE_BATCH_SIZE);
        let mut visited_before = false;
        let result = subset_walk_batched(
            &points,
            G1::identity(),
            &|| Err("trace timed out".into()),
            &mut |_, _| {
                visited_before = true;
                None::<()>
            },
        );
        assert_eq!(result.unwrap_err(), "trace timed out");
        assert!(!visited_before);
    }
}
