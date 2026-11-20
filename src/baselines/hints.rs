//! hinTS: Threshold Signatures with Silent Setup, IEEE S&P 2024, Sections 5–6.
//! Group allocation follows the authors' public implementation.

use ff::Field;
use group::Group;

use crate::{
    common::{
        eof, rand_nonzero, read_f, read_g1, read_g2, read_uint, uint_bytes, Res, Rng, Transcript,
        F, G1, G2,
    },
    hash::hash_to_g2,
    pairing::{batch_coefficient, g1_exp, g1_msm, g2_exp, g2_msm, pair_product},
    poly::{batch_invert, eval, interpolate, opening_quotient, polynomial_mul, root},
};

const SIGN_DST: &[u8] = b"HINTS_BLS12381G2_XMD:SHA-256_SSWU_RO_";

#[derive(Clone)]
pub struct Parameters {
    pub u: usize,
    pub d: usize,
    pub weights: Vec<u64>,
    pub srs_g1: Vec<G1>,
    pub srs_g2: Vec<G2>,
    pub lagrange: Vec<Vec<F>>,
    hint_bases_g1: Vec<Vec<G1>>,
    hint_bases_g2: Vec<Vec<G2>>,
    sk_bases_g2: Vec<G2>,
    pub z_c: G2,
    pub first_c: G1,
    pub dummy_c: G1,
}

pub struct SecretKey {
    pub sk_i: F,
    pub pk_i: G1,
}

#[derive(Clone)]
pub struct Hint {
    pub sk_c: G2,
    pub q_z: Vec<G1>,
    pub q_x: G1,
    pub u: G1,
}

impl Hint {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96 + 48 * (self.q_z.len() + 2));
        bytes.extend_from_slice(&self.sk_c.to_compressed());
        for point in self.q_z.iter().chain([&self.q_x, &self.u]) {
            bytes.extend_from_slice(&point.to_compressed());
        }
        bytes
    }

    pub fn decode(mut bytes: &[u8], d: usize) -> Res<Self> {
        let sk_c = read_g2(&mut bytes)?;
        let q_z = (0..d).map(|_| read_g1(&mut bytes)).collect::<Res<_>>()?;
        let q_x = read_g1(&mut bytes)?;
        let u = read_g1(&mut bytes)?;
        eof(bytes)?;
        Ok(Self { sk_c, q_z, q_x, u })
    }
}

/// The optimized signature fields and group allocation of Section 6.1.
#[derive(Clone)]
pub struct Signature {
    pub a_pk: G1,
    pub sigma: G2,
    pub weight: u64,
    pub b_c: G1,
    pub q_x_c: G1,
    pub q_z_c: G1,
    pub u: G1,
    pub par_sum_c: G1,
    pub q_c: G1,
    pub b_r: F,
    pub par_sum_r: F,
    pub par_sum_r_omega: F,
    pub w_r: F,
    pub q_r: F,
    pub open_r: G1,
    pub open_r_omega: G1,
}

impl Signature {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(720);
        bytes.extend_from_slice(&self.a_pk.to_compressed());
        bytes.extend_from_slice(&self.sigma.to_compressed());
        bytes.extend_from_slice(&uint_bytes(self.weight));
        for point in [
            self.b_c,
            self.q_x_c,
            self.q_z_c,
            self.u,
            self.par_sum_c,
            self.q_c,
        ] {
            bytes.extend_from_slice(&point.to_compressed());
        }
        for scalar in [
            self.b_r,
            self.par_sum_r,
            self.par_sum_r_omega,
            self.w_r,
            self.q_r,
        ] {
            bytes.extend_from_slice(&scalar.to_bytes_be());
        }
        bytes.extend_from_slice(&self.open_r.to_compressed());
        bytes.extend_from_slice(&self.open_r_omega.to_compressed());
        bytes
    }

    pub fn decode(mut bytes: &[u8]) -> Res<Self> {
        let signature = Self {
            a_pk: read_g1(&mut bytes)?,
            sigma: read_g2(&mut bytes)?,
            weight: read_uint(&mut bytes)?,
            b_c: read_g1(&mut bytes)?,
            q_x_c: read_g1(&mut bytes)?,
            q_z_c: read_g1(&mut bytes)?,
            u: read_g1(&mut bytes)?,
            par_sum_c: read_g1(&mut bytes)?,
            q_c: read_g1(&mut bytes)?,
            b_r: read_f(&mut bytes)?,
            par_sum_r: read_f(&mut bytes)?,
            par_sum_r_omega: read_f(&mut bytes)?,
            w_r: read_f(&mut bytes)?,
            q_r: read_f(&mut bytes)?,
            open_r: read_g1(&mut bytes)?,
            open_r_omega: read_g1(&mut bytes)?,
        };
        eof(bytes)?;
        Ok(signature)
    }
}

#[derive(Clone)]
pub struct AggregationKey {
    pub pks: Vec<G1>,
    pub weights: Vec<u64>,
    pub excluded: Vec<usize>,
    pub q_z: Vec<G1>,
    pub q_x: Vec<G1>,
    pub u: Vec<G1>,
}

#[derive(Clone)]
pub struct VerificationKey {
    pub d: usize,
    pub sk_c: G2,
    pub w_c: G1,
    pub z_c: G2,
    pub first_c: G1,
    pub dummy_c: G1,
    pub tau_g2: G2,
    pub omega: F,
    pub inverse_d: F,
    pub digest: [u8; 32],
}

impl VerificationKey {
    fn new(pp: &Parameters, sk_c: G2, w_c: G1) -> Self {
        let omega = root(pp.d);
        let inverse_d = Option::<F>::from(F::from(pp.d as u64).invert()).unwrap();
        // Preprocess: bind the complete public verification key once.
        let mut transcript = Transcript::new("hinTS/verification-key");
        transcript
            .u32(pp.d as u32)
            .f(omega)
            .f(inverse_d)
            .g2(sk_c)
            .g1(w_c)
            .g2(pp.z_c)
            .g1(pp.first_c)
            .g1(pp.dummy_c)
            .g2(pp.srs_g2[1]);
        Self {
            d: pp.d,
            sk_c,
            w_c,
            z_c: pp.z_c,
            first_c: pp.first_c,
            dummy_c: pp.dummy_c,
            tau_g2: pp.srs_g2[1],
            omega,
            inverse_d,
            digest: transcript.digest(),
        }
    }
}

impl Parameters {
    /// HintGen outputs d quotient contributions, Qx, U, and one SK contribution.
    pub fn hint_check_equalities_per_signer(&self) -> usize {
        self.d + 3
    }
}

fn divide_z(mut numerator: Vec<F>, d: usize) -> Res<Vec<F>> {
    if numerator.len() <= d {
        return Err("hinTS polynomial numerator is shorter than the vanishing polynomial".into());
    }
    let mut quotient = vec![F::ZERO; numerator.len() - d];
    for i in (d..numerator.len()).rev() {
        let high = numerator[i];
        quotient[i - d] = high;
        numerator[i - d] += high;
    }
    if numerator[..d].iter().any(|&v| v != F::ZERO) {
        return Err("hinTS polynomial has nonzero remainder modulo Z".into());
    }
    Ok(quotient)
}

/// Setup creates public polynomial bases for the selected universe.
/// The local test-only KZG trapdoor is dropped on return.
pub fn setup(weights: &[u64], rng: &mut Rng) -> Res<Parameters> {
    if weights.is_empty() || weights.iter().any(|&weight| weight == 0) {
        return Err("hinTS requires a nonempty universe with positive weights".into());
    }
    let u = weights.len();
    let d = (u + 1).next_power_of_two();
    let tau = loop {
        let tau = rand_nonzero(rng);
        if tau.pow_vartime([d as u64]) != F::ONE {
            break tau;
        }
    };
    let mut srs_g1 = Vec::with_capacity(d + 1);
    let mut srs_g2 = Vec::with_capacity(d + 1);
    let mut power = F::ONE;
    for _ in 0..=d {
        srs_g1.push(g1_exp(G1::generator(), power));
        srs_g2.push(g2_exp(G2::generator(), power));
        power *= tau;
    }
    let lagrange: Vec<_> = (0..d)
        .map(|i| {
            let mut values = vec![F::ZERO; d];
            values[(i + 1) % d] = F::ONE;
            interpolate(values)
        })
        .collect();
    let mut hint_bases_g1 = Vec::with_capacity(u);
    let mut hint_bases_g2 = Vec::with_capacity(u);
    let mut sk_bases_g2 = Vec::with_capacity(u);
    for i in 0..u {
        let mut polys = Vec::with_capacity(d + 2);
        for j in 0..d {
            let mut numerator = polynomial_mul(&lagrange[i], &lagrange[j]);
            if i == j {
                for (out, &coefficient) in numerator.iter_mut().zip(&lagrange[i]) {
                    *out -= coefficient;
                }
            }
            polys.push(divide_z(numerator, d)?);
        }
        let q_x = lagrange[i][1..].to_vec();
        let mut u_poly = lagrange[i].clone();
        u_poly[0] = F::ZERO;
        polys.push(q_x);
        polys.push(u_poly);
        hint_bases_g1.push(
            polys
                .iter()
                .map(|poly| g1_msm(&srs_g1[..poly.len()], poly))
                .collect(),
        );
        hint_bases_g2.push(
            polys
                .iter()
                .map(|poly| g2_msm(&srs_g2[..poly.len()], poly))
                .collect(),
        );
        sk_bases_g2.push(g2_msm(&srs_g2[..d], &lagrange[i]));
    }
    let z_c = srs_g2[d] - srs_g2[0];
    let first_c = g1_msm(&srs_g1[..d], &lagrange[0]);
    let dummy_c = g1_msm(&srs_g1[..d], &lagrange[d - 1]);
    Ok(Parameters {
        u,
        d,
        weights: weights.to_vec(),
        srs_g1,
        srs_g2,
        lagrange,
        hint_bases_g1,
        hint_bases_g2,
        sk_bases_g2,
        z_c,
        first_c,
        dummy_c,
    })
}

/// KGen, Section 5: one independent BLS key pair.
pub fn kgen(rng: &mut Rng) -> SecretKey {
    let sk_i = F::random(&mut *rng);
    SecretKey {
        sk_i,
        pk_i: g1_exp(G1::generator(), sk_i),
    }
}

/// HintGen, Section 5: publish SK, QZ, Qx, and shifted-Qx contributions.
pub fn hint_gen(pp: &Parameters, slot: usize, key: &SecretKey) -> Res<Hint> {
    if slot >= pp.u {
        return Err("hinTS hint slot is outside the signer universe".into());
    }
    let material: Vec<_> = pp.hint_bases_g1[slot]
        .iter()
        .map(|&base| g1_exp(base, key.sk_i))
        .collect();
    Ok(Hint {
        sk_c: g2_exp(pp.sk_bases_g2[slot], key.sk_i),
        q_z: material[..pp.d].to_vec(),
        q_x: material[pp.d],
        u: material[pp.d + 1],
    })
}

fn hint_valid(pp: &Parameters, slot: usize, pk: G1, hint: &Hint, rng: &mut Rng) -> bool {
    let points: Vec<_> = hint.q_z.iter().copied().chain([hint.q_x, hint.u]).collect();
    let coefficients: Vec<_> = (0..points.len()).map(|_| batch_coefficient(rng)).collect();
    let sk_coefficient = batch_coefficient(rng);
    let mut public_bases = pp.hint_bases_g2[slot].clone();
    public_bases.push(pp.sk_bases_g2[slot]);
    let mut public_coefficients = coefficients.clone();
    public_coefficients.push(sk_coefficient);
    pair_product(&[
        (g1_msm(&points, &coefficients), G2::generator()),
        (G1::generator(), g2_exp(hint.sk_c, sk_coefficient)),
        (-pk, g2_msm(&public_bases, &public_coefficients)),
    ])
}

fn hints_valid(pp: &Parameters, public_keys: &[G1], hints: &[Hint], rng: &mut Rng) -> bool {
    let mut points = Vec::with_capacity(pp.u * (pp.d + 2));
    let mut coefficients = Vec::with_capacity(points.capacity());
    let mut sk_coefficients = Vec::with_capacity(pp.u);
    let mut sk_points = Vec::with_capacity(pp.u);
    let mut terms = Vec::with_capacity(pp.u + 2);
    for (i, hint) in hints.iter().enumerate() {
        let local_coefficients: Vec<_> = (0..pp.d + 2).map(|_| batch_coefficient(rng)).collect();
        let sk_coefficient = batch_coefficient(rng);
        let mut bases = pp.hint_bases_g2[i].clone();
        bases.push(pp.sk_bases_g2[i]);
        let mut all_coefficients = local_coefficients.clone();
        all_coefficients.push(sk_coefficient);
        terms.push((-public_keys[i], g2_msm(&bases, &all_coefficients)));
        points.extend(hint.q_z.iter().copied().chain([hint.q_x, hint.u]));
        coefficients.extend(local_coefficients);
        sk_points.push(hint.sk_c);
        sk_coefficients.push(sk_coefficient);
    }
    terms.push((g1_msm(&points, &coefficients), G2::generator()));
    terms.push((G1::generator(), g2_msm(&sk_points, &sk_coefficients)));
    pair_product(&terms)
}

/// Preprocess follows Section 5, footnote 14. A failed batch is isolated per signer.
pub fn preprocess(
    pp: &Parameters,
    public_keys: &[Vec<u8>],
    hints: &[Vec<u8>],
    rng: &mut Rng,
) -> Res<(AggregationKey, VerificationKey)> {
    if public_keys.len() != pp.u || hints.len() != pp.u {
        return Err("hinTS preprocessing requires every universe member".into());
    }
    let mut decoded_pks = Vec::with_capacity(pp.u);
    let mut decoded_hints = Vec::with_capacity(pp.u);
    for i in 0..pp.u {
        let mut pk_wire = public_keys[i].as_slice();
        decoded_pks.push(read_g1(&mut pk_wire)?);
        eof(pk_wire)?;
        decoded_hints.push(Hint::decode(&hints[i], pp.d)?);
    }
    let batch_valid = hints_valid(pp, &decoded_pks, &decoded_hints, rng);
    let mut pks = Vec::with_capacity(pp.u);
    let mut weights = pp.weights.clone();
    let mut excluded = Vec::new();
    let mut q_z = vec![G1::identity(); pp.d];
    let mut q_x = Vec::with_capacity(pp.u);
    let mut u = Vec::with_capacity(pp.u);
    let mut sk_c = G2::identity();
    for i in 0..pp.u {
        let pk = decoded_pks[i];
        let hint = &decoded_hints[i];
        if batch_valid || hint_valid(pp, i, pk, hint, rng) {
            pks.push(pk);
            for (out, contribution) in q_z.iter_mut().zip(&hint.q_z) {
                *out += contribution;
            }
            q_x.push(hint.q_x);
            u.push(hint.u);
            sk_c += hint.sk_c;
        } else {
            excluded.push(i);
            pks.push(G1::identity());
            weights[i] = 0;
            q_x.push(G1::identity());
            u.push(G1::identity());
        }
    }
    let mut values = vec![F::ZERO; pp.d];
    for (i, &weight) in weights.iter().enumerate() {
        values[(i + 1) % pp.d] = F::from(weight);
    }
    let w_c = g1_msm(&pp.srs_g1[..pp.d], &interpolate(values));
    Ok((
        AggregationKey {
            pks,
            weights,
            excluded,
            q_z,
            q_x,
            u,
        },
        VerificationKey::new(pp, sk_c, w_c),
    ))
}

pub fn hash_message(message: &[u8]) -> G2 {
    hash_to_g2(message, SIGN_DST)
}

/// Sign, Section 5, with the role-local message hash shared by a signing aggregator.
pub fn sign_with_hash(key: &SecretKey, h: G2) -> Vec<u8> {
    g2_exp(h, key.sk_i).to_compressed().to_vec()
}

pub fn sign(key: &SecretKey, message: &[u8]) -> Vec<u8> {
    sign_with_hash(key, hash_message(message))
}

/// Checks all selected partial signatures with independent 128-bit coefficients.
pub fn partial_verify(
    ak: &AggregationKey,
    slots: &[usize],
    message: &[u8],
    signatures: &[Vec<u8>],
    rng: &mut Rng,
) -> Res<Vec<G2>> {
    partial_verify_with_hash(ak, slots, hash_message(message), signatures, rng)
}

fn partial_verify_with_hash(
    ak: &AggregationKey,
    slots: &[usize],
    h: G2,
    signatures: &[Vec<u8>],
    rng: &mut Rng,
) -> Res<Vec<G2>> {
    let decoded = decode_partials(ak, slots, signatures)?;
    let coefficients: Vec<_> = slots.iter().map(|_| batch_coefficient(rng)).collect();
    let pks: Vec<_> = slots.iter().map(|&slot| ak.pks[slot]).collect();
    if !pair_product(&[
        (g1_msm(&pks, &coefficients), h),
        (-G1::generator(), g2_msm(&decoded, &coefficients)),
    ]) {
        return Err("hinTS partial signature batch is invalid".into());
    }
    Ok(decoded)
}

// Section 5 SignAggr receives group elements. The main path retains canonical
// decoding and subgroup checks, without adding a partial-signature pairing.
fn decode_partials(ak: &AggregationKey, slots: &[usize], signatures: &[Vec<u8>]) -> Res<Vec<G2>> {
    if slots.is_empty()
        || slots.len() != signatures.len()
        || slots.windows(2).any(|slots| slots[0] >= slots[1])
        || slots
            .iter()
            .any(|&slot| slot >= ak.pks.len() || ak.weights[slot] == 0)
    {
        return Err("hinTS partial signature slot set is invalid".into());
    }
    signatures
        .iter()
        .map(|wire| {
            let mut bytes = wire.as_slice();
            let signature = read_g2(&mut bytes)?;
            eof(bytes)?;
            Ok(signature)
        })
        .collect::<Res<Vec<_>>>()
}

/// Independently checks the honest small-instance aggregation identity.
pub fn aggregation_identity(
    pp: &Parameters,
    ak: &AggregationKey,
    vk: &VerificationKey,
    slots: &[usize],
) -> Res<bool> {
    if slots.iter().any(|&slot| slot >= pp.u) {
        return Err("hinTS aggregation identity slot is out of range".into());
    }
    let inverse_d = Option::<F>::from(F::from(pp.d as u64).invert()).unwrap();
    let a_pk = g1_exp(
        slots
            .iter()
            .fold(G1::identity(), |sum, &slot| sum + ak.pks[slot]),
        inverse_d,
    );
    let q_x = slots
        .iter()
        .fold(G1::identity(), |sum, &slot| sum + ak.q_x[slot]);
    let u = slots
        .iter()
        .fold(G1::identity(), |sum, &slot| sum + ak.u[slot]);
    let q_z = slots
        .iter()
        .chain(std::iter::once(&(pp.d - 1)))
        .fold(G1::identity(), |sum, &slot| sum + ak.q_z[slot]);
    let mut values = vec![F::ZERO; pp.d];
    for &slot in slots {
        values[(slot + 1) % pp.d] = F::ONE;
    }
    values[0] = F::ONE;
    let b = interpolate(values);
    let b_c = g1_msm(&pp.srs_g1[..pp.d], &b);
    Ok(pair_product(&[
        (b_c, vk.sk_c),
        (-q_z, vk.z_c),
        (-(a_pk + u), G2::generator()),
    ]) && pair_product(&[(q_x, vk.tau_g2), (-u, G2::generator())]))
}

struct PolynomialWitness {
    b: Vec<F>,
    par_sum: Vec<F>,
    w: Vec<F>,
    quotients: [Vec<F>; 4],
    weight: u64,
}

fn polynomial_witness(
    pp: &Parameters,
    ak: &AggregationKey,
    slots: &[usize],
) -> Res<PolynomialWitness> {
    if slots.is_empty()
        || slots.windows(2).any(|slots| slots[0] >= slots[1])
        || slots
            .iter()
            .any(|&slot| slot >= pp.u || ak.weights[slot] == 0)
    {
        return Err("hinTS signer set is invalid".into());
    }
    let weight = slots.iter().try_fold(0_u64, |sum, &slot| {
        sum.checked_add(ak.weights[slot])
            .ok_or("hinTS total weight overflows u64")
    })?;
    let mut b_values = vec![F::ZERO; pp.d];
    let mut w_values = vec![F::ZERO; pp.d];
    for (slot, &weight) in ak.weights.iter().enumerate() {
        w_values[(slot + 1) % pp.d] = F::from(weight);
    }
    for &slot in slots {
        b_values[(slot + 1) % pp.d] = F::ONE;
    }
    // SignAggr, Section 5, steps 5–6: the final virtual slot closes the prefix sum.
    b_values[0] = F::ONE;
    w_values[0] = -F::from(weight);
    let mut par_sum_values = vec![F::ZERO; pp.d];
    let mut sum = F::ZERO;
    for slot in 0..pp.d {
        let index = (slot + 1) % pp.d;
        par_sum_values[index] = sum;
        sum += w_values[index] * b_values[index];
    }
    if sum != F::ZERO {
        return Err("hinTS prefix sum does not close at the virtual slot".into());
    }
    let b = interpolate(b_values);
    let w = interpolate(w_values);
    let par_sum = interpolate(par_sum_values);
    let mut q1 = polynomial_mul(&w, &b);
    for coefficient in &mut q1 {
        *coefficient = -*coefficient;
    }
    let omega = root(pp.d);
    let mut omega_power = F::ONE;
    for (i, &coefficient) in par_sum.iter().enumerate() {
        q1[i] += coefficient * (omega_power - F::ONE);
        omega_power *= omega;
    }
    let mut q2 = polynomial_mul(&b, &b);
    for coefficient in &mut q2 {
        *coefficient = -*coefficient;
    }
    for (out, &coefficient) in q2.iter_mut().zip(&b) {
        *out += coefficient;
    }
    let q3 = polynomial_mul(&pp.lagrange[0], &par_sum);
    let mut one_minus_b = b
        .iter()
        .map(|&coefficient| -coefficient)
        .collect::<Vec<_>>();
    one_minus_b[0] += F::ONE;
    let q4 = polynomial_mul(&pp.lagrange[pp.d - 1], &one_minus_b);
    Ok(PolynomialWitness {
        b,
        par_sum,
        w,
        quotients: [
            divide_z(q1, pp.d)?,
            divide_z(q2, pp.d)?,
            divide_z(q3, pp.d)?,
            divide_z(q4, pp.d)?,
        ],
        weight,
    })
}

fn proof_prefix(
    vk: &VerificationKey,
    message: &[u8],
    signature: &Signature,
    label: &str,
) -> Transcript {
    let mut transcript = Transcript::new(label);
    transcript
        .add(&vk.digest)
        .u32(message.len() as u32)
        .add(message)
        .add(&uint_bytes(signature.weight))
        .g1(signature.a_pk)
        .g2(signature.sigma)
        .g1(signature.b_c)
        .g1(signature.q_x_c)
        .g1(signature.q_z_c)
        .g1(signature.u)
        .g1(signature.par_sum_c);
    transcript
}

fn quotient_challenge(vk: &VerificationKey, message: &[u8], signature: &Signature) -> F {
    proof_prefix(vk, message, signature, "hinTS/quotient-challenge").scalar()
}

fn evaluation_challenge(vk: &VerificationKey, message: &[u8], signature: &Signature, v: F) -> F {
    let mut base = proof_prefix(vk, message, signature, "hinTS/evaluation-challenge");
    base.f(v).g1(signature.q_c);
    for counter in 0..=u32::MAX {
        let r = base.clone().u32(counter).scalar();
        if r.pow_vartime([vk.d as u64]) != F::ONE {
            return r;
        }
    }
    unreachable!("hinTS evaluation-point sampler exhausted")
}

fn opening_challenge(vk: &VerificationKey, message: &[u8], signature: &Signature, v: F, r: F) -> F {
    proof_prefix(vk, message, signature, "hinTS/opening-challenge")
        .f(v)
        .g1(signature.q_c)
        .f(r)
        .f(signature.b_r)
        .f(signature.par_sum_r)
        .f(signature.par_sum_r_omega)
        .f(signature.w_r)
        .f(signature.q_r)
        .scalar()
}

/// SignAggr, Section 5 and Section 6.1: decode partials and build the optimized proof.
pub fn sign_aggr(
    pp: &Parameters,
    ak: &AggregationKey,
    vk: &VerificationKey,
    slots: &[usize],
    message: &[u8],
    signatures: &[Vec<u8>],
    _rng: &mut Rng,
) -> Res<Vec<u8>> {
    let partials = decode_partials(ak, slots, signatures)?;
    sign_aggr_decoded(pp, ak, vk, slots, message, partials)
}

/// Keeps the host-signing adapter API; the unchecked aggregation needs no H(m).
pub fn sign_aggr_with_hash(
    pp: &Parameters,
    ak: &AggregationKey,
    vk: &VerificationKey,
    slots: &[usize],
    message: &[u8],
    _h: G2,
    signatures: &[Vec<u8>],
    rng: &mut Rng,
) -> Res<Vec<u8>> {
    sign_aggr(pp, ak, vk, slots, message, signatures, rng)
}

/// Batch-verify partial signatures before aggregating them.
pub fn sign_aggr_with_partial_checks(
    pp: &Parameters,
    ak: &AggregationKey,
    vk: &VerificationKey,
    slots: &[usize],
    message: &[u8],
    signatures: &[Vec<u8>],
    rng: &mut Rng,
) -> Res<Vec<u8>> {
    let partials = partial_verify_with_hash(ak, slots, hash_message(message), signatures, rng)?;
    sign_aggr_decoded(pp, ak, vk, slots, message, partials)
}

fn sign_aggr_decoded(
    pp: &Parameters,
    ak: &AggregationKey,
    vk: &VerificationKey,
    slots: &[usize],
    message: &[u8],
    partials: Vec<G2>,
) -> Res<Vec<u8>> {
    if pp.d != vk.d || ak.weights.len() != pp.u {
        return Err("hinTS aggregation parameters do not match".into());
    }
    let polynomial = polynomial_witness(pp, ak, slots)?;
    let a_pk = g1_exp(
        slots
            .iter()
            .fold(G1::identity(), |sum, &slot| sum + ak.pks[slot]),
        vk.inverse_d,
    );
    let sigma = g2_exp(
        partials
            .iter()
            .fold(G2::identity(), |sum, &point| sum + point),
        vk.inverse_d,
    );
    let q_x_c = slots
        .iter()
        .fold(G1::identity(), |sum, &slot| sum + ak.q_x[slot]);
    let u = slots
        .iter()
        .fold(G1::identity(), |sum, &slot| sum + ak.u[slot]);
    let q_z_c = slots
        .iter()
        .copied()
        .chain(std::iter::once(pp.d - 1))
        .fold(G1::identity(), |sum, slot| sum + ak.q_z[slot]);
    let mut signature = Signature {
        a_pk,
        sigma,
        weight: polynomial.weight,
        q_x_c,
        q_z_c,
        u,
        b_c: g1_msm(&pp.srs_g1[..pp.d], &polynomial.b),
        par_sum_c: g1_msm(&pp.srs_g1[..pp.d], &polynomial.par_sum),
        q_c: G1::identity(),
        b_r: F::ZERO,
        par_sum_r: F::ZERO,
        par_sum_r_omega: F::ZERO,
        w_r: F::ZERO,
        q_r: F::ZERO,
        open_r: G1::identity(),
        open_r_omega: G1::identity(),
    };
    // SignAggr, Section 6.1, step 3: commit to the four quotients with challenge powers.
    let v = quotient_challenge(vk, message, &signature);
    let mut q = vec![F::ZERO; pp.d - 1];
    let mut v_power = F::ONE;
    for quotient in &polynomial.quotients {
        for (out, &coefficient) in q.iter_mut().zip(quotient) {
            *out += v_power * coefficient;
        }
        v_power *= v;
    }
    signature.q_c = g1_msm(&pp.srs_g1[..q.len()], &q);
    let r = evaluation_challenge(vk, message, &signature, v);
    signature.b_r = eval(&polynomial.b, r);
    signature.par_sum_r = eval(&polynomial.par_sum, r);
    signature.par_sum_r_omega = eval(&polynomial.par_sum, r * vk.omega);
    signature.w_r = eval(&polynomial.w, r);
    signature.q_r = eval(&q, r);
    let beta = opening_challenge(vk, message, &signature, v, r);
    let mut combined = polynomial.b.clone();
    for (poly, coefficient) in [
        (&polynomial.par_sum, beta),
        (&polynomial.w, beta.square()),
        (&q, beta.square() * beta),
    ] {
        for (out, &value) in combined.iter_mut().zip(poly) {
            *out += value * coefficient;
        }
    }
    // SignAggr, Section 6.1, step 4: one opening at r and the forward opening at rω.
    let quotient_r = opening_quotient(&combined, r);
    let quotient_r_omega = opening_quotient(&polynomial.par_sum, r * vk.omega);
    signature.open_r = g1_msm(&pp.srs_g1[..quotient_r.len()], &quotient_r);
    signature.open_r_omega = g1_msm(&pp.srs_g1[..quotient_r_omega.len()], &quotient_r_omega);
    Ok(signature.encode())
}

fn quotient_value(vk: &VerificationKey, signature: &Signature, v: F, r: F) -> F {
    let z_r = r.pow_vartime([vk.d as u64]) - F::ONE;
    // Verify: batch the two Lagrange denominators into one shared field inversion.
    let mut denominators = [r - vk.omega, r - F::ONE];
    batch_invert(&mut denominators).expect("evaluation point is outside the domain");
    let first_r = vk.omega * vk.inverse_d * z_r * denominators[0];
    let dummy_r = vk.inverse_d * z_r * denominators[1];
    signature.par_sum_r_omega - signature.par_sum_r - signature.w_r * signature.b_r
        + v * signature.b_r * (F::ONE - signature.b_r)
        + v.square() * first_r * signature.par_sum_r
        + v.square() * v * dummy_r * (F::ONE - signature.b_r)
}

/// Verify, Section 5: five equations, with eleven terms before batching and six after batching.
pub fn verify(
    vk: &VerificationKey,
    message: &[u8],
    threshold: u64,
    wire: &[u8],
    merged: bool,
    rng: &mut Rng,
) -> Res<()> {
    let signature = Signature::decode(wire)?;
    if signature.weight < threshold {
        return Err("hinTS total weight is below threshold".into());
    }
    let v = quotient_challenge(vk, message, &signature);
    let r = evaluation_challenge(vk, message, &signature, v);
    let beta = opening_challenge(vk, message, &signature, v, r);
    let z_r = r.pow_vartime([vk.d as u64]) - F::ONE;
    if quotient_value(vk, &signature, v, r) != z_r * signature.q_r {
        return Err("hinTS merged quotient relation is invalid".into());
    }
    let w_c = vk.w_c - g1_exp(vk.dummy_c, F::from(signature.weight));
    let coefficients = [F::ONE, beta, beta.square(), beta.square() * beta];
    let c_r = g1_msm(
        &[signature.b_c, signature.par_sum_c, w_c, signature.q_c],
        &coefficients,
    );
    let value_r = signature.b_r
        + beta * signature.par_sum_r
        + beta.square() * signature.w_r
        + beta.square() * beta * signature.q_r;
    let rhs_r = c_r + g1_exp(signature.open_r, r) - g1_exp(G1::generator(), value_r);
    let rhs_r_omega = signature.par_sum_c + g1_exp(signature.open_r_omega, r * vk.omega)
        - g1_exp(G1::generator(), signature.par_sum_r_omega);
    let h = hash_message(message);
    let valid = if merged {
        let a = std::array::from_fn::<_, 5, _>(|_| batch_coefficient(rng));
        pair_product(&[
            (g1_exp(signature.b_c, a[0]), vk.sk_c),
            (-g1_exp(signature.q_z_c, a[0]), vk.z_c),
            (
                g1_msm(
                    &[signature.q_x_c, signature.open_r, signature.open_r_omega],
                    &[a[1], a[2], a[3]],
                ),
                vk.tau_g2,
            ),
            (
                -g1_msm(
                    &[
                        signature.a_pk + signature.u,
                        signature.u,
                        rhs_r,
                        rhs_r_omega,
                    ],
                    &[a[0], a[1], a[2], a[3]],
                ),
                G2::generator(),
            ),
            (g1_exp(signature.a_pk, a[4]), h),
            (-g1_exp(G1::generator(), a[4]), signature.sigma),
        ])
    } else {
        let aggregate = pair_product(&[
            (signature.b_c, vk.sk_c),
            (-signature.q_z_c, vk.z_c),
            (-(signature.a_pk + signature.u), G2::generator()),
        ]);
        let degree = pair_product(&[
            (signature.q_x_c, vk.tau_g2),
            (-signature.u, G2::generator()),
        ]);
        let opening_r = pair_product(&[(signature.open_r, vk.tau_g2), (-rhs_r, G2::generator())]);
        let opening_r_omega = pair_product(&[
            (signature.open_r_omega, vk.tau_g2),
            (-rhs_r_omega, G2::generator()),
        ]);
        let bls = pair_product(&[(signature.a_pk, h), (-G1::generator(), signature.sigma)]);
        aggregate && degree && opening_r && opening_r_omega && bls
    };
    if valid {
        Ok(())
    } else {
        Err("hinTS verification pairing equations are invalid".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn each_quotient_and_the_merged_relation_match_on_a_small_instance() {
        let mut rng = Rng::seed_from_u64(61);
        let pp = setup(&[2, 3, 9], &mut rng).unwrap();
        let keys: Vec<_> = (0..pp.u).map(|_| kgen(&mut rng)).collect();
        let pks: Vec<_> = keys
            .iter()
            .map(|key| key.pk_i.to_compressed().to_vec())
            .collect();
        let hints: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(slot, key)| hint_gen(&pp, slot, key).unwrap().encode())
            .collect();
        let (ak, _) = preprocess(&pp, &pks, &hints, &mut rng).unwrap();
        for mask in 1..(1 << pp.u) {
            let slots: Vec<_> = (0..pp.u).filter(|slot| mask & (1 << slot) != 0).collect();
            let polys = polynomial_witness(&pp, &ak, &slots).unwrap();
            let r = F::random(&mut rng);
            let omega = root(pp.d);
            let z = r.pow_vartime([pp.d as u64]) - F::ONE;
            let b = eval(&polys.b, r);
            let p = eval(&polys.par_sum, r);
            let expected = [
                eval(&polys.par_sum, r * omega) - p - eval(&polys.w, r) * b,
                b * (F::ONE - b),
                eval(&pp.lagrange[0], r) * p,
                eval(&pp.lagrange[pp.d - 1], r) * (F::ONE - b),
            ];
            let v = F::random(&mut rng);
            let mut actual = F::ZERO;
            let mut merged = F::ZERO;
            let mut v_power = F::ONE;
            for (quotient, numerator) in polys.quotients.iter().zip(expected) {
                assert_eq!(z * eval(quotient, r), numerator);
                actual += v_power * z * eval(quotient, r);
                merged += v_power * numerator;
                v_power *= v;
            }
            assert_eq!(actual, merged);
            assert_eq!(eval(&polys.par_sum, omega), F::ZERO);
            assert_eq!(eval(&polys.b, F::ONE), F::ONE);
        }
    }
}
