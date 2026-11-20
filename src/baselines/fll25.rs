//! FLL25 Protocol 1, Protocol 3 and Algorithm 2, with no shared private attributes.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use ff::Field;
use group::Group;

use crate::common::{eof, rand_nonzero, read_f, read_g1, take, Res, Rng, Transcript, F, G1, G2};
use crate::hash::hash_to_g1;
use crate::pairing::{batch_coefficient, g1_exp, g1_msm, g2_exp, pair_product};
use crate::poly::batch_invert;
use crate::OpCounts;

const BASE_DST: &[u8] = b"FLL25-BBS-BASE-BLS12381G1_XMD:SHA-256_SSWU_RO_";
const AUXILIARY_DST: &[u8] = b"FLL25-APPENDIX-H-BLS12381G1_XMD:SHA-256_SSWU_RO_";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShareMode {
    Original,
    Certified,
}

#[derive(Clone)]
pub struct Parameters {
    pub g0: G1,
    pub attribute_bases: Vec<G1>,
    pub issuer_key: G2,
    pub auxiliary_key: Option<G2>,
    pub id: [u8; 32],
}

pub struct IssuerKey {
    secret: F,
    auxiliary_secret: Option<F>,
}

impl Parameters {
    pub fn setup(attributes: usize, rng: &mut Rng) -> (Self, IssuerKey) {
        // Algorithm 1: generate the BBS bases and issuer public key.
        let secret = rand_nonzero(rng);
        let g0 = hash_to_g1(b"g0", BASE_DST);
        let attribute_bases: Vec<_> = (0..attributes)
            .map(|i| hash_to_g1(&(i as u32).to_be_bytes(), BASE_DST))
            .collect();
        // Hash the fixed public bases once, during parameter generation.
        let mut parameter_input = Transcript::new("FLL25-PARAMETERS");
        parameter_input.u32(attributes as u32).g1(g0);
        for &base in &attribute_bases {
            parameter_input.g1(base);
        }
        (
            Self {
                g0,
                attribute_bases,
                issuer_key: g2_exp(G2::generator(), secret),
                auxiliary_key: None,
                id: parameter_input.digest(),
            },
            IssuerKey {
                secret,
                auxiliary_secret: None,
            },
        )
    }

    pub fn enable_optimization(&mut self, key: &mut IssuerKey, rng: &mut Rng) {
        // Appendix H, Optimization 1: the issuer's auxiliary BLS signing key.
        let secret = rand_nonzero(rng);
        self.auxiliary_key = Some(g2_exp(G2::generator(), secret));
        key.auxiliary_secret = Some(secret);
    }
}

#[derive(Clone)]
pub struct Share {
    pub holder_index: usize,
    pub holders: usize,
    pub threshold: usize,
    pub a: G1,
    pub e_share: F,
    pub attributes: Vec<F>,
    c: G1,
    other_d: Vec<Option<G1>>,
    own_d: Option<G1>,
    auxiliary_signature: Option<G1>,
    credential_id: Option<[u8; 32]>,
    storage: ShareMode,
}

impl Share {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.a.to_compressed());
        bytes.extend_from_slice(&self.e_share.to_bytes_be());
        match self.storage {
            ShareMode::Original => {
                for d in self.other_d.iter().flatten() {
                    bytes.extend_from_slice(&d.to_compressed());
                }
            }
            ShareMode::Certified => {
                bytes.extend_from_slice(&self.own_d.expect("appendix H own D").to_compressed());
                bytes.extend_from_slice(
                    &self
                        .auxiliary_signature
                        .expect("appendix H auxiliary signature")
                        .to_compressed(),
                );
            }
        }
        for value in &self.attributes {
            bytes.extend_from_slice(&value.to_bytes_be());
        }
        bytes
    }

    pub fn stored_bytes(&self) -> usize {
        // Shared certificate public keys are public parameters, not holder storage.
        self.encode().len() + self.c.to_compressed().len()
    }
}

fn credential_digest(p: &Parameters, a: G1, attrs: &[F]) -> [u8; 32] {
    let mut transcript = Transcript::new("FLL25-APPENDIX-H-CREDENTIAL");
    // Appendix H: h = H(X2, pp, A, public attributes), with pp bound by its digest.
    transcript.g2(p.issuer_key).add(&p.id);
    transcript.g1(a);
    for value in attrs {
        transcript.f(*value);
    }
    transcript.digest()
}

fn auxiliary_message(digest: [u8; 32], holder_index: usize, d: G1) -> Vec<u8> {
    let mut bytes = digest.to_vec();
    bytes.extend_from_slice(&((holder_index + 1) as u32).to_be_bytes());
    bytes.extend_from_slice(&d.to_compressed());
    bytes
}

fn issue_mode(
    p: &Parameters,
    key: &IssuerKey,
    attributes: &[F],
    holders: usize,
    threshold: usize,
    storage: ShareMode,
    rng: &mut Rng,
) -> Res<Vec<Share>> {
    if attributes.len() != p.attribute_bases.len()
        || threshold == 0
        || threshold > holders
        || holders > u32::MAX as usize
    {
        return Err("invalid FLL25 issuance parameters".into());
    }
    // Protocol 1, step 1: sign all public attributes with BBS.
    let (e, inverse) = loop {
        let e = F::random(&mut *rng);
        if let Some(inverse) = Option::<F>::from((key.secret + e).invert()) {
            break (e, inverse);
        }
    };
    let c = p.g0 + g1_msm(&p.attribute_bases, attributes);
    let a = g1_exp(c, inverse);
    // Protocol 1, step 2: Shamir-share e with threshold t.
    let mut coefficients = vec![e];
    coefficients.extend((1..threshold).map(|_| F::random(&mut *rng)));
    let shares: Vec<_> = (1..=holders)
        .map(|i| {
            let x = F::from(i as u64);
            coefficients
                .iter()
                .rev()
                .fold(F::ZERO, |acc, coefficient| acc * x + coefficient)
        })
        .collect();
    // Protocol 1, step 3: derive D_i = A^(-e_i) for the credential shares.
    let d: Vec<_> = shares.iter().map(|share| g1_exp(a, -*share)).collect();
    let credential_id =
        (storage == ShareMode::Certified).then(|| credential_digest(p, a, attributes));
    let signatures = if storage == ShareMode::Certified {
        let digest = credential_id.expect("appendix H credential digest");
        let secret = key
            .auxiliary_secret
            .ok_or("enable appendix H before issuing compact shares")?;
        if p.auxiliary_key.is_none() {
            return Err("missing appendix H BLS public key".into());
        }
        d.iter()
            .enumerate()
            .map(|(i, point)| {
                g1_exp(
                    hash_to_g1(&auxiliary_message(digest, i, *point), AUXILIARY_DST),
                    secret,
                )
            })
            .map(Some)
            .collect::<Vec<_>>()
    } else {
        vec![None; holders]
    };

    Ok((0..holders)
        .map(|i| Share {
            holder_index: i,
            holders,
            threshold,
            a,
            e_share: shares[i],
            attributes: attributes.to_vec(),
            c,
            other_d: if storage == ShareMode::Original {
                d.iter()
                    .enumerate()
                    .map(|(j, point)| (j != i).then_some(*point))
                    .collect()
            } else {
                vec![None; holders]
            },
            own_d: (storage == ShareMode::Certified).then_some(d[i]),
            auxiliary_signature: signatures[i],
            credential_id,
            storage,
        })
        .collect())
}

fn accept_mode(
    p: &Parameters,
    mut bytes: &[u8],
    attributes: usize,
    holders: usize,
    threshold: usize,
    holder_index: usize,
    storage: ShareMode,
) -> Res<Share> {
    if attributes != p.attribute_bases.len()
        || holder_index >= holders
        || threshold == 0
        || threshold > holders
    {
        return Err("invalid FLL25 received share context".into());
    }
    let a = read_g1(&mut bytes)?;
    let e_share = read_f(&mut bytes)?;
    let (other_d, own_d, auxiliary_signature) = match storage {
        ShareMode::Original => {
            let mut values = Vec::with_capacity(holders);
            for i in 0..holders {
                values.push(if i == holder_index {
                    None
                } else {
                    Some(read_g1(&mut bytes)?)
                });
            }
            (values, None, None)
        }
        ShareMode::Certified => (
            vec![None; holders],
            Some(read_g1(&mut bytes)?),
            Some(read_g1(&mut bytes)?),
        ),
    };
    let attributes = (0..attributes)
        .map(|_| read_f(&mut bytes))
        .collect::<Res<Vec<_>>>()?;
    eof(bytes)?;
    // Accept: cache C = g0 * product_i h_i^a_i once for this credential.
    let c = p.g0 + g1_msm(&p.attribute_bases, &attributes);
    // Cache the public credential digest once at receipt; the wire share is unchanged.
    let credential_id =
        (storage == ShareMode::Certified).then(|| credential_digest(p, a, &attributes));
    Ok(Share {
        holder_index,
        holders,
        threshold,
        a,
        e_share,
        attributes,
        c,
        other_d,
        own_d,
        auxiliary_signature,
        credential_id,
        storage,
    })
}

/// Original Protocol 1 share issuance.
pub fn issue(
    p: &Parameters,
    key: &IssuerKey,
    attributes: &[F],
    holders: usize,
    threshold: usize,
    rng: &mut Rng,
) -> Res<Vec<Share>> {
    issue_mode(
        p,
        key,
        attributes,
        holders,
        threshold,
        ShareMode::Original,
        rng,
    )
}

/// Appendix H Optimization 1: BLS-certify each (holder index, D_i).
pub fn issue_opt(
    p: &Parameters,
    key: &IssuerKey,
    attributes: &[F],
    holders: usize,
    threshold: usize,
    rng: &mut Rng,
) -> Res<Vec<Share>> {
    issue_mode(
        p,
        key,
        attributes,
        holders,
        threshold,
        ShareMode::Certified,
        rng,
    )
}

pub fn accept(
    p: &Parameters,
    bytes: &[u8],
    attributes: usize,
    holders: usize,
    threshold: usize,
    holder_index: usize,
) -> Res<Share> {
    accept_mode(
        p,
        bytes,
        attributes,
        holders,
        threshold,
        holder_index,
        ShareMode::Original,
    )
}

pub fn accept_opt(
    p: &Parameters,
    bytes: &[u8],
    attributes: usize,
    holders: usize,
    threshold: usize,
    holder_index: usize,
) -> Res<Share> {
    accept_mode(
        p,
        bytes,
        attributes,
        holders,
        threshold,
        holder_index,
        ShareMode::Certified,
    )
}

#[derive(Clone)]
pub struct Session {
    pub id: [u8; 32],
    pub nonce: [u8; 32],
    pub disclosed: Vec<Option<F>>,
}

impl Session {
    pub fn request_bytes(&self) -> Vec<u8> {
        let mut bytes = self.id.to_vec();
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.disclosed.iter().flatten().count() as u32).to_be_bytes());
        for (i, value) in self.disclosed.iter().enumerate() {
            if let Some(value) = value {
                bytes.extend_from_slice(&((i + 1) as u32).to_be_bytes());
                bytes.extend_from_slice(&value.to_bytes_be());
            }
        }
        bytes
    }

    fn hidden_indices(&self) -> Vec<usize> {
        self.disclosed
            .iter()
            .enumerate()
            .filter_map(|(i, value)| value.is_none().then_some(i))
            .collect()
    }
}

#[derive(Clone)]
pub struct Presentation {
    pub a: G1,
    pub b: G1,
    pub challenge: F,
    pub response_r: F,
    pub responses_attributes: Vec<F>,
    pub response_e: F,
}

impl Presentation {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.a.to_compressed());
        bytes.extend_from_slice(&self.b.to_compressed());
        bytes.extend_from_slice(&self.challenge.to_bytes_be());
        bytes.extend_from_slice(&self.response_r.to_bytes_be());
        for value in &self.responses_attributes {
            bytes.extend_from_slice(&value.to_bytes_be());
        }
        bytes.extend_from_slice(&self.response_e.to_bytes_be());
        bytes
    }

    pub fn decode(mut bytes: &[u8], hidden: usize) -> Res<Self> {
        let result = Self {
            a: read_g1(&mut bytes)?,
            b: read_g1(&mut bytes)?,
            challenge: read_f(&mut bytes)?,
            response_r: read_f(&mut bytes)?,
            responses_attributes: (0..hidden)
                .map(|_| read_f(&mut bytes))
                .collect::<Res<Vec<_>>>()?,
            response_e: read_f(&mut bytes)?,
        };
        eof(bytes)?;
        Ok(result)
    }
}

fn challenge(session: &Session, u: G1, a: G1, b: G1) -> F {
    let mut transcript = Transcript::new("FLL25-HSIG");
    transcript
        .add(&session.id)
        .add(&session.nonce)
        .g1(u)
        .g1(a)
        .g1(b)
        .u32(session.disclosed.iter().flatten().count() as u32);
    for (i, value) in session.disclosed.iter().enumerate() {
        if let Some(value) = value {
            transcript.u32(i as u32).f(*value);
        }
    }
    transcript.scalar()
}

fn commitment(session: &Session, u: G1) -> [u8; 32] {
    Transcript::new("FLL25-HCOM")
        .add(&session.id)
        .add(&session.nonce)
        .g1(u)
        .digest()
}

pub fn lagrange_coefficients(indices: &[usize]) -> Res<Vec<F>> {
    // Protocol 3, step 2: reuse these coefficients throughout the same execution.
    let mut distinct = HashSet::with_capacity(indices.len());
    if indices.is_empty() || indices.iter().any(|index| !distinct.insert(*index)) {
        return Err("empty or duplicate FLL25 participating subset".into());
    }
    let points: Vec<_> = indices
        .iter()
        .map(|index| F::from(*index as u64 + 1))
        .collect();
    let mut numerators = vec![F::ONE; points.len()];
    let mut denominators = vec![F::ONE; points.len()];
    for (i, x) in points.iter().enumerate() {
        for (j, y) in points.iter().enumerate() {
            if i != j {
                numerators[i] *= -*y;
                denominators[i] *= *x - y;
            }
        }
    }
    // Replace k scalar inversions with one inversion and field products.
    batch_invert(&mut denominators)?;
    Ok(numerators
        .into_iter()
        .zip(denominators)
        .map(|(numerator, inverse)| numerator * inverse)
        .collect())
}

#[derive(Default, Clone)]
pub struct PartyCost {
    pub online: Duration,
    pub online_counts: OpCounts,
}

#[cfg(feature = "op-count")]
fn add_counts(left: &mut OpCounts, right: &OpCounts) {
    left.g1_exp += right.g1_exp;
    left.g2_exp += right.g2_exp;
    left.g1_msm.extend_from_slice(&right.g1_msm);
    left.g2_msm.extend_from_slice(&right.g2_msm);
    left.pair_terms += right.pair_terms;
    left.final_exps += right.final_exps;
    left.hash_g1 += right.hash_g1;
    left.hash_g2 += right.hash_g2;
    left.hash_scalar += right.hash_scalar;
    left.batch_inversions += right.batch_inversions;
}

fn record_role<T>(cost: &mut PartyCost, operation: impl FnOnce() -> T) -> T {
    #[cfg(feature = "op-count")]
    let existing = crate::take_counts();
    let started = Instant::now();
    let result = operation();
    let duration = started.elapsed();
    cost.online += duration;
    #[cfg(feature = "op-count")]
    {
        let measured = crate::take_counts();
        add_counts(&mut cost.online_counts, &measured);
        crate::update_counts(|current| {
            add_counts(current, &existing);
            add_counts(current, &measured);
        });
    }
    result
}

struct Prepared {
    coefficients: Vec<F>,
    disclosed_base: G1,
    full_base: G1,
}

fn prepare(p: &Parameters, share: &Share, session: &Session, indices: &[usize]) -> Res<Prepared> {
    let mut disclosed_bases = Vec::new();
    let mut disclosed_values = Vec::new();
    for (i, value) in session.disclosed.iter().enumerate() {
        if let Some(value) = value {
            if *value != share.attributes[i] {
                return Err("FLL25 disclosed value differs from the credential".into());
            }
            disclosed_bases.push(p.attribute_bases[i]);
            disclosed_values.push(*value);
        }
    }
    let disclosed_base = p.g0 + g1_msm(&disclosed_bases, &disclosed_values);
    Ok(Prepared {
        coefficients: lagrange_coefficients(indices)?,
        disclosed_base,
        full_base: share.c,
    })
}

pub struct ShowResult {
    pub presentation: Presentation,
    pub wire: Vec<u8>,
    pub parties: Vec<PartyCost>,
    pub broadcasts: Vec<Broadcast>,
}

impl ShowResult {
    pub fn logical_bytes(&self) -> usize {
        self.wire.len()
            + self
                .broadcasts
                .iter()
                .map(|message| message.payload.len())
                .sum::<usize>()
    }

    pub fn link_bytes(&self) -> usize {
        self.wire.len()
            + (self.parties.len() - 1)
                * self
                    .broadcasts
                    .iter()
                    .map(|message| message.payload.len())
                    .sum::<usize>()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BroadcastPhase {
    Randomizer,
    Commitment,
    Opening,
    Response,
}

pub struct Broadcast {
    pub sender: usize,
    pub phase: BroadcastPhase,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy)]
pub enum Fault<'a> {
    None,
    ChangedOpening {
        participant: usize,
    },
    ChangedResponse {
        participant: usize,
    },
    ReplayedResponse {
        participant: usize,
        payload: &'a [u8],
    },
}

struct Response {
    r: Option<F>,
    attributes: Vec<F>,
    e: F,
}

impl Response {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        if let Some(r) = self.r {
            bytes.extend_from_slice(&r.to_bytes_be());
        }
        for value in &self.attributes {
            bytes.extend_from_slice(&value.to_bytes_be());
        }
        bytes.extend_from_slice(&self.e.to_bytes_be());
        bytes
    }

    fn decode(mut bytes: &[u8], hidden: usize, primary: bool) -> Res<Self> {
        let r = if primary {
            Some(read_f(&mut bytes)?)
        } else {
            None
        };
        let attributes = if primary {
            (0..hidden)
                .map(|_| read_f(&mut bytes))
                .collect::<Res<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let e = read_f(&mut bytes)?;
        eof(bytes)?;
        Ok(Self { r, attributes, e })
    }
}

pub fn show(p: &Parameters, shares: &[Share], session: &Session, rng: &mut Rng) -> Res<ShowResult> {
    show_with_fault(p, shares, session, Fault::None, rng)
}

pub fn show_with_fault(
    p: &Parameters,
    shares: &[Share],
    session: &Session,
    fault: Fault<'_>,
    rng: &mut Rng,
) -> Res<ShowResult> {
    if shares.is_empty() || session.disclosed.len() != p.attribute_bases.len() {
        return Err("invalid FLL25 presentation parameters".into());
    }
    let first = &shares[0];
    if shares.len() != first.threshold
        || shares.iter().any(|share| {
            share.a != first.a
                || share.storage != first.storage
                || share.holders != first.holders
                || share.threshold != first.threshold
                || share.attributes != first.attributes
                || share.holder_index >= share.holders
                || share.attributes.len() != p.attribute_bases.len()
        })
    {
        return Err("FLL25 shares do not form one threshold credential".into());
    }
    let indices: Vec<_> = shares.iter().map(|share| share.holder_index).collect();
    let hidden = session.hidden_indices();
    let hidden_bases: Vec<_> = hidden.iter().map(|&i| p.attribute_bases[i]).collect();
    let mut parties = vec![PartyCost::default(); shares.len()];
    let mut broadcasts = Vec::new();
    // Protocol 3, step 2: the disclosure product and interpolation depend on this request.
    let prepared = shares
        .iter()
        .zip(&mut parties)
        .map(|(share, cost)| record_role(cost, || prepare(p, share, session, &indices)))
        .collect::<Res<Vec<_>>>()?;

    // Protocol 3, step 1: the primary broadcasts the signature randomizer r.
    let (r, randomizer_wire) = record_role(&mut parties[0], || {
        let r = F::random(&mut *rng);
        (r, r.to_bytes_be().to_vec())
    });
    broadcasts.push(Broadcast {
        sender: 0,
        phase: BroadcastPhase::Randomizer,
        payload: randomizer_wire.clone(),
    });
    for cost in parties.iter_mut().skip(1) {
        record_role(cost, || -> Res<()> {
            let mut input = randomizer_wire.as_slice();
            let value = read_f(&mut input)?;
            eof(input)?;
            if value != r {
                return Err("FLL25 randomizer mismatch".into());
            }
            Ok(())
        })?;
    }

    // Protocol 3, steps 2-3: randomize A, form U_i, and broadcast com_i.
    let mut abar = Vec::new();
    let mut nonces = Vec::new();
    let mut openings = Vec::new();
    let mut commitments = Vec::new();
    for (i, (share, cost)) in shares.iter().zip(&mut parties).enumerate() {
        let (a, nonce, u, commit, payload) = record_role(cost, || -> Res<_> {
            let a = g1_exp(share.a, r);
            let gamma = F::random(&mut *rng);
            let (alpha, beta, u) = if i == 0 {
                let alpha = F::random(&mut *rng);
                let beta: Vec<_> = hidden.iter().map(|_| F::random(&mut *rng)).collect();
                let mut bases = vec![prepared[i].disclosed_base];
                bases.extend(&hidden_bases);
                bases.push(a);
                let mut values = vec![alpha];
                values.extend(&beta);
                values.push(gamma);
                (Some(alpha), beta, g1_msm(&bases, &values))
            } else {
                (None, Vec::new(), g1_exp(a, gamma))
            };
            let commit = commitment(session, u);
            let mut payload = commit.to_vec();
            if share.storage == ShareMode::Certified {
                payload
                    .extend_from_slice(&share.own_d.ok_or("missing certified D")?.to_compressed());
                payload.extend_from_slice(
                    &share
                        .auxiliary_signature
                        .ok_or("missing certificate")?
                        .to_compressed(),
                );
            }
            Ok((a, (alpha, beta, gamma), u, commit, payload))
        })?;
        broadcasts.push(Broadcast {
            sender: i,
            phase: BroadcastPhase::Commitment,
            payload,
        });
        abar.push(a);
        nonces.push(nonce);
        openings.push(u);
        commitments.push(commit);
    }

    // Appendix H: receive D_i and its auxiliary signature with step 3's commitment.
    let mut local_d = Vec::new();
    let mut local_commitments = Vec::new();
    for (i, (share, cost)) in shares.iter().zip(&mut parties).enumerate() {
        let (values, received_commitments) = record_role(cost, || -> Res<_> {
            let mut values = Vec::with_capacity(shares.len());
            let mut received_commitments = Vec::with_capacity(shares.len());
            let mut signatures = Vec::new();
            let mut messages = Vec::new();
            let mut coefficients = Vec::new();
            let digest = if first.storage == ShareMode::Certified {
                Some(
                    share
                        .credential_id
                        .ok_or("missing appendix H credential digest")?,
                )
            } else {
                None
            };
            for (j, peer) in shares.iter().enumerate() {
                if i == j {
                    received_commitments.push(commitments[j]);
                } else {
                    let mut input = broadcasts[1 + j].payload.as_slice();
                    received_commitments.push(take::<32>(&mut input)?);
                    if first.storage == ShareMode::Original {
                        eof(input)?;
                    }
                }
                if first.storage == ShareMode::Original {
                    values.push(if i == j {
                        None
                    } else {
                        Some(share.other_d[peer.holder_index].ok_or("FLL25 missing D")?)
                    });
                    continue;
                }
                if i == j {
                    values.push(share.own_d);
                    continue;
                }
                let broadcast = &broadcasts[1 + j];
                let mut input = broadcast.payload.as_slice();
                take::<32>(&mut input)?;
                let d = read_g1(&mut input)?;
                let signature = read_g1(&mut input)?;
                eof(input)?;
                values.push(Some(d));
                signatures.push(signature);
                messages.push(hash_to_g1(
                    &auxiliary_message(digest.expect("appendix H digest"), peer.holder_index, d),
                    AUXILIARY_DST,
                ));
            }
            if first.storage == ShareMode::Certified {
                for _ in 0..signatures.len() {
                    coefficients.push(batch_coefficient(rng));
                }
                let signature = g1_msm(&signatures, &coefficients);
                let message = g1_msm(&messages, &coefficients);
                let key = p
                    .auxiliary_key
                    .ok_or("missing FLL25 auxiliary public key")?;
                if !pair_product(&[(signature, G2::generator()), (-message, key)]) {
                    return Err("FLL25 appendix H signature batch failed".into());
                }
            }
            Ok((values, received_commitments))
        })?;
        local_d.push(values);
        local_commitments.push(received_commitments);
    }

    // Protocol 3, step 2: form B_bar and the individual factors used in step 7.
    let mut bbar = Vec::new();
    let mut components = Vec::new();
    for (i, cost) in parties.iter_mut().enumerate() {
        let (b, local_components) = record_role(cost, || {
            let coefficients = &prepared[i].coefficients;
            let own_contribution = if i == 0 {
                g1_exp(first.a, -shares[i].e_share * coefficients[i])
            } else {
                G1::identity()
            };
            let local_components: Vec<_> = (0..shares.len())
                .map(|j| {
                    if j == 0 {
                        let d = if j == i {
                            own_contribution
                        } else {
                            g1_exp(local_d[i][j].expect("known peer D"), coefficients[j])
                        };
                        g1_exp(prepared[i].full_base + d, r)
                    } else if j == i {
                        g1_exp(abar[i], -shares[i].e_share * coefficients[i])
                    } else {
                        g1_exp(local_d[i][j].expect("known peer D"), coefficients[j] * r)
                    }
                })
                .collect();
            let b = local_components
                .iter()
                .copied()
                .fold(G1::identity(), |acc, p| acc + p);
            (b, local_components)
        });
        bbar.push(b);
        components.push(local_components);
    }

    // Protocol 3, step 4: open the commitments by broadcasting U_i.
    for (i, (u, cost)) in openings.iter().copied().zip(&mut parties).enumerate() {
        let u = if matches!(fault, Fault::ChangedOpening {participant} if participant==i) {
            u + G1::generator()
        } else {
            u
        };
        broadcasts.push(Broadcast {
            sender: i,
            phase: BroadcastPhase::Opening,
            payload: record_role(cost, || u.to_compressed().to_vec()),
        });
    }
    // Protocol 3, step 5: check every received commitment opening.
    let opening_offset = 1 + shares.len();
    let mut local_openings = Vec::new();
    for (i, cost) in parties.iter_mut().enumerate() {
        local_openings.push(record_role(cost, || {
            let mut received = Vec::with_capacity(shares.len());
            for j in 0..shares.len() {
                let u = if i == j {
                    openings[j]
                } else {
                    let mut input = broadcasts[opening_offset + j].payload.as_slice();
                    let u = read_g1(&mut input)?;
                    eof(input)?;
                    if commitment(session, u) != local_commitments[i][j] {
                        return Err(format!(
                            "FLL25 identifiable abort at commitment participant {}",
                            indices[j]
                        ));
                    }
                    u
                };
                received.push(u);
            }
            Ok(received)
        })?);
    }

    // Protocol 3, step 6: derive ch from the common transcript and broadcast responses.
    let mut challenges = Vec::new();
    let mut responses = Vec::new();
    for (i, cost) in parties.iter_mut().enumerate() {
        let (ch, response) = record_role(cost, || {
            let u = local_openings[i]
                .iter()
                .copied()
                .fold(G1::identity(), |acc, p| acc + p);
            let ch = challenge(session, u, abar[i], bbar[i]);
            let (alpha, beta, gamma) = &nonces[i];
            let response = Response {
                r: alpha.map(|alpha| alpha + ch * r),
                attributes: hidden
                    .iter()
                    .zip(beta)
                    .map(|(&j, beta)| *beta + ch * r * shares[i].attributes[j])
                    .collect(),
                e: *gamma - ch * shares[i].e_share * prepared[i].coefficients[i],
            };
            (ch, response)
        });
        let mut response = response;
        if matches!(fault, Fault::ChangedResponse {participant} if participant==i) {
            response.e += F::ONE;
        }
        let payload = record_role(cost, || {
            if let Fault::ReplayedResponse {
                participant,
                payload,
            } = fault
            {
                if participant == i {
                    return payload.to_vec();
                }
            }
            response.encode()
        });
        broadcasts.push(Broadcast {
            sender: i,
            phase: BroadcastPhase::Response,
            payload,
        });
        challenges.push(ch);
        responses.push(response);
    }

    // Protocol 3, steps 7-8: identify bad responses, then combine the honest responses.
    let response_offset = 1 + 2 * shares.len();
    let mut presentations = Vec::new();
    for (i, cost) in parties.iter_mut().enumerate() {
        let result = record_role(cost, || {
            let mut received = Vec::new();
            for j in 0..shares.len() {
                let response = if i == j {
                    Response {
                        r: responses[j].r,
                        attributes: responses[j].attributes.clone(),
                        e: responses[j].e,
                    }
                } else {
                    Response::decode(
                        &broadcasts[response_offset + j].payload,
                        hidden.len(),
                        j == 0,
                    )?
                };
                // Protocol 3, step 7: preserve per-sender checks for identifiable abort.
                if i != j {
                    let mut bases = vec![abar[i], components[i][j]];
                    let mut values = vec![response.e, -challenges[i]];
                    if j == 0 {
                        bases.push(prepared[i].disclosed_base);
                        values.push(response.r.ok_or("missing primary FLL25 r response")?);
                        bases.extend(&hidden_bases);
                        values.extend(&response.attributes);
                    }
                    let reconstructed = g1_msm(&bases, &values);
                    if reconstructed != local_openings[i][j] {
                        return Err(format!(
                            "FLL25 identifiable abort at response participant {}",
                            indices[j]
                        ));
                    }
                }
                received.push(response);
            }
            // Protocol 3, step 8: output the ordinary BBS-compatible presentation.
            let presentation = Presentation {
                a: abar[i],
                b: bbar[i],
                challenge: challenges[i],
                response_r: received[0].r.ok_or("missing primary FLL25 r response")?,
                responses_attributes: received[0].attributes.clone(),
                response_e: received
                    .iter()
                    .fold(F::ZERO, |acc, response| acc + response.e),
            };
            let wire = presentation.encode();
            Ok((presentation, wire))
        })?;
        presentations.push(result);
    }
    let (presentation, wire) = presentations.remove(0);
    if presentations
        .iter()
        .any(|(_, other_wire)| *other_wire != wire)
    {
        return Err("FLL25 parties produced different presentations".into());
    }
    Ok(ShowResult {
        presentation,
        wire,
        parties,
        broadcasts,
    })
}

pub fn verify(p: &Parameters, session: &Session, bytes: &[u8]) -> Res<()> {
    // Algorithm 2: recover U, check Hsig, then check the BBS pairing equation.
    if session.disclosed.len() != p.attribute_bases.len() {
        return Err("FLL25 verification disclosure shape".into());
    }
    let hidden = session.hidden_indices();
    let presentation = Presentation::decode(bytes, hidden.len())?;
    let (disclosed_bases, disclosed_values): (Vec<_>, Vec<_>) = session
        .disclosed
        .iter()
        .enumerate()
        .filter_map(|(i, value)| value.map(|value| (p.attribute_bases[i], value)))
        .unzip();
    let disclosed_base = p.g0 + g1_msm(&disclosed_bases, &disclosed_values);
    let mut bases = vec![presentation.b, disclosed_base, presentation.a];
    let mut values = vec![
        -presentation.challenge,
        presentation.response_r,
        presentation.response_e,
    ];
    bases.extend(hidden.iter().map(|&i| p.attribute_bases[i]));
    values.extend(&presentation.responses_attributes);
    let u = g1_msm(&bases, &values);
    if challenge(session, u, presentation.a, presentation.b) != presentation.challenge {
        return Err("FLL25 challenge mismatch".into());
    }
    if !pair_product(&[
        (presentation.a, p.issuer_key),
        (-presentation.b, G2::generator()),
    ]) {
        return Err("FLL25 BBS pairing check failed".into());
    }
    Ok(())
}
