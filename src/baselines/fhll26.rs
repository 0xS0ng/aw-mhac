//! Device-Bound Anonymous Credentials With(out) Trusted Hardware, EUROCRYPT 2026.
//! BBS-BLS follows Sections 6.1 and 6.3, Figure 5, and Appendix F.1.

use ff::Field;
use group::Group;

use crate::common::{rand_nonzero, read_f, read_g1, read_g2, Res, Rng, Transcript, F, G1, G2};
use crate::hash::{hash_to_g1, hash_to_g2};
use crate::pairing::{batch_coefficient, g1_exp, g1_msm, g2_exp, pair_product};

const BASE_DST: &[u8] = b"FHLL26_BBS_BLS_BASE_BLS12381G1_XMD:SHA-256_SSWU_RO_";
const SIGNATURE_DST: &[u8] = b"FHLL26_BBS_BLS_SIGN_BLS12381G2_XMD:SHA-256_SSWU_RO_";

#[derive(Clone)]
pub struct Parameters {
    pub h0: G1,
    pub hs: Vec<G1>,
    pub id: [u8; 32],
}

#[derive(Clone)]
pub struct IssuerKey {
    pub sk: F,
    pub pk: G2,
}

#[derive(Clone)]
pub struct DeviceKey {
    pub sk: F,
    pub pk: G1,
}

#[derive(Clone)]
pub struct Credential {
    pub a: G1,
    pub e: F,
}

impl Credential {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);
        out.extend_from_slice(&self.a.to_compressed());
        out.extend_from_slice(&self.e.to_bytes_be());
        out
    }

    fn decode(mut input: &[u8]) -> Res<Self> {
        let a = read_g1(&mut input)?;
        let e = read_f(&mut input)?;
        if !input.is_empty() || bool::from(a.is_identity()) {
            return Err("invalid BBS-BLS credential".into());
        }
        Ok(Self { a, e })
    }
}

#[derive(Clone)]
pub struct Host {
    pub ipk: G2,
    pub dpk: G1,
    pub credential: Credential,
    pub attrs: Vec<F>,
    pub c: G1,
}

#[derive(Clone)]
pub struct UserState {
    pub r_key: F,
    pub dpk_bar: G1,
}

pub fn setup(attributes: usize) -> Parameters {
    // Figure 5, Setup: derive the BBS attribute bases.
    let h0 = hash_to_g1(&0u32.to_be_bytes(), BASE_DST);
    let hs = (1..=attributes)
        .map(|index| hash_to_g1(&(index as u32).to_be_bytes(), BASE_DST))
        .collect::<Vec<_>>();
    // Bind the fixed public bases once; later Schnorr transcripts use pp.id.
    let mut input = Transcript::new("FHLL26-BBS-BLS-parameters");
    input.u32(attributes as u32).g1(h0);
    for &h in &hs {
        input.g1(h);
    }
    Parameters {
        h0,
        hs,
        id: input.digest(),
    }
}

pub fn iss_kgen(_pp: &Parameters, rng: &mut Rng) -> IssuerKey {
    // Figure 5, IssKGen: the BBS issuer key pair.
    let sk = rand_nonzero(rng);
    IssuerKey {
        sk,
        pk: g2_exp(G2::generator(), sk),
    }
}

pub fn dev_kgen(pp: &Parameters, rng: &mut Rng) -> DeviceKey {
    // Figure 5, DevKGen: bind the SE secret to H_0 in G1.
    let sk = rand_nonzero(rng);
    DeviceKey {
        sk,
        pk: g1_exp(pp.h0, sk),
    }
}

fn decode_g1(mut wire: &[u8]) -> Res<G1> {
    let point = read_g1(&mut wire)?;
    if !wire.is_empty() {
        return Err("trailing BBS-BLS G1 bytes".into());
    }
    Ok(point)
}

fn decode_g2(mut wire: &[u8]) -> Res<G2> {
    let point = read_g2(&mut wire)?;
    if !wire.is_empty() {
        return Err("trailing BBS-BLS G2 bytes".into());
    }
    Ok(point)
}

fn attribute_product(pp: &Parameters, dpk: G1, attrs: &[F]) -> Res<G1> {
    if attrs.len() != pp.hs.len() {
        return Err("BBS-BLS attribute count".into());
    }
    Ok(G1::generator() + dpk + g1_msm(&pp.hs, attrs))
}

pub fn issue(
    pp: &Parameters,
    issuer: &IssuerKey,
    dpk_wire: &[u8],
    attrs: &[F],
    rng: &mut Rng,
) -> Res<Credential> {
    // Figure 5, Issue: sign the device public key together with the attributes.
    let dpk = decode_g1(dpk_wire)?;
    let c = attribute_product(pp, dpk, attrs)?;
    if bool::from(c.is_identity()) {
        return Err("BBS-BLS attribute product is identity".into());
    }
    loop {
        let e = F::random(&mut *rng);
        if let Some(inverse) = Option::<F>::from((issuer.sk + e).invert()) {
            return Ok(Credential {
                a: g1_exp(c, inverse),
                e,
            });
        }
    }
}

pub fn accept(
    pp: &Parameters,
    ipk_wire: &[u8],
    dpk_wire: &[u8],
    credential_wire: &[u8],
    attrs: &[F],
) -> Res<Host> {
    // Figure 5, VfCred: check A != 0 and the BBS credential pairing equation.
    let ipk = decode_g2(ipk_wire)?;
    let dpk = decode_g1(dpk_wire)?;
    let credential = Credential::decode(credential_wire)?;
    let c = attribute_product(pp, dpk, attrs)?;
    let ipk_e = ipk + g2_exp(G2::generator(), credential.e);
    if !pair_product(&[(credential.a, ipk_e), (-c, G2::generator())]) {
        return Err("BBS-BLS credential pairing".into());
    }
    // Cache C for the subsequent ShowUser2 attribute-product computation.
    Ok(Host {
        ipk,
        dpk,
        credential,
        attrs: attrs.to_vec(),
        c,
    })
}

// Figure 5, ShowUser1: randomize dpk; this computation is independent of ctx.
pub fn show_user1(pp: &Parameters, host: &Host, rng: &mut Rng) -> (UserState, Vec<u8>) {
    let r_key = F::random(&mut *rng);
    let dpk_bar = host.dpk + g1_exp(pp.h0, r_key);
    let request = dpk_bar.to_compressed().to_vec();
    (UserState { r_key, dpk_bar }, request)
}

fn signature_message(dpk_bar: G1, context: &[u8]) -> Vec<u8> {
    // Figure 5, ShowSE/Verify: hash the actual (dpk_bar, ctx) BLS message.
    let mut out = Vec::with_capacity(52 + context.len());
    out.extend_from_slice(&dpk_bar.to_compressed());
    out.extend_from_slice(&(context.len() as u32).to_be_bytes());
    out.extend_from_slice(context);
    out
}

pub fn show_se(
    _pp: &Parameters,
    device: &DeviceKey,
    request: &[u8],
    context: &[u8],
) -> Res<Vec<u8>> {
    // Figure 5, ShowSE: return the deterministic BLS signature under dsk.
    let dpk_bar = decode_g1(request)?;
    let q = hash_to_g2(&signature_message(dpk_bar, context), SIGNATURE_DST);
    Ok(g2_exp(q, device.sk).to_compressed().to_vec())
}

fn check_disclosed(pp: &Parameters, disclosed: &[usize]) -> Res<()> {
    if disclosed.iter().any(|&index| index >= pp.hs.len())
        || disclosed.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("BBS-BLS disclosure indices are not ordered and in range".into());
    }
    Ok(())
}

fn hidden_indices(pp: &Parameters, disclosed: &[usize]) -> Vec<usize> {
    (0..pp.hs.len())
        .filter(|index| disclosed.binary_search(index).is_err())
        .collect()
}

fn disclosed_product(pp: &Parameters, dpk_bar: G1, disclosed: &[(usize, F)]) -> G1 {
    let bases = disclosed
        .iter()
        .map(|&(index, _)| pp.hs[index])
        .collect::<Vec<_>>();
    let scalars = disclosed
        .iter()
        .map(|&(_, scalar)| scalar)
        .collect::<Vec<_>>();
    G1::generator() + dpk_bar + g1_msm(&bases, &scalars)
}

#[derive(Clone)]
pub struct Presentation {
    pub dpk_bar: G1,
    pub pi_se: G2,
    pub a_bar: G1,
    pub b_bar: G1,
    pub c_bar: G1,
    pub challenge: F,
    pub responses: Vec<F>,
}

impl Presentation {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(288 + 32 * (1 + self.responses.len()));
        out.extend_from_slice(&self.dpk_bar.to_compressed());
        out.extend_from_slice(&self.pi_se.to_compressed());
        for point in [self.a_bar, self.b_bar, self.c_bar] {
            out.extend_from_slice(&point.to_compressed());
        }
        out.extend_from_slice(&self.challenge.to_bytes_be());
        for response in &self.responses {
            out.extend_from_slice(&response.to_bytes_be());
        }
        out
    }

    pub fn decode(mut input: &[u8], hidden: usize) -> Res<Self> {
        if input.len() != 448 + 32 * hidden {
            return Err("BBS-BLS presentation length".into());
        }
        let result = Self {
            dpk_bar: read_g1(&mut input)?,
            pi_se: read_g2(&mut input)?,
            a_bar: read_g1(&mut input)?,
            b_bar: read_g1(&mut input)?,
            c_bar: read_g1(&mut input)?,
            challenge: read_f(&mut input)?,
            responses: (0..hidden + 4)
                .map(|_| read_f(&mut input))
                .collect::<Res<_>>()?,
        };
        if bool::from(result.a_bar.is_identity()) {
            return Err("BBS-BLS randomized signature is identity".into());
        }
        Ok(result)
    }
}

fn first_messages(
    pp: &Parameters,
    proof: &Presentation,
    hidden: &[usize],
    values: &[F],
) -> [G1; 2] {
    let mut bases = vec![proof.c_bar, pp.h0];
    bases.extend(hidden.iter().map(|&index| -pp.hs[index]));
    [
        g1_msm(&bases, &values[..hidden.len() + 2]),
        g1_msm(&[proof.c_bar, -proof.a_bar], &values[hidden.len() + 2..]),
    ]
}

fn challenge(
    pp: &Parameters,
    ipk: G2,
    context: &[u8],
    disclosed: &[(usize, F)],
    proof: &Presentation,
    y: G1,
    commitments: [G1; 2],
) -> F {
    // Figure 5, ShowUser2/Verify, and Appendix F.1: bind the public relation,
    // first messages and ctx. Fixed parameter bases are already bound by pp.id.
    let mut input = Transcript::new("FHLL26-BBS-BLS-Schnorr");
    input
        .add(&pp.id)
        .g2(ipk)
        .u32(context.len() as u32)
        .add(context)
        .u32(disclosed.len() as u32);
    for &(index, value) in disclosed {
        input.u32(index as u32).f(value);
    }
    input
        .g1(proof.dpk_bar)
        .g2(proof.pi_se)
        .g1(proof.a_bar)
        .g1(proof.b_bar)
        .g1(proof.c_bar)
        .g1(y)
        .g1(commitments[0])
        .g1(commitments[1]);
    input.scalar()
}

pub fn show_user2(
    pp: &Parameters,
    host: &Host,
    state: &UserState,
    context: &[u8],
    disclosed: &[usize],
    response: &[u8],
    rng: &mut Rng,
) -> Res<Vec<u8>> {
    // Figure 5, ShowUser2: validate the SE response before adapting it.
    check_disclosed(pp, disclosed)?;
    let smsg = decode_g2(response)?;
    let q = hash_to_g2(&signature_message(state.dpk_bar, context), SIGNATURE_DST);
    if !pair_product(&[(pp.h0, smsg), (-host.dpk, q)]) {
        return Err("BBS-BLS host device signature pairing".into());
    }
    // Figure 5, ShowUser2: adapt the same signature to the randomized device key.
    let pi_se = smsg + g2_exp(q, state.r_key);
    let r1 = rand_nonzero(rng);
    let r2 = rand_nonzero(rng);
    // Figure 5, ShowUser2: randomize the cached credential product and signature.
    let c_bar = g1_exp(host.c, r1);
    let a_bar = g1_exp(host.credential.a, r1 * r2);
    let b_bar = g1_msm(&[c_bar, -a_bar], &[r2, host.credential.e]);
    let hidden = hidden_indices(pp, disclosed);
    let disclosed = disclosed
        .iter()
        .map(|&index| (index, host.attrs[index]))
        .collect::<Vec<_>>();
    let y = disclosed_product(pp, state.dpk_bar, &disclosed);
    let mut proof = Presentation {
        dpk_bar: state.dpk_bar,
        pi_se,
        a_bar,
        b_bar,
        c_bar,
        challenge: F::ZERO,
        responses: Vec::new(),
    };
    // Figure 5, ShowUser2: prove both linear relations with shared responses.
    let mut witnesses = vec![Option::<F>::from(r1.invert()).unwrap(), state.r_key];
    witnesses.extend(hidden.iter().map(|&index| host.attrs[index]));
    witnesses.extend([r2, host.credential.e]);
    let randomizers = (0..witnesses.len())
        .map(|_| F::random(&mut *rng))
        .collect::<Vec<_>>();
    let commitments = first_messages(pp, &proof, &hidden, &randomizers);
    proof.challenge = challenge(pp, host.ipk, context, &disclosed, &proof, y, commitments);
    proof.responses = randomizers
        .into_iter()
        .zip(witnesses)
        .map(|(randomizer, witness)| randomizer + proof.challenge * witness)
        .collect();
    Ok(proof.encode())
}

pub fn verify(
    pp: &Parameters,
    ipk_wire: &[u8],
    context: &[u8],
    disclosed: &[(usize, F)],
    presentation: &[u8],
    batched: bool,
    rng: &mut Rng,
) -> Res<()> {
    // Figure 5, Verify: decode received points and reconstruct the Schnorr messages.
    let indices = disclosed
        .iter()
        .map(|&(index, _)| index)
        .collect::<Vec<_>>();
    check_disclosed(pp, &indices)?;
    let ipk = decode_g2(ipk_wire)?;
    let hidden = hidden_indices(pp, &indices);
    let proof = Presentation::decode(presentation, hidden.len())?;
    let q = hash_to_g2(&signature_message(proof.dpk_bar, context), SIGNATURE_DST);
    let y = disclosed_product(pp, proof.dpk_bar, disclosed);
    let mut first_bases = vec![proof.c_bar, pp.h0];
    first_bases.extend(hidden.iter().map(|&index| -pp.hs[index]));
    first_bases.push(y);
    let mut first_scalars = proof.responses[..hidden.len() + 2].to_vec();
    first_scalars.push(-proof.challenge);
    let second_scalars = [
        proof.responses[hidden.len() + 2],
        proof.responses[hidden.len() + 3],
        -proof.challenge,
    ];
    let commitments = [
        g1_msm(&first_bases, &first_scalars),
        g1_msm(&[proof.c_bar, -proof.a_bar, proof.b_bar], &second_scalars),
    ];
    if proof.challenge != challenge(pp, ipk, context, disclosed, &proof, y, commitments) {
        return Err("BBS-BLS Schnorr challenge".into());
    }
    // Figure 5, Verify: check the adapted BLS signature and BBS pairing equations.
    let valid = if batched {
        let bls_coefficient = batch_coefficient(rng);
        let bbs_coefficient = batch_coefficient(rng);
        pair_product(&[
            (g1_exp(pp.h0, bls_coefficient), proof.pi_se),
            (-g1_exp(proof.dpk_bar, bls_coefficient), q),
            (g1_exp(proof.a_bar, bbs_coefficient), ipk),
            (-g1_exp(proof.b_bar, bbs_coefficient), G2::generator()),
        ])
    } else {
        let bls = pair_product(&[(pp.h0, proof.pi_se), (-proof.dpk_bar, q)]);
        let bbs = pair_product(&[(proof.a_bar, ipk), (-proof.b_bar, G2::generator())]);
        bls && bbs
    };
    if !valid {
        return Err("BBS-BLS presentation pairing".into());
    }
    Ok(())
}
