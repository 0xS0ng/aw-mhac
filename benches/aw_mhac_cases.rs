//! AW-MHAC benchmark fixtures, timing boundaries and byte encodings.

use super::{attrs, bits_bytes, disclosure, sampling::Repetition, Case};
use aw_mhac::{
    aw_mhac::*,
    common::{Res, Rng, F, G1, G2},
};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

const TRACE_TIMEOUT: Duration = Duration::from_secs(600);

struct Fixture {
    pp: Parameters,
    isk: F,
    ipk: G2,
    ask: [F; 2],
    apk: [G1; 2],
    registered: Vec<usize>,
    keys: Vec<HolderKey>,
    rho: Vec<(usize, Vec<u8>)>,
    pks: Vec<(usize, [u8; 96])>,
    attributes: Vec<F>,
    registry: Registry,
    credential: Vec<u8>,
    host: Host,
}

struct PresentationInput {
    ctx: Context,
    parts: Vec<(usize, Vec<u8>)>,
    wire: Vec<u8>,
}

impl Fixture {
    fn new(c: &Case) -> Res<Self> {
        let registered = c.registered_slots();
        if registered.len() != c.dim(1) {
            return Err("registered holders exceed slot count".into());
        }
        let pp = setup(&c.weights()?, c.dim(3), &mut c.fixture_rng("setup"))?;
        let (isk, ipk) = ikeygen(&pp, &mut c.fixture_rng("issuer key"));
        let (ask, apk) = akeygen(&pp, &mut c.fixture_rng("auditor key"));
        let mut keys = Vec::with_capacity(registered.len());
        let mut rho = Vec::with_capacity(registered.len());
        let mut pks = Vec::with_capacity(registered.len());
        let mut key_rng = c.fixture_rng("holder keys");
        for &slot in &registered {
            let (mut key, reg) = hkeygen(&pp, slot, &mut key_rng)?;
            key.precompute(&pp);
            keys.push(key);
            pks.push((slot, reg.pk_k.to_compressed()));
            rho.push((slot, reg.encode()));
        }
        pks.sort_unstable_by_key(|entry| entry.0);
        let attributes = attrs(c.dim(3), &mut c.fixture_rng("attributes"));
        let mut registry = Registry::new();
        let credential = issue(
            &pp,
            isk,
            &attributes,
            &rho,
            &mut registry,
            &mut c.fixture_rng("issuance"),
        )?
        .encode();
        let host = accept(
            &pp,
            ipk,
            &attributes,
            &pks,
            &credential,
            &mut c.fixture_rng("acceptance"),
        )?;
        Ok(Self {
            pp,
            isk,
            ipk,
            ask,
            apk,
            registered,
            keys,
            rho,
            pks,
            attributes,
            registry,
            credential,
            host,
        })
    }

    fn audit_participants(&self, k: usize) -> Vec<usize> {
        let mut logical = (0..self.registered.len()).collect::<Vec<_>>();
        logical.sort_unstable_by_key(|&i| self.registered[i]);
        logical.split_off(logical.len() - k)
    }

    fn context(&self, c: &Case, participants: &[usize]) -> Context {
        let mut request = c.fixture_rng("request");
        let threshold = participants
            .iter()
            .map(|&holder| u64::from(self.pp.weights[self.registered[holder]]))
            .sum();
        Context {
            verifier: bits_bytes(&mut request),
            nonce: bits_bytes(&mut request),
            disclosed: disclosure(&self.attributes, c.dim(4)),
            threshold,
        }
    }

    fn presentation(
        &self,
        c: &Case,
        participants: &[usize],
        audit: bool,
    ) -> Res<PresentationInput> {
        let ctx = self.context(c, participants);
        let message = ctx.encode();
        let mut parts_rng = c.fixture_rng(if audit {
            "audit partials"
        } else {
            "presentation partials"
        });
        let parts = participants
            .iter()
            .map(|&holder| {
                Ok((
                    self.registered[holder],
                    part_sign(&self.keys[holder], &message, &mut parts_rng)?,
                ))
            })
            .collect::<Res<Vec<_>>>()?;
        let mut show_rng = c.fixture_rng(if audit {
            "audit presentation"
        } else {
            "presentation"
        });
        let wire = show(
            &self.pp,
            self.ipk,
            self.apk,
            &self.host,
            &self.attributes,
            &ctx,
            &parts,
            &mut show_rng,
        )?
        .encode();
        Ok(PresentationInput { ctx, parts, wire })
    }

    fn trace(&self, input: &PresentationInput, rng: &mut Rng) -> Res<TraceResult> {
        let mut progress = TraceProgress::default();
        trace_with_progress(
            &self.pp,
            self.ipk,
            self.apk,
            self.ask,
            &input.ctx,
            &input.wire,
            &self.registry,
            TRACE_TIMEOUT,
            rng,
            &mut progress,
        )
        .map_err(|error| {
            if error == "trace timed out" {
                format!(
                    "trace timed out; deadline_s={}; left_visited={}; right_visited={}",
                    TRACE_TIMEOUT.as_secs(),
                    progress.left_visited,
                    progress.right_visited
                )
            } else {
                error
            }
        })
    }

    fn enrolment_costs(&self, c: &Case) -> Res<()> {
        c.timed("HKeyGen", "holder", |rng| {
            let (mut key, registration) = hkeygen(&self.pp, self.registered[0], rng)?;
            key.precompute(&self.pp);
            Ok((key, registration.encode()))
        })?;
        if c.experiment == "time_cost_table" {
            let (mut key, _) = hkeygen(
                &self.pp,
                self.registered[0],
                &mut c.fixture_rng("precompute key"),
            )?;
            c.timed("HolderPrecompute", "holder", |_| {
                Ok(key.precompute(&self.pp))
            })?;
        }
        self.issuance_costs(c)
    }

    fn issuance_costs(&self, c: &Case) -> Res<()> {
        c.timed("Issue", "issuer", |rng| {
            let mut registry = Registry::new();
            Ok(issue(
                &self.pp,
                self.isk,
                &self.attributes,
                &self.rho,
                &mut registry,
                rng,
            )?
            .encode())
        })?;
        c.timed("Accept", "host", |rng| {
            accept(
                &self.pp,
                self.ipk,
                &self.attributes,
                &self.pks,
                &self.credential,
                rng,
            )
        })
    }

    fn presentation_costs(&self, c: &Case, input: &PresentationInput, host: usize) -> Res<()> {
        let message = input.ctx.encode();
        c.timed("PartSign", "holder", |rng| {
            part_sign(&self.keys[host], &message, rng)
        })?;
        c.timed("Show", "host", |rng| {
            Ok(show(
                &self.pp,
                self.ipk,
                self.apk,
                &self.host,
                &self.attributes,
                &input.ctx,
                &input.parts,
                rng,
            )?
            .encode())
        })?;
        c.timed("Verify", "verifier", |rng| {
            verify(
                &self.pp,
                self.ipk,
                self.apk,
                &input.ctx,
                &input.wire,
                true,
                rng,
            )
        })?;
        if c.experiment == "time_cost_table" {
            c.timed("VerifyUnmerged", "verifier", |rng| {
                verify(
                    &self.pp,
                    self.ipk,
                    self.apk,
                    &input.ctx,
                    &input.wire,
                    false,
                    rng,
                )
            })?;
        }
        Ok(())
    }

    fn audit_costs(&self, c: &Case, input: &PresentationInput) -> Res<()> {
        let role = if c.experiment == "time_cost_table" {
            "audit_verifier"
        } else {
            "verifier"
        };
        c.timed("Verify", role, |rng| {
            verify(
                &self.pp,
                self.ipk,
                self.apk,
                &input.ctx,
                &input.wire,
                true,
                rng,
            )
        })?;
        c.timed("Trace", "auditor", |rng| {
            self.trace(input, rng)?.theta.encode(c.dim(0))
        })?;
        let theta = match self.trace(input, &mut c.fixture_rng("audit decryption proof")) {
            Ok(result) => result.theta.encode(c.dim(0))?,
            Err(error) if error.starts_with("trace timed out") => {
                c.timeout("Judge", "judge", &format!("{error}; prerequisite=Trace"));
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        c.timed("Judge", "judge", |rng| {
            judge(
                &self.pp,
                self.ipk,
                self.apk,
                &input.ctx,
                &input.wire,
                &theta,
                &self.registry,
                rng,
            )
        })
    }
}

pub fn run(c: &Case) -> Res<()> {
    let experiment = c.experiment.as_str();
    if experiment == "compare_holder_storage" {
        let setup = setup(&c.weights()?, c.dim(3), &mut c.fixture_rng("setup"))?;
        let (mut key, _) = hkeygen(
            &setup,
            c.registered_slots()[0],
            &mut c.fixture_rng("holder keys"),
        )?;
        key.precompute(&setup);
        c.bytes(
            "Storage",
            "holder",
            key.encode()?.len(),
            "includes cached G1 point",
        );
        return Ok(());
    }
    if experiment == "time_cost_table" {
        let weights = c.weights()?;
        c.timed("Setup", "setup", |rng| setup(&weights, c.dim(3), rng))?;
    }
    let fixture = Fixture::new(c)?;
    let participants = c.participants();
    let audit_only = matches!(experiment, "audit_vs_registered" | "audit_vs_participants");
    let needs_audit = audit_only || matches!(experiment, "time_cost_table" | "default_parameters");
    let presentation = if audit_only {
        None
    } else {
        Some(fixture.presentation(c, &participants, false)?)
    };
    let audit = if needs_audit {
        Some(fixture.presentation(c, &fixture.audit_participants(c.dim(2)), true)?)
    } else {
        None
    };
    if experiment == "default_parameters" {
        let presentation = presentation.as_ref().unwrap();
        let trace = fixture.trace(
            audit.as_ref().unwrap(),
            &mut c.fixture_rng("audit decryption proof"),
        )?;
        let bytes = [
            ("Parameters", "setup", fixture.pp.encode().len()),
            ("Rho", "holder", fixture.rho[0].1.len()),
            ("Credential", "holder", fixture.credential.len()),
            (
                "Record",
                "issuer",
                fixture
                    .registry
                    .values()
                    .next()
                    .ok_or("empty registry")?
                    .1
                    .len(),
            ),
            ("PartialSignature", "holder", presentation.parts[0].1.len()),
            ("Presentation", "host", presentation.wire.len()),
            (
                "TraceOutput",
                "auditor",
                trace.theta.encode(c.dim(0))?.len(),
            ),
            ("Storage", "holder", fixture.keys[0].encode()?.len()),
        ];
        for (algorithm, role, len) in bytes {
            c.bytes(algorithm, role, len, "");
        }
        return Ok(());
    }
    if experiment == "compare_link_bytes" {
        let presentation = presentation.as_ref().unwrap();
        let threshold_bytes = 32;
        let signatures = presentation
            .parts
            .iter()
            .skip(1)
            .map(|(_, wire)| wire.len())
            .sum::<usize>();
        c.bytes(
            "LinkBytes",
            "link",
            c.dim(2) * threshold_bytes + signatures + presentation.wire.len(),
            "threshold on each request link, non-host partials, final presentation",
        );
        c.bytes(
            "LogicalBytes",
            "communication",
            threshold_bytes + signatures + presentation.wire.len(),
            "protocol payloads before forwarding",
        );
        c.bytes(
            "ContextBytes",
            "verifier",
            presentation.ctx.encode().len() - threshold_bytes,
            "shared request payload excluded",
        );
        c.bytes(
            "OneWayMessages",
            "communication",
            2 * c.dim(2),
            "physical transmissions",
        );
        return Ok(());
    }
    if experiment == "aggregation_checks" {
        let input = presentation.as_ref().unwrap();
        let message = input.ctx.encode();
        let keys = fixture
            .pks
            .iter()
            .map(|(slot, wire)| Ok((*slot, aw_mhac::common::read_g2(&mut wire.as_slice())?)))
            .collect::<Res<Vec<_>>>()?;
        return c.timed("ShowWithPartialChecks", "host", |rng| {
            check_partials(&fixture.pp, &keys, &message, &input.parts, rng)?;
            Ok(show(
                &fixture.pp,
                fixture.ipk,
                fixture.apk,
                &fixture.host,
                &fixture.attributes,
                &input.ctx,
                &input.parts,
                rng,
            )?
            .encode())
        });
    }
    if matches!(experiment, "time_cost_table" | "vary_slots") {
        fixture.enrolment_costs(c)?;
    } else if experiment == "audit_vs_registered" {
        fixture.issuance_costs(c)?;
    }
    if let Some(input) = &presentation {
        fixture.presentation_costs(c, input, participants[0])?;
    }
    if let Some(input) = &audit {
        fixture.audit_costs(c, input)?;
    }
    Ok(())
}

pub fn comparison(c: &Case) -> Res<Repetition<'static>> {
    let fixture = Fixture::new(c)?;
    let participants = c.participants();
    let ctx = fixture.context(c, &participants);
    let message = ctx.encode();
    let baseline = fixture.presentation(c, &participants, false)?;
    verify(
        &fixture.pp,
        fixture.ipk,
        fixture.apk,
        &ctx,
        &baseline.wire,
        true,
        &mut c.fixture_rng("comparison correctness"),
    )?;
    Ok(Box::new(move |rng| {
        let mut other = Duration::ZERO;
        let mut host = Duration::ZERO;
        let mut parts = Vec::with_capacity(participants.len());
        for (i, &holder) in participants.iter().enumerate() {
            let start = Instant::now();
            let signature = part_sign(&fixture.keys[holder], &message, rng)?;
            let elapsed = start.elapsed();
            if i == 0 {
                host += elapsed;
            } else {
                other += elapsed;
            }
            parts.push((fixture.registered[holder], signature));
        }
        let start = Instant::now();
        let wire = show(
            &fixture.pp,
            fixture.ipk,
            fixture.apk,
            &fixture.host,
            &fixture.attributes,
            &ctx,
            &parts,
            rng,
        )?
        .encode();
        host += start.elapsed();
        black_box(wire);
        Ok(vec![
            other / (participants.len() as u32 - 1),
            host,
            other + host,
        ])
    }))
}

#[cfg(feature = "op-count")]
pub fn diagnostics(c: &Case) -> Res<()> {
    use crate::encode_indices;
    use aw_mhac::{common::rand_nonzero, pairing::g1_msm, poly::interpolate};
    use ff::Field;
    if c.experiment == "compare_holder_storage" {
        let data = [
            c.scheme.as_str(),
            "not_applicable",
            &encode_indices(&c.registered_slots()),
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ];
        println!("{}", data.join(","));
        return Ok(());
    }
    let fixture = Fixture::new(c)?;
    let slots = c.dim(0);
    let emit = |purpose: &str, logical: &[usize], audit: bool, trace_used: bool| -> Res<()> {
        let mapped = logical
            .iter()
            .map(|&i| fixture.registered[i])
            .collect::<Vec<_>>();
        let input = fixture.presentation(c, logical, audit)?;
        let presentation = Presentation::decode(&input.wire, c.dim(4))?;
        let mut evaluation = vec![F::ZERO; slots];
        for &slot in &mapped {
            evaluation[slot] = F::from(slots as u64 * u64::from(fixture.pp.weights[slot]));
        }
        let mut polynomial = interpolate(evaluation);
        let nonzero = polynomial.iter().filter(|&&value| value != F::ZERO).count();
        let mut rng = c.fixture_rng(if audit {
            "audit presentation"
        } else {
            "presentation"
        });
        let _r = rand_nonzero(&mut rng);
        let _delta = F::random(&mut rng);
        let _s = F::random(&mut rng);
        let mu1 = F::random(&mut rng);
        let mu2 = F::random(&mut rng);
        polynomial.resize(slots + 3, F::ZERO);
        polynomial[1] -= mu1;
        polynomial[2] -= mu2;
        polynomial[slots + 1] += mu1;
        polynomial[slots + 2] += mu2;
        if g1_msm(&fixture.pp.srs[..polynomial.len()], &polynomial) != presentation.c_f {
            return Err("diagnostic f differs from the presentation commitment".into());
        }
        let masked_nonzero = polynomial.iter().filter(|&&value| value != F::ZERO).count();
        let mut row = vec![
            c.scheme.clone(),
            purpose.into(),
            encode_indices(&fixture.registered),
            encode_indices(logical),
            encode_indices(&mapped),
            nonzero.to_string(),
            slots.to_string(),
            masked_nonzero.to_string(),
            (slots + 3).to_string(),
        ];
        if trace_used {
            let result = fixture.trace(&input, &mut c.fixture_rng("audit decryption proof"))?;
            if result.theta.slots != mapped {
                return Err("diagnostic Trace recovered a different J".into());
            }
            let k = c.dim(2);
            let m = c.dim(1) / 2;
            let expected = if k < m {
                (1 << m) - (1 << (m - k)) + 1
            } else {
                1 << m
            };
            if result.right_visited != expected {
                return Err(format!(
                    "diagnostic Trace visited {}, expected {expected}",
                    result.right_visited
                ));
            }
            row.extend(
                [
                    result.left_generated,
                    result.right_generated,
                    result.converted_points,
                    result.right_visited,
                    expected,
                    result.right_lookups,
                    result.table_entries,
                ]
                .map(|value| value.to_string()),
            );
        } else {
            row.resize(16, String::new());
        }
        println!("{}", row.join(","));
        Ok(())
    };
    let audit_only = matches!(
        c.experiment.as_str(),
        "audit_vs_registered" | "audit_vs_participants"
    );
    if !audit_only {
        emit("presentation", &c.participants(), false, false)?;
    }
    if audit_only
        || matches!(
            c.experiment.as_str(),
            "time_cost_table" | "default_parameters"
        )
    {
        emit("audit", &fixture.audit_participants(c.dim(2)), true, true)?;
    }
    Ok(())
}
