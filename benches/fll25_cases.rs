//! Original and Appendix H FLL25, including the retained credential-product cache.

use crate::{attrs, bits_bytes, disclosure, Case};
use aw_mhac::{
    baselines::fll25::{self, BroadcastPhase, IssuerKey, Parameters, Session, Share, ShowResult},
    common::{Res, Rng, F},
};
use std::{hint::black_box, time::Duration};

struct Fixture {
    pp: Parameters,
    key: IssuerKey,
    attrs: Vec<F>,
    shares: Vec<Share>,
    selected: Vec<Share>,
    session: Session,
}

fn fixture(c: &Case) -> Res<Fixture> {
    let (b, k, n, h) = (c.dim(1), c.dim(2), c.dim(3), c.dim(4));
    if k < 2 || k > b || h > n {
        return Err("invalid FLL25 dimensions".into());
    }
    let (mut pp, mut key) = Parameters::setup(n, &mut c.fixture_rng("setup"));
    let optimized = c.scheme == "fll25_opt";
    if optimized {
        pp.enable_optimization(&mut key, &mut c.fixture_rng("certification-key"));
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
    let attrs = attrs(n, &mut c.fixture_rng("attributes"));
    let issued = issue(&pp, &key, &attrs, b, k, &mut c.fixture_rng("issue"))?;
    let shares = issued
        .iter()
        .map(|share| accept(&pp, &share.encode(), n, b, k, share.holder_index))
        .collect::<Res<Vec<_>>>()?;
    let ids = c.participants();
    if ids.len() != k {
        return Err("FLL25 participant count differs from k".into());
    }
    let selected = ids
        .iter()
        .map(|&id| {
            shares
                .get(id)
                .cloned()
                .ok_or_else(|| "FLL25 participant outside registered holders".into())
        })
        .collect::<Res<Vec<_>>>()?;
    let mut request_rng = c.fixture_rng("request");
    let session = Session {
        id: bits_bytes(&mut request_rng),
        nonce: bits_bytes(&mut request_rng),
        disclosed: disclosure(&attrs, h),
    };
    Ok(Fixture {
        pp,
        key,
        attrs,
        shares,
        selected,
        session,
    })
}

fn role_durations(result: &ShowResult) -> Vec<Duration> {
    let others = result
        .parties
        .iter()
        .skip(1)
        .map(|p| p.online)
        .sum::<Duration>();
    let host = result.parties[0].online;
    vec![
        others / (result.parties.len() as u32 - 1),
        host,
        others + host,
    ]
}

pub fn comparison(c: &Case) -> Res<Box<dyn FnMut(&mut Rng) -> Res<Vec<Duration>>>> {
    let f = fixture(c)?;
    Ok(Box::new(move |rng| {
        let result = fll25::show(&f.pp, &f.selected, &f.session, rng)?;
        let durations = role_durations(&result);
        black_box(result);
        Ok(durations)
    }))
}

pub fn run(c: &Case) -> Res<()> {
    let f = fixture(c)?;
    let optimized = c.scheme == "fll25_opt";
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
    if c.experiment == "compare_holder_storage" {
        c.bytes(
            "Storage",
            "holder",
            f.shares[0].stored_bytes(),
            if optimized {
                "certified credential share plus Accept's retained G1 cache; shared key excluded"
            } else {
                "original credential share plus Accept's retained G1 cache"
            },
        );
        return Ok(());
    }
    let baseline = fll25::show(&f.pp, &f.selected, &f.session, &mut c.fixture_rng("proof"))?;
    fll25::verify(&f.pp, &f.session, &baseline.wire)?;
    if c.experiment == "compare_link_bytes" {
        let k = f.selected.len();
        c.bytes(
            "LinkBytes",
            "link",
            baseline.link_bytes(),
            "all private broadcasts and relays plus final presentation",
        );
        c.bytes(
            "LogicalBytes",
            "communication",
            baseline.logical_bytes(),
            "broadcast payloads once plus final presentation",
        );
        c.bytes(
            "ContextBytes",
            "verifier",
            f.session.request_bytes().len(),
            "identical request identifier nonce and disclosed attributes excluded",
        );
        c.bytes(
            "OneWayMessages",
            "communication",
            k + baseline.broadcasts.len() * (k - 1) + 1,
            "request links broadcast and relay links and final verifier link",
        );
        for (name, phase) in [
            ("RandomizerBroadcastBytes", BroadcastPhase::Randomizer),
            ("CommitmentBroadcastBytes", BroadcastPhase::Commitment),
            ("OpeningBroadcastBytes", BroadcastPhase::Opening),
            ("ResponseBroadcastBytes", BroadcastPhase::Response),
        ] {
            c.bytes(
                name,
                "communication",
                baseline
                    .broadcasts
                    .iter()
                    .filter(|message| message.phase == phase)
                    .map(|message| message.payload.len())
                    .sum(),
                "logical payloads in this broadcast phase",
            );
        }
        return Ok(());
    }
    if c.experiment == "compare_computation" {
        let mut operation = comparison(c)?;
        return c.sample_group(
            &[("PartSign", "holder"), ("Show", "host"), ("Total", "total")],
            move |rng| operation(rng),
        );
    }
    if c.experiment != "time_cost_table" {
        return Err("unsupported FLL25 experiment".into());
    }
    let (b, k, n) = (c.dim(1), c.dim(2), c.dim(3));
    c.bytes(
        "Presentation",
        "host",
        baseline.wire.len(),
        "actual encoded verifier presentation",
    );
    c.timed("Issue", "issuer", |rng| {
        let shares = issue(&f.pp, &f.key, &f.attrs, b, k, rng)?;
        Ok(shares.iter().map(Share::encode).collect::<Vec<_>>())
    })?;
    let share_wire = f.shares[0].encode();
    c.timed("Accept", "holder", |_rng| {
        accept(&f.pp, &share_wire, n, b, k, 0)
    })?;
    let metrics = if optimized {
        vec![("PartSign", "holder")]
    } else {
        vec![("PartSign", "holder"), ("Show", "host")]
    };
    c.sample_group(&metrics, |rng| {
        let result = fll25::show(&f.pp, &f.selected, &f.session, rng)?;
        let durations = role_durations(&result);
        black_box(result);
        Ok(durations[..metrics.len()].to_vec())
    })?;
    c.timed("Verify", "verifier", |_rng| {
        fll25::verify(&f.pp, &f.session, &baseline.wire)
    })?;
    if !optimized {
        c.timed("VerifyUnmerged", "verifier", |_rng| {
            fll25::verify(&f.pp, &f.session, &baseline.wire)
        })?;
    }
    Ok(())
}
