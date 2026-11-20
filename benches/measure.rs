//! Single-threaded measurement worker. The runner owns the matrix and checkpoints.

mod aw_mhac_cases;
mod fhll26_cases;
mod fll25_cases;
mod hints_cases;
mod sampling;

use std::{hint::black_box, sync::OnceLock, time::Instant};

use aw_mhac::{
    common::{Res, Rng, F, G1, G2},
    hash::{hash_to_g1, hash_to_g2},
    pairing::{g1_exp, g1_msm, g2_exp, pair_product},
    poly::fft,
};
use ff::Field;
use group::Group;
use rand::{seq::SliceRandom, RngCore, SeedableRng};
use sha2::{Digest, Sha256};

use sampling::{Metric, Task};

fn master_seed() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| {
        include_str!("benchmark_config.txt")
            .lines()
            .find_map(|line| line.strip_prefix("master_seed="))
            .expect("master seed missing")
            .parse()
            .expect("invalid master seed")
    })
}

fn seeded_rng(domain: &str, fields: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Rng {
    let mut hash = Sha256::new();
    hash.update(master_seed().to_be_bytes());
    let mut add = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    };
    add(domain.as_bytes());
    for field in fields {
        add(field.as_ref());
    }
    Rng::from_seed(hash.finalize().into())
}

#[derive(Clone)]
struct Case {
    experiment: String,
    scheme: String,
    dims: [String; 7],
    warmup: usize,
    runs: usize,
    formal: bool,
}

impl Case {
    fn parse(args: &[String]) -> Res<Self> {
        if args.len() != 12 {
            return Err(
                "measure requires EXPERIMENT SCHEME N b k n h weight_bits layout warmup runs profile"
                    .into(),
            );
        }
        let integer = |index: usize| {
            args[index]
                .parse::<usize>()
                .map_err(|_| format!("invalid integer {}", args[index]))
        };
        let formal = match args[11].as_str() {
            "formal" => true,
            "smoke" => false,
            _ => return Err("invalid profile".into()),
        };
        let runs = integer(10)?;
        if runs == 0 {
            return Err("runs must be positive".into());
        }
        let case = Self {
            experiment: args[0].clone(),
            scheme: args[1].clone(),
            dims: std::array::from_fn(|i| args[i + 2].clone()),
            warmup: integer(9)?,
            runs,
            formal,
        };
        if case.experiment != "unit_costs"
            && (case.dim(2) == 0 || case.dim(2) > case.dim(1) || case.dim(4) > case.dim(3))
        {
            return Err("invalid benchmark participant or attribute dimensions".into());
        }
        Ok(case)
    }

    fn dim(&self, i: usize) -> usize {
        self.dims[i].parse().unwrap_or(0)
    }

    fn numeric_rng<const M: usize>(&self, domain: &str, indices: [usize; M]) -> Rng {
        seeded_rng(domain, indices.map(|i| (self.dim(i) as u64).to_be_bytes()))
    }

    fn registered_slots(&self) -> Vec<usize> {
        let mut slots = (0..self.dim(0)).collect::<Vec<_>>();
        slots.shuffle(&mut self.numeric_rng("registered slots", [0, 1, 6]));
        slots.truncate(self.dim(1));
        slots
    }

    fn participants(&self) -> Vec<usize> {
        let mut holders = (0..self.dim(1)).collect::<Vec<_>>();
        holders.shuffle(&mut self.numeric_rng("participants", [1, 2, 6]));
        holders.truncate(self.dim(2));
        holders
    }

    fn weights(&self) -> Res<Vec<u32>> {
        let (slots, bits) = (self.dim(0), self.dim(5));
        if !(1..=32).contains(&bits) {
            return Err("invalid weight bit length".into());
        }
        let mut rng = self.numeric_rng("weights", [0, 5, 6]);
        let mask = u32::MAX >> (32 - bits);
        let top = 1 << (bits - 1);
        Ok((0..slots).map(|_| (rng.next_u32() & mask) | top).collect())
    }

    fn fixture_rng(&self, domain: &str) -> Rng {
        if matches!(domain, "attributes" | "request") {
            return self.numeric_rng(domain, []);
        }
        seeded_rng(
            "fixture",
            std::iter::once(self.scheme.as_str())
                .chain(self.dims[..6].iter().map(String::as_str))
                .chain([domain]),
        )
    }

    fn operation_rng(&self, metrics: &[Metric<'_>], phase: &str) -> Rng {
        seeded_rng(
            "measurement",
            std::iter::once(self.scheme.as_str())
                .chain(self.dims[..6].iter().map(String::as_str))
                .chain(metrics.iter().flat_map(|&(name, role)| [name, role]))
                .chain([phase]),
        )
    }

    fn for_scheme(&self, scheme: &str) -> Self {
        let mut case = self.clone();
        case.scheme = scheme.into();
        if matches!(scheme, "fll25" | "fll25_opt") {
            case.dims[0] = "-".into();
        }
        case
    }

    fn emit(&self, algorithm: &str, role: &str, fields: [&str; 10]) {
        let dim = |i: usize| match self.dims[i].as_str() {
            "-" => "",
            value => value,
        };
        let row = std::iter::once(self.scheme.as_str())
            .chain([algorithm, role])
            .chain((0..6).map(dim))
            .chain(fields[..6].iter().copied())
            .chain([dim(6)])
            .chain(fields[6..].iter().copied())
            .map(csv)
            .collect::<Vec<_>>();
        println!("{}", row.join(","));
    }

    fn bytes(&self, algorithm: &str, role: &str, bytes: usize, note: &str) {
        self.emit(
            algorithm,
            role,
            ["", "", "", "", &bytes.to_string(), note, "", "", "", ""],
        );
    }

    fn timeout(&self, algorithm: &str, role: &str, note: &str) {
        self.emit(
            algorithm,
            role,
            ["0", "", "", "", "", note, "0", "0", "false", ""],
        );
    }

    fn timed<T>(
        &self,
        algorithm: &str,
        role: &str,
        mut call: impl FnMut(&mut Rng) -> Res<T>,
    ) -> Res<()> {
        self.sample_group(&[(algorithm, role)], |rng| {
            let start = Instant::now();
            let result = call(rng)?;
            let elapsed = start.elapsed();
            black_box(result);
            Ok(vec![elapsed])
        })
    }

    fn sample_group(
        &self,
        names: &[Metric<'_>],
        call: impl FnMut(&mut Rng) -> Res<Vec<std::time::Duration>>,
    ) -> Res<()> {
        sampling::rotate(vec![Task::new(self.clone(), names, Box::new(call))])
    }
}

fn csv(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn attrs(n: usize, rng: &mut Rng) -> Vec<F> {
    (0..n).map(|_| F::random(&mut *rng)).collect()
}

fn bits_bytes(rng: &mut Rng) -> [u8; 32] {
    let mut bytes = [0; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn disclosure(a: &[F], h: usize) -> Vec<Option<F>> {
    a.iter()
        .enumerate()
        .map(|(i, &x)| (i < a.len() - h).then_some(x))
        .collect()
}

fn unit_costs(c: &Case) -> Res<()> {
    let mut rng = c.fixture_rng("primitive operands");
    let points: Vec<_> = (0..512)
        .map(|_| g1_exp(G1::generator(), F::random(&mut rng)))
        .collect();
    let exps = attrs(1024, &mut rng);
    let g2: Vec<_> = (0..5)
        .map(|_| g2_exp(G2::generator(), F::random(&mut rng)))
        .collect();
    let pairs: Vec<_> = points.iter().copied().zip(g2.iter().copied()).collect();
    c.timed("G1Exponent", "primitive", |_| {
        Ok(g1_exp(black_box(points[0]), black_box(exps[0])))
    })?;
    c.timed("G2Exponent", "primitive", |_| {
        Ok(g2_exp(black_box(g2[0]), black_box(exps[0])))
    })?;
    for (name, terms) in [("Pairing", 1), ("Pairing5", 5)] {
        c.timed(name, "primitive", |_| {
            Ok(pair_product(black_box(&pairs[..terms])))
        })?;
    }
    let m = [0u8; 128];
    c.timed("HashToG1", "primitive", |_| {
        Ok(hash_to_g1(
            black_box(&m),
            b"Unit-Cost-BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ))
    })?;
    c.timed("HashToG2", "primitive", |_| {
        Ok(hash_to_g2(
            black_box(&m),
            b"Unit-Cost-BLS12381G2_XMD:SHA-256_SSWU_RO_",
        ))
    })?;
    for len in [16, 32, 64, 128, 256, 512] {
        c.timed(&format!("G1Msm{len}"), "primitive", |_| {
            Ok(g1_msm(black_box(&points[..len]), black_box(&exps[..len])))
        })?;
    }
    for len in [64, 128, 256, 512, 1024] {
        let mut values = exps[..len].to_vec();
        c.sample_group(&[(&format!("Fft{len}"), "primitive")], |_| {
            values.copy_from_slice(&exps[..len]);
            let start = Instant::now();
            fft(black_box(&mut values), false);
            Ok(vec![start.elapsed()])
        })?;
    }
    Ok(())
}

const COMPARISON_METRICS: [Metric<'static>; 3] =
    [("PartSign", "holder"), ("Show", "host"), ("Total", "total")];

fn run_comparison(case: &Case) -> Res<()> {
    let aw = case.for_scheme("aw_mhac");
    let fll = case.for_scheme("fll25");
    let fll_opt = case.for_scheme("fll25_opt");
    let hints = case.for_scheme("hints");
    let aw_sampler = aw_mhac_cases::comparison(&aw)?;
    let fll_sampler = fll25_cases::comparison(&fll)?;
    let fll_opt_sampler = fll25_cases::comparison(&fll_opt)?;
    let hints_sampler = hints_cases::comparison(&hints)?;
    sampling::rotate(vec![
        Task::new(aw, &COMPARISON_METRICS, aw_sampler),
        Task::new(fll, &COMPARISON_METRICS, fll_sampler),
        Task::new(fll_opt, &COMPARISON_METRICS, fll_opt_sampler),
        Task::new(hints, &COMPARISON_METRICS, hints_sampler),
    ])
}

#[cfg(feature = "op-count")]
fn encode_indices(indices: &[usize]) -> String {
    indices
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(feature = "op-count")]
fn diagnostics(c: &Case) -> Res<()> {
    let cases = if c.scheme == "comparison" {
        ["aw_mhac", "fll25", "fll25_opt", "hints"]
            .map(|scheme| c.for_scheme(scheme))
            .to_vec()
    } else {
        vec![c.clone()]
    };
    for case in cases {
        if case.scheme == "aw_mhac" {
            aw_mhac_cases::diagnostics(&case)?;
            continue;
        }
        let base = usize::from(case.scheme == "hints");
        let members = (base..base + case.dim(1)).collect::<Vec<_>>();
        let storage_or_units = matches!(
            case.experiment.as_str(),
            "unit_costs" | "compare_holder_storage"
        );
        let selected = if storage_or_units {
            Vec::new()
        } else {
            case.participants()
        };
        let slots = selected.iter().map(|&i| members[i]).collect::<Vec<_>>();
        let purpose = if storage_or_units {
            "not_applicable"
        } else {
            "presentation"
        };
        println!(
            "{},{purpose},{},{},{},,,,,,,,,,,",
            case.scheme,
            encode_indices(&members),
            encode_indices(&selected),
            encode_indices(&slots),
        );
    }
    Ok(())
}

fn run() -> Res<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let inspect = args.last().is_some_and(|arg| arg == "--diagnostics");
    if inspect {
        args.pop();
    }
    let c = Case::parse(&args)?;
    if inspect {
        #[cfg(feature = "op-count")]
        return diagnostics(&c);
        #[cfg(not(feature = "op-count"))]
        return Err("participant diagnostics require the op-count build".into());
    }
    if c.experiment == "unit_costs" {
        return unit_costs(&c);
    }
    match c.scheme.as_str() {
        "aw_mhac" => aw_mhac_cases::run(&c),
        "fll25" | "fll25_opt" => fll25_cases::run(&c),
        "fhll26" => fhll26_cases::run(&c),
        "hints" => hints_cases::run(&c),
        "comparison" => run_comparison(&c),
        _ => Err("unknown scheme".into()),
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::from(if e.starts_with("blocked:") { 3 } else { 1 })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case() -> Case {
        Case::parse(
            &[
                "time_cost_table",
                "aw_mhac",
                "32",
                "16",
                "8",
                "10",
                "7",
                "1",
                "0",
                "10",
                "100",
                "formal",
            ]
            .map(str::to_string),
        )
        .unwrap()
    }

    #[test]
    fn layout_streams_ignore_the_non_layout_fields() {
        let original = case();
        let mut modified = original.clone();
        modified.experiment = "vary_weight_bits".into();
        modified.scheme = "comparison".into();
        modified.dims[3] = "50".into();
        modified.dims[4] = "47".into();
        modified.dims[5] = "32".into();
        assert_eq!(original.registered_slots(), modified.registered_slots());
        assert_eq!(original.participants(), modified.participants());
        assert_eq!(original.weights().unwrap(), vec![1; 32]);
        assert!(modified
            .weights()
            .unwrap()
            .iter()
            .all(|&weight| weight >= 1 << 31));
        modified.dims[0] = "64".into();
        assert_eq!(original.participants(), modified.participants());
    }

    #[test]
    fn sampling_stream_does_not_depend_on_warmup_draws() {
        let original = case();
        let labels = [("Show", "host")];
        let formal = original.operation_rng(&labels, "samples").next_u64();
        let mut warmup = original.operation_rng(&labels, "warmup");
        assert_ne!(warmup.next_u64(), formal);
        for _ in 0..100 {
            black_box(warmup.next_u64());
        }
        assert_eq!(
            original.operation_rng(&labels, "samples").next_u64(),
            formal
        );
    }
}
