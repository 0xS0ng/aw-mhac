# AW-MHAC

This repository implements the protocols and experiments for **AW-MHAC: Accountable Weighted Multi-Holder Anonymous Credentials for the Internet of Things**.

## Implemented schemes

| Scheme | Implementation |
| --- | --- |
| AW-MHAC | Weighted multi-holder anonymous credentials, selective disclosure, tracing, and public audit verification. |
| FLL25 | Protocols 1 and 3 without private attributes. The second instance, FLL25 (opt.), adds its storage optimization, using BLS issuer certificates in G1. |
| FHLL26 | The BBS-BLS construction with one secure element; all stages, including the secure-element algorithm, run in software. |
| hinTS | Key generation, hints, public-key preprocessing, partial signing, aggregation, and verification, with the source-group assignment of its public implementation. |

All implementations use BLS12-381, canonical serialized inputs, subgroup checks, and shared arithmetic and hashing routines. The default hinTS instance has 16 real signers and a 32-point polynomial domain.

## Build and test

Use Rust **1.94.1**, pinned in `rust-toolchain.toml`, a C compiler for `blst`, and Python **3.11** for the scripts. The supplied figures used **3.11.4**. Install the plotting dependencies in an isolated Python environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r scripts/requirements.txt

cargo build --release --locked
cargo test --release --locked
cargo test --release --locked --features op-count -- --nocapture
```

`Cargo.lock` fixes the Rust dependencies. The `op-count` feature records group operations, MSM lengths, pairing terms, final exponentiations, hashes, and batch inversions. Timing runs use a separate default-feature release build with single-threaded `blst`. The figures use Arial; the configured fallbacks are Helvetica and Liberation Sans. Font substitutions can change text metrics and PDF bytes.

## Reproduce the experiments

The supplied `data/` directory contains the frozen paper measurements. Write new measurements to a separate run directory:

```sh
# Full paper experiment matrix.
scripts/run_all.sh --profile formal --out runs/formal

# A single experiment.
scripts/run_all.sh --profile formal --only vary_slots --out runs/vary-slots

# Short workflow checks; these results are not paper measurements.
scripts/run_all.sh --profile smoke --out runs/smoke
```

The runner builds the release worker, saves CSVs and resumable checkpoints, and resumes compatible completed cases on restart. Sweep selections include their canonical time-table dependency when needed. Use AC power and a quiet machine for timing. The wrapper inhibits sleep where the operating system supports it.

Operations run single-threaded after at least **1 second and 10 warmup calls**. Results report the median, P25, and P75 of **100 samples**, or **1000 samples for unit costs**. Operations whose warmup median exceeds one second use 20 samples. Warmup and measured calls use independent random streams; CSVs retain warmup metadata and the median of each consecutive block of up to 100 measured calls.

The master seed is **42**, with stream encodings specified in `benches/benchmark_config.txt`. Defaults are N=32 slots, b=16 registered holders, k=8 participants, n=10 attributes, three disclosed attributes, unit weights, T=k, and layout 0. Registration and participant selections are shared across matching configurations and schemes. The first selected participant is the host. Audit presentations use the holders of the k largest registered slots. Matching default sweep points reuse their `time_cost_table.csv` source rows, identified in the CSV notes.

AW-MHAC HKeyGen includes its holder cache; hinTS HKeyGen includes key generation and hint generation. FLL25 Accept caches the attribute product and its storage includes that cache. The AW-MHAC and hinTS time-table Show rows measure aggregation after receiving the partial signatures, excluding the host's own partial signing. Computation comparisons include that signature in the host's time, average the non-host holders' times, and sum all participants' times within each sample before taking the median. Comparison instances rotate within each repetition.

The paper's primitive-operation prices come from **`data/sentinel_start/unit_costs.csv`**. The additional `audit_vs_registered.csv` records the b-dependent Trace measurements and issuance costs discussed in the text. Optional `aggregation_checks` and `sensitivity_layouts` cases remain available through an explicit `--only` selection; they are outside the default matrix and have no supplied frozen CSVs.

## Reproduce the figures and Table IV

These commands read the frozen CSVs and do not run benchmarks:

```sh
python3 scripts/plot.py --data data --out rebuilt-figures
python3 scripts/table_iv.py --data data
```

The first command generates all 12 PDF panels. The second prints Table IV as Markdown. Bar labels and Table IV round timing values directly from their decimal CSV strings to three significant digits, with round-half-up; byte counts remain integers.

| Paper item | Frozen CSV in `data/` | Selection | PDF output |
| --- | --- | --- | --- |
| Fig. 6(a) | `time_cost_table.csv` | AW-MHAC Setup, HKeyGen, Issue, Accept, PartSign, Show, ordinary Verify, Trace, Judge | `fig_alg_time.pdf` |
| Fig. 6(b) | `default_parameters.csv` | AW-MHAC Parameters, Rho, Credential, PartialSignature, Presentation, TraceOutput bytes | `fig_alg_size.pdf` |
| Fig. 7(a) | `vary_slots.csv` | AW-MHAC PartSign, Show, Verify versus N | `fig_growth_slots.pdf` |
| Fig. 7(b) | `vary_attributes.csv` | AW-MHAC PartSign, Show, Verify versus n | `fig_growth_attrs.pdf` |
| Fig. 8(a) | `vary_participants.csv` | AW-MHAC PartSign, Show, Verify versus k | `fig_pres_holders.pdf` |
| Fig. 8(b) | `vary_weight_bits.csv` | AW-MHAC PartSign, Show, Verify versus weight bit length | `fig_pres_weights.pdf` |
| Fig. 9(a) | `vary_slots.csv` | AW-MHAC HKeyGen, Issue, Accept versus N | `fig_issue_slots.pdf` |
| Fig. 9(b) | `audit_vs_participants.csv` | Audit-presentation Verify, Trace, Judge versus k | `fig_audit.pdf` |
| Fig. 10(a) | `compare_computation.csv` | `Total/total`, all four comparison instances | `fig_cmp_comp.pdf` |
| Fig. 10(b) | `compare_link_bytes.csv` | `LinkBytes/link`, all four comparison instances | `fig_cmp_comm.pdf` |
| Fig. 11(a) | `compare_computation.csv` | `PartSign/holder`, the mean non-host holder time | `fig_cmp_holder.pdf` |
| Fig. 11(b) | `compare_holder_storage.csv` | `Storage/holder`, AW-MHAC, FLL25, FLL25 (opt.), FHLL26 | `fig_cmp_storage.pdf` |
| Table IV | `time_cost_table.csv` | FHLL26, FLL25, hinTS, AW-MHAC at the default parameters; ordinary `Verify/verifier` | Markdown on stdout |

Time plots use milliseconds; communication, output size, and storage use bytes. Fig. 11(b) draws FHLL26 for the coincident 32 B FHLL26/hinTS storage series. The ordinary and audit Verify rows in the time table are distinct; the audit sweeps reuse the latter. Table IV excludes the additional FLL25 (opt.) instance and displays a dash for algorithms not reported there.

## Reference environment

The recorded measurements used a MacBook Pro with an Apple M2 Pro, **10 CPU cores** (6 performance and 4 efficiency), **32 GB RAM**, and **macOS 14.6.1**. The compiler was **Rust/Cargo 1.94.1**. Main arithmetic dependencies are **blstrs 0.7.1**, **blst 0.3.17** (`no-threads`), **ff 0.13.1**, and **group 0.13.0**. Plotting used **Python 3.11.4**, **Matplotlib 3.8.4**, and **NumPy 2.2.6**. See `data/environment.md` for the compact version record.

## Directory layout

| Path | Contents |
| --- | --- |
| `src/` | Protocols, baselines, canonical encodings, transcripts, and shared arithmetic. |
| `tests/` | Correctness, rejection, serialization, and operation-count tests. |
| `benches/` | Benchmark adapters, sampling, and deterministic input configuration. |
| `scripts/` | Experiment runner, plot generator, Table IV generator, and Python requirements. |
| `data/` | Frozen paper CSVs and the reference environment. |
| `figures/` | The 12 paper PDF panels. |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` | Package configuration, locked dependencies, and pinned compiler. |
| `runs/` | New measurement outputs; ignored by Git. |

## License

This project is licensed under the Apache License 2.0. See `LICENSE`.
