#!/usr/bin/env python3
"""Run reproducible single-thread benchmark cases with atomic CSV checkpoints."""

import argparse
import csv
import fcntl
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone


COLUMNS = (
    "scheme", "algorithm", "role", "N", "b", "k", "n", "h", "weight_bits",
    "runs", "median_ms", "p25_ms", "p75_ms", "bytes", "note", "layout",
    "warmup_runs", "warmup_s", "warmup_stable", "block_medians_ms",
)
DIMENSIONS = ("N", "b", "k", "n", "h", "weight_bits", "layout")
SCHEMES = ("aw_mhac", "fll25", "fhll26", "hints", "fll25_opt")
COMPARISON_SCHEMES = ("aw_mhac", "fll25", "hints", "fll25_opt")
EXPERIMENTS = (
    "unit_costs", "time_cost_table", "default_parameters", "aggregation_checks", "vary_slots", "vary_attributes",
    "vary_participants", "vary_weight_bits", "audit_vs_participants", "audit_vs_registered", "compare_computation",
    "compare_link_bytes", "compare_holder_storage", "sensitivity_layouts",
)
OPTIONAL_EXPERIMENTS = frozenset(("aggregation_checks", "sensitivity_layouts"))
DEFAULT_EXPERIMENTS = tuple(name for name in EXPERIMENTS if name not in OPTIONAL_EXPERIMENTS)
TRIO = {("PartSign", "holder"), ("Show", "host"), ("Verify", "verifier")}
EXPECTED_ROWS = {
    "default_parameters": {
        ("Parameters", "setup"), ("Rho", "holder"), ("Credential", "holder"),
        ("Record", "issuer"), ("PartialSignature", "holder"), ("Presentation", "host"),
        ("TraceOutput", "auditor"), ("Storage", "holder"),
    },
    "vary_slots": TRIO | {("HKeyGen", "holder"), ("Issue", "issuer"), ("Accept", "host")},
    "vary_attributes": TRIO,
    "vary_participants": TRIO,
    "vary_weight_bits": TRIO,
    "audit_vs_participants": {("Verify", "verifier"), ("Trace", "auditor"), ("Judge", "judge")},
    "audit_vs_registered": {("Verify", "verifier"), ("Trace", "auditor"), ("Judge", "judge"), ("Issue", "issuer"), ("Accept", "host")},
    "aggregation_checks": {("ShowWithPartialChecks", "host")},
    "compare_computation": {("PartSign", "holder"), ("Show", "host"), ("Total", "total")},
    "compare_link_bytes": {("LinkBytes", "link"), ("LogicalBytes", "communication"),
                           ("ContextBytes", "verifier"), ("OneWayMessages", "communication")},
    "compare_holder_storage": {("Storage", "holder")},
    "sensitivity_layouts": TRIO,
    "unit_costs": {(name, "primitive") for name in (
        "G1Exponent", "G2Exponent", "Pairing", "Pairing5", "HashToG1", "HashToG2",
        *(f"G1Msm{size}" for size in (16, 32, 64, 128, 256, 512)),
        *(f"Fft{size}" for size in (64, 128, 256, 512, 1024)),
    )},
}
TIME_ROWS = {
    "aw_mhac": {
        ("Setup", "setup"), ("HKeyGen", "holder"), ("Issue", "issuer"), ("Accept", "host"),
        ("PartSign", "holder"), ("Show", "host"), ("Verify", "verifier"),
        ("VerifyUnmerged", "verifier"), ("Verify", "audit_verifier"),
        ("Trace", "auditor"), ("Judge", "judge"), ("HolderPrecompute", "holder"),
    },
    "fhll26": {
        ("HKeyGen", "device"), ("Issue", "issuer"), ("Accept", "host"),
        ("PartSign", "secure_element"), ("Show", "host"), ("Verify", "verifier"),
        ("ShowUser1", "host"), ("VerifyUnmerged", "verifier"),
    },
    "fll25": {
        ("Issue", "issuer"), ("Accept", "holder"), ("PartSign", "holder"),
        ("Show", "host"), ("Verify", "verifier"), ("VerifyUnmerged", "verifier"),
    },
    "hints": {
        ("HKeyGen", "holder"), ("Issue", "issuer"), ("PartSign", "holder"),
        ("Show", "host"), ("Verify", "verifier"), ("VerifyUnmerged", "verifier"),
    },
    "fll25_opt": {("Issue", "issuer"), ("Accept", "holder"), ("PartSign", "holder"), ("Verify", "verifier")},
}
for _scheme in ("fll25", "fll25_opt", "fhll26", "hints"):
    TIME_ROWS[_scheme].add(("Presentation", "host"))
FLL25_BROADCAST_ROWS = {
    ("RandomizerBroadcastBytes", "communication"), ("CommitmentBroadcastBytes", "communication"),
    ("OpeningBroadcastBytes", "communication"), ("ResponseBroadcastBytes", "communication"),
}
BYTE_ROWS = {name for name, _ in EXPECTED_ROWS["default_parameters"]} | {
    "LinkBytes", "LogicalBytes", "ContextBytes", "OneWayMessages",
    *(name for name, _ in FLL25_BROADCAST_ROWS),
}


def expected_rows(case):
    if case.experiment == "time_cost_table":
        return TIME_ROWS[case.scheme]
    rows = EXPECTED_ROWS[case.experiment]
    if case.experiment == "compare_link_bytes" and case.scheme in ("fll25", "fll25_opt"):
        return rows | FLL25_BROADCAST_ROWS
    return rows


def expected_identities(case):
    schemes = COMPARISON_SCHEMES if case.scheme == "comparison" else (case.scheme,)
    return {(scheme, algorithm, role) for scheme in schemes for algorithm, role in expected_rows(case)}


@dataclass(frozen=True)
class Case:
    experiment: str
    scheme: str
    N: str = "32"
    b: str = "16"
    k: str = "8"
    n: str = "10"
    h: str = "7"
    weight_bits: str = "1"
    layout: str = "0"

    def values(self):
        return (self.experiment, self.scheme, *(getattr(self, name) for name in DIMENSIONS))

    def key(self):
        return hashlib.sha256("\0".join(self.values()).encode()).hexdigest()[:24]

    def label(self):
        parameters = " ".join(f"{name}={getattr(self, name)}" for name in DIMENSIONS)
        return f"{self.experiment} {self.scheme} {parameters}"


def matrix(include_optional=False):
    cases = [Case("unit_costs", "all", *(["-"]*6))]
    for scheme in SCHEMES:
        cases.append(Case("time_cost_table", scheme,
                          N="-" if scheme in ("fll25", "fll25_opt", "fhll26") else "32",
                          b="1" if scheme == "fhll26" else "16",
                          k="1" if scheme == "fhll26" else "8"))
    cases.append(Case("default_parameters", "aw_mhac"))
    cases.extend(Case("aggregation_checks", scheme) for scheme in ("aw_mhac", "hints"))
    cases.extend(Case("vary_slots", "aw_mhac", N=str(N)) for N in (16, 32, 64, 128, 256, 512))
    cases.extend(Case("vary_attributes", "aw_mhac", n=str(n), h=str(n-3)) for n in (5, 10, 20, 30, 40, 50))
    cases.extend(Case("vary_participants", "aw_mhac", k=str(k)) for k in (2, 4, 8, 16))
    cases.extend(Case("vary_weight_bits", "aw_mhac", weight_bits=str(bits)) for bits in (1, 4, 8, 16, 32))
    cases.extend(Case("audit_vs_participants", "aw_mhac", k=str(k)) for k in (2, 4, 8, 16))
    cases.extend(Case("audit_vs_registered", "aw_mhac", b=str(b)) for b in (8, 12, 16, 20, 24, 28, 32))
    cases.extend(Case("compare_computation", "comparison", k=str(k)) for k in (2, 4, 8, 16))
    for k in (2, 4, 8, 16):
        for scheme in COMPARISON_SCHEMES:
            cases.append(Case("compare_link_bytes", scheme, N="-" if scheme in ("fll25", "fll25_opt") else "32", k=str(k)))
    for n in (5, 10, 20, 30, 40, 50):
        for scheme in SCHEMES:
            cases.append(Case("compare_holder_storage", scheme,
                              N="-" if scheme in ("fll25", "fll25_opt", "fhll26") else "32",
                              b="1" if scheme == "fhll26" else "16",
                              k="1" if scheme == "fhll26" else "8", n=str(n), h=str(n-3)))
    cases.extend(Case("sensitivity_layouts", "aw_mhac", k=str(k), layout=str(layout))
                 for k in (8, 16) for layout in (1, 2, 3, 4, 5))
    assert len(cases) == len({case.key() for case in cases}) == 101
    return cases if include_optional else [case for case in cases if case.experiment not in OPTIONAL_EXPERIMENTS]


def alias_source(case):
    defaults = dict(N="32", b="16", k="8", n="10", h="7", weight_bits="1", layout="0")
    if case.scheme != "aw_mhac" or any(getattr(case, name) != value for name, value in defaults.items()):
        return None
    if case.experiment not in ("vary_slots", "vary_attributes", "vary_participants", "vary_weight_bits", "audit_vs_participants", "audit_vs_registered"):
        return None
    return Case("time_cost_table", "aw_mhac")


def aliases(case):
    if alias_source(case) is None:
        return {}
    return {(algorithm, role): (algorithm, "audit_verifier" if case.experiment in ("audit_vs_participants", "audit_vs_registered") and algorithm == "Verify" else role)
            for algorithm, role in expected_rows(case)}


def parse_selector(text):
    output = {}
    for clause in text.split(","):
        key, separator, value = clause.partition("=")
        key = key.strip().replace("weight-bits", "weight_bits")
        if not separator or key not in ("experiment", "scheme", *DIMENSIONS) or not value.strip():
            raise argparse.ArgumentTypeError(f"invalid selector {clause!r}; expected key=value")
        if key in output:
            raise argparse.ArgumentTypeError(f"duplicate selector key {key}")
        output[key] = value.strip()
    return output


def matches(case, selector):
    return all((case.scheme == "comparison" and key == "scheme" and value in COMPARISON_SCHEMES)
               or getattr(case, key) == value for key, value in selector.items())


def comma_options(items):
    return {value.strip() for item in items for value in item.split(",") if value.strip()}


def selected_cases(args):
    selectors = args.select + args.repeat
    explicit_experiments = comma_options(args.only)
    experiments = explicit_experiments or set(DEFAULT_EXPERIMENTS)
    if not explicit_experiments:
        experiments.update(selector["experiment"] for selector in selectors
                           if selector.get("experiment") in OPTIONAL_EXPERIMENTS)
    unknown = experiments - set(EXPERIMENTS)
    if unknown:
        raise ValueError("unknown experiments: " + ", ".join(sorted(unknown)))
    schemes = comma_options(args.scheme)
    if schemes - set(SCHEMES) - {"all", "comparison"}:
        raise ValueError("unknown schemes: " + ", ".join(sorted(schemes - set(SCHEMES) - {"all", "comparison"})))
    catalog = matrix(include_optional=bool(experiments.intersection(OPTIONAL_EXPERIMENTS)))
    cases = [case for case in catalog
             if case.experiment in experiments and (not schemes or case.scheme in schemes
                 or (case.scheme == "comparison" and schemes.intersection(COMPARISON_SCHEMES)))
             and (not selectors or any(matches(case, selector) for selector in selectors))]
    if not cases:
        raise ValueError("no benchmark cases match the requested filters")
    for selector in selectors:
        if not any(matches(case, selector) for case in cases):
            raise ValueError(f"selector matches no selected case: {selector}")
    needed = {alias_source(case) for case in cases if alias_source(case) is not None}
    chosen = set(cases) | needed
    return [case for case in catalog if case in chosen]


def configuration(args, case):
    formal = args.profile == "formal"
    warmup = args.warmup if args.warmup is not None else 10
    standard_runs = args.runs if args.runs is not None else (100 if formal else 3)
    unit_runs = args.unit_runs if args.unit_runs is not None else (1000 if formal else 10)
    return warmup, unit_runs if case.experiment == "unit_costs" else standard_runs


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def command_output(command, cwd=None):
    try:
        result = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=30, check=False)
        return result.stdout.strip() if result.returncode == 0 else "unavailable\n" + result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return "unavailable\n" + str(error)


def power_state():
    if platform.system() == "Darwin":
        state = command_output(["pmset", "-g", "batt"])
        return re.sub(r"\s+\(id=\d+\)", "", state)
    directory = Path("/sys/class/power_supply")
    if directory.exists():
        values = []
        for item in sorted(directory.iterdir()):
            for name in ("type", "status", "capacity", "online"):
                path = item / name
                if path.is_file():
                    values.append(f"{item.name}/{name}={path.read_text().strip()}")
        return "\n".join(values) or "unavailable"
    return "unavailable"


def load_state():
    try:
        return ", ".join(f"{value:.3f}" for value in os.getloadavg())
    except (OSError, AttributeError):
        return "unavailable"


def atomic_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def fingerprint(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def environment(root, args, cases, binary):
    if platform.system() == "Darwin":
        hardware = command_output(["system_profiler", "SPHardwareDataType"])
        # Serial numbers and hardware UUIDs are not needed for the experiment.
        hardware = "\n".join(line for line in hardware.splitlines()
                             if not any(key in line for key in (
                                 "Model Identifier", "Model Number", "Serial Number", "Hardware UUID",
                                 "Provisioning UDID", "Activation Lock",
                             )))
        memory = command_output(["sysctl", "-n", "hw.memsize"])
        if not memory.isdecimal():
            memory = next((line.strip().split(":", 1)[1].strip() for line in hardware.splitlines()
                           if line.strip().startswith("Memory:")), "unavailable")
        os_version = command_output(["sw_vers"])
    else:
        hardware = command_output(["lscpu"])
        memory = command_output(["getconf", "_PHYS_PAGES"]) + " pages; page bytes=" + command_output(["getconf", "PAGE_SIZE"])
        os_version = platform.platform()
    sections = [
        "# Benchmark environment", f"UTC {utc_now()}",
        f"Profile {args.profile}, selected cases {len(cases)}.",
        "```text\n" + hardware + "\n```", "Memory\n\n```text\n" + memory + "\n```",
        "Operating system\n\n```text\n" + os_version + "\n```",
        "Compiler\n\n```text\n" + command_output(["rustc", "-Vv"], root) + "\n```",
        "Cargo\n\n```text\n" + command_output(["cargo", "-V"], root) + "\n```",
        "Dependencies and features\n\n```text\n" + command_output([
            "cargo", "tree", "--locked", "--edges", "features", "--prefix", "none",
            "--format", "{p} features=[{f}]"], root).replace(str(root), ".") + "\n```",
        "Commit\n\n```text\n" + command_output(["git", "rev-parse", "HEAD"], root) + "\n```",
        "Working tree\n\n```text\n" + command_output(["git", "status", "--short"], root) + "\n```",
        f"Cargo.lock SHA-256 {fingerprint(root / 'Cargo.lock')}",
        f"Measurement executable SHA-256 {fingerprint(binary)}",
        "Invocation\n\n```text\n" + shlex.join([Path(sys.argv[0]).name, *sys.argv[1:]]) + "\n```",
        "Sleep prevention\n\n" + os.environ.get("BENCHMARK_SLEEP_PREVENTION", "unavailable"),
        "Power state\n\n```text\n" + power_state() + "\n```", "System load\n\n" + load_state(),
        "Each trace evaluation is limited to 600 seconds by the Rust implementation.\n"
        "The formal profile uses 20 repetitions for points slower than one second, with a CSV note.\n"
        "Smoke-profile timings are workflow checks and are excluded from paper results.",
    ]
    return "\n\n".join(sections) + "\n"


def row_key(row):
    return tuple(row[column] for column in ("scheme", "algorithm", "role", *DIMENSIONS))


def failure_kind(row):
    note = row["note"].lower()
    return "blocked" if "blocked" in note else "timed_out" if ("timeout" in note or "timed out" in note) else None


def validate_rows(case, stdout, exit_code, args):
    records = list(csv.reader(io.StringIO(stdout)))
    if not records:
        raise ValueError("measurement child returned no CSV rows")
    rows, seen = [], set()
    for values in records:
        if not values:
            continue
        if len(values) != len(COLUMNS):
            raise ValueError(f"expected {len(COLUMNS)} CSV columns, received {len(values)}")
        row = dict(zip(COLUMNS, values))
        schemes = COMPARISON_SCHEMES if case.scheme == "comparison" else (case.scheme,)
        if row["scheme"] not in schemes:
            raise ValueError(f"scheme mismatch: {row['scheme']} instead of {schemes}")
        if not row["algorithm"] or not row["role"]:
            raise ValueError("algorithm and role must be populated")
        for name in DIMENSIONS:
            expected = getattr(case, name)
            if case.scheme == "comparison" and row["scheme"] in ("fll25", "fll25_opt") and name == "N":
                expected = "-"
            actual = "" if row[name] == "-" else row[name]
            if actual != ("" if expected == "-" else expected):
                raise ValueError(f"{name} mismatch: {row[name]!r} instead of {expected!r}")
            row[name] = actual
        key = row_key(row)
        if key in seen:
            raise ValueError(f"duplicate algorithm/role row: {key}")
        seen.add(key)
        failure = failure_kind(row)
        stats = [row[name] for name in ("median_ms", "p25_ms", "p75_ms")]
        timing_metadata = ("warmup_runs", "warmup_s", "warmup_stable", "block_medians_ms")
        if failure:
            if any(stats) or row["bytes"]:
                raise ValueError("blocked/timeout rows cannot contain statistics or byte counts")
        elif any(stats):
            if not all(stats) or not row["runs"] or int(row["runs"]) < 1:
                raise ValueError("timing row lacks quartiles or repetition count")
            median, p25, p75 = map(float, stats)
            if not all(math.isfinite(value) and value >= 0 for value in (median, p25, p75)):
                raise ValueError("timing quartiles must be finite and nonnegative")
            if not p25 <= median <= p75:
                raise ValueError("timing quartiles are out of order")
            minimum_warmup, requested = configuration(args, case)
            repetitions = int(row["runs"])
            if repetitions != requested and not (
                args.profile == "formal" and case.experiment != "unit_costs" and requested >= 20
                and repetitions == 20 and "slow" in row["note"].lower()
            ):
                raise ValueError(f"unexplained repetition count {repetitions}, expected {requested}")
            if row["bytes"]:
                raise ValueError("timing rows cannot contain byte counts")
            if int(row["warmup_runs"]) < max(10, minimum_warmup):
                raise ValueError("timed row has fewer than the minimum warmup iterations")
            warmup_s = float(row["warmup_s"])
            if not math.isfinite(warmup_s) or warmup_s < 1:
                raise ValueError("timed row has less than one second of warmup")
            if row["warmup_stable"] not in ("true", "false"):
                raise ValueError("warmup_stable must be literal true or false")
            blocks = row["block_medians_ms"].split(":")
            if len(blocks) != math.ceil(repetitions / 100):
                raise ValueError("block median count does not match the measured repetitions")
            if not all(math.isfinite(float(value)) and float(value) >= 0 for value in blocks):
                raise ValueError("block medians must be finite and nonnegative")
        elif row["bytes"]:
            if int(row["bytes"]) < 0 or row["runs"] or any(row[name] for name in timing_metadata):
                raise ValueError("invalid byte-only row or populated timing metadata")
        else:
            raise ValueError("row has neither measured statistics nor bytes nor an explicit failure note")
        rows.append(row)
    if not rows:
        raise ValueError("measurement child returned no nonempty CSV rows")
    if exit_code == 3 and not any(failure_kind(row) for row in rows):
        raise ValueError("incomplete child must include an explicitly blocked/timeout row")
    actual = {(row["scheme"], row["algorithm"], row["role"]) for row in rows}
    expected = expected_identities(case)
    if actual != expected:
        raise ValueError(f"unexpected row coverage: missing={sorted(expected-actual)}, extra={sorted(actual-expected)}")
    return rows


class Runner:
    def __init__(self, root, output, args, cases, binary):
        self.root, self.output, self.args, self.cases, self.binary = root, output, args, cases, binary
        self.binary_hash = fingerprint(binary)
        self.output.mkdir(parents=True, exist_ok=True)
        self.lock = (self.output / ".run.lock").open("a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another measurement runner is writing this output directory") from error
        self.log = (self.output / "run.log").open("a", encoding="utf-8", buffering=1)
        self.started = time.monotonic()
        self.completed, self.blocked, self.timed_out, self.failed = 0, 0, 0, 0
        self.forced_source_keys = {alias_source(case).key() for case in cases
                                   if alias_source(case) is not None and
                                   (args.force or any(matches(case, selector) for selector in args.repeat))}

    def message(self, message):
        line = f"{utc_now()} {message}"
        print(line, flush=True)
        self.log.write(line + "\n")
        self.log.flush()
        os.fsync(self.log.fileno())

    def checkpoint_path(self, case):
        return self.output / ".cases" / case.experiment / (case.key() + ".json")

    def read_checkpoint(self, case):
        path = self.checkpoint_path(case)
        if not path.exists():
            return None
        try:
            receipt = json.loads(path.read_text())
            if receipt["case"] != list(case.values()):
                raise ValueError("checkpoint case identity mismatch")
            encoded = json.dumps(receipt["rows"], sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(encoded).hexdigest() != receipt["rows_sha256"]:
                raise ValueError("checkpoint row checksum mismatch")
            return receipt
        except (ValueError, KeyError) as error:
            raise RuntimeError(f"invalid checkpoint {path}: {error}") from error

    def save_checkpoint(self, case, rows, state, *, reason="measurement", source=None, detail=None):
        path = self.checkpoint_path(case)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + f"-{os.getpid()}"
        if path.exists():
            old = json.loads(path.read_text())
            history = self.output / ".history" / case.experiment / case.key() / (stamp + ".json")
            atomic_text(history, json.dumps(dict(replacement_reason=reason, previous=old),
                                           ensure_ascii=False, indent=2) + "\n")
        encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
        warmup, runs = configuration(self.args, case)
        receipt = dict(
            version=2, case=case.values(), status=state, profile=self.args.profile,
            warmup=warmup, runs=runs, executable_sha256=self.binary_hash,
            rows_sha256=hashlib.sha256(encoded).hexdigest(), rows=rows, completed_utc=utc_now(),
            reason=reason,
        )
        if source is not None:
            receipt["source_case"] = list(alias_source(case).values())
            receipt["source_rows_sha256"] = source["rows_sha256"]
        if detail is not None:
            receipt["detail"] = detail
        atomic_text(path, json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")

    def current(self, receipt, case):
        if not (receipt and receipt["status"] == "complete" and self.compatible(receipt, case)):
            return False
        source_case = alias_source(case)
        if source_case is not None:
            source = self.read_checkpoint(source_case)
            return self.current(source, source_case) and receipt.get("source_rows_sha256") == source["rows_sha256"]
        return True

    def compatible(self, receipt, case):
        warmup, runs = configuration(self.args, case)
        return receipt and receipt.get("version") == 2 and receipt["profile"] == self.args.profile \
            and receipt["warmup"] == warmup and receipt["runs"] == runs \
            and receipt["executable_sha256"] == self.binary_hash

    def derive_alias(self, case, reason):
        source_case = alias_source(case)
        source = self.read_checkpoint(source_case)
        if not self.current(source, source_case):
            raise RuntimeError("canonical time_cost_table case is incomplete; default rows cannot be reused")
        lookup = {(row["algorithm"], row["role"]): row for row in source["rows"]}
        rows = []
        for target, original in sorted(aliases(case).items()):
            row = dict(lookup[original])
            row["algorithm"], row["role"] = target
            row.update({name: "" if getattr(case, name) == "-" else getattr(case, name) for name in DIMENSIONS})
            provenance = (f"reused time_cost_table.csv source={source_case.scheme}/{original[0]}/{original[1]} "
                          f"N=32 b=16 k=8 n=10 h=7 weight_bits=1 layout=0 source_rows_sha256={source['rows_sha256']}")
            row["note"] = "; ".join(filter(None, (row["note"], provenance)))
            rows.append(row)
        self.save_checkpoint(case, rows, "complete", reason=reason, source=source)
        return rows

    def synchronize_aliases(self, source_case):
        affected = set()
        for case in matrix(include_optional=True):
            if alias_source(case) != source_case:
                continue
            receipt = self.read_checkpoint(case)
            if receipt and not self.current(receipt, case):
                if self.compatible(receipt, case) and self.current(self.read_checkpoint(source_case), source_case):
                    self.derive_alias(case, "canonical source updated; reuse refreshed without measurement")
                    self.message(f"REFRESH_REUSE {case.label()}")
                else:
                    self.message(f"INVALIDATE_REUSE {case.label()} canonical source incomplete")
                affected.add(case.experiment)
        for experiment in affected:
            self.refresh_csv(experiment)

    def refresh_csv(self, experiment):
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        seen = set()
        for case in matrix(include_optional=True):
            if case.experiment != experiment:
                continue
            receipt = self.read_checkpoint(case)
            if self.compatible(receipt, case) and (alias_source(case) is None or self.current(receipt, case)):
                for row in receipt["rows"]:
                    key = row_key(row)
                    if key in seen:
                        raise ValueError(f"duplicate exported CSV row {key}")
                    seen.add(key)
                    writer.writerow(row)
        atomic_text(self.output / (experiment + ".csv"), output.getvalue())

    def child(self, case):
        warmup, runs = configuration(self.args, case)
        command = [str(self.binary), *case.values(), str(warmup), str(runs), self.args.profile]
        process = subprocess.Popen(command, cwd=self.root, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = process.communicate()
        except KeyboardInterrupt:
            process.send_signal(signal.SIGINT)
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            raise
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        attempt = self.output / ".attempts" / case.experiment / case.key() / stamp
        atomic_text(Path(str(attempt) + ".stdout.csv"), stdout)
        atomic_text(Path(str(attempt) + ".stderr.log"), stderr)
        atomic_text(Path(str(attempt) + ".json"), json.dumps(dict(exit_code=process.returncode, case=case.values())) + "\n")
        if stderr.strip():
            self.message(f"CHILD {case.label()}\n{stderr.rstrip()}")
        if process.returncode not in (0, 3):
            raise RuntimeError(f"measurement child exited {process.returncode}")
        return validate_rows(case, stdout, process.returncode, self.args), process.returncode

    def record_environment(self):
        content = environment(self.root, self.args, self.cases, self.binary)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
        atomic_text(self.output / "environment.md", content)
        atomic_text(self.output / ".environments" / (stamp + ".md"), content)
        self.message(f"START profile={self.args.profile} selected_cases={len(self.cases)}")

    def progress(self, case, rows, elapsed, state, index):
        statistics = []
        for row in rows:
            if row["median_ms"]:
                statistics.append(f"{row['scheme']}/{row['algorithm']}/{row['role']}={float(row['median_ms']):.6f}ms")
            elif row["bytes"]:
                statistics.append(f"{row['scheme']}/{row['algorithm']}/{row['role']}={row['bytes']}")
        gaps = [f"{row['scheme']}/{row['algorithm']}/{row['role']}={row['note']}" for row in rows
                if failure_kind(row)]
        suffix = " ".join([*statistics, *gaps])
        self.message(f"{state} {index}/{len(self.cases)} {case.label()} elapsed_s={elapsed:.3f} {suffix}")

    def dispersion(self, experiment):
        path = self.output / (experiment + ".csv")
        if not path.exists():
            return
        high = []
        with path.open(newline="") as stream:
            for row in csv.DictReader(stream):
                if row["median_ms"]:
                    median, p25, p75 = (float(row[name]) for name in ("median_ms", "p25_ms", "p75_ms"))
                    if p75 - p25 > 0.05 * median:
                        high.append(row)
        self.message(f"DISPERSION {experiment} points_above_5pct={len(high)}")
        for row in high:
            ratio = 100 * (float(row["p75_ms"]) - float(row["p25_ms"])) / float(row["median_ms"]) \
                if float(row["median_ms"]) else math.inf
            dims = " ".join(f"{name}={row[name]}" for name in DIMENSIONS)
            self.message(f"DISPERSION_POINT {experiment} {row['scheme']} {row['algorithm']}/{row['role']} {dims} IQR_pct={ratio:.3f}")

    def run(self):
        self.record_environment()
        for experiment in EXPERIMENTS:
            selected = [(index, case) for index, case in enumerate(self.cases, 1) if case.experiment == experiment]
            if not selected:
                continue
            stage_start = time.monotonic()
            self.message(f"EXPERIMENT_START {experiment} load={load_state()} power={power_state()!r}")
            self.refresh_csv(experiment)
            for index, case in selected:
                receipt = self.read_checkpoint(case)
                forced = self.args.force or case.key() in self.forced_source_keys or any(
                    matches(case, selector) for selector in self.args.repeat)
                if not forced and self.current(receipt, case):
                    self.completed += 1
                    self.message(f"RESUME {index}/{len(self.cases)} {case.label()}")
                    continue
                start = time.monotonic()
                reason = (getattr(self.args, "reason", None) or
                          ("forced retest selectors=" + json.dumps(self.args.repeat, sort_keys=True)
                           if forced else "missing or stale checkpoint"))
                try:
                    if alias_source(case) is not None:
                        rows = self.derive_alias(case, reason + "; canonical default reuse")
                        state = "complete"
                    else:
                        rows, exit_code = self.child(case)
                        failures = {failure_kind(row) for row in rows}
                        state = "timed_out" if "timed_out" in failures else "blocked" if "blocked" in failures or exit_code == 3 else "complete"
                        self.save_checkpoint(case, rows, state, reason=reason)
                        self.synchronize_aliases(case)
                    self.refresh_csv(experiment)
                    if state == "blocked":
                        self.blocked += 1
                    elif state == "timed_out":
                        self.timed_out += 1
                    else:
                        self.completed += 1
                    unstable = [f"{row['scheme']}/{row['algorithm']}/{row['role']}" for row in rows
                                if row["warmup_stable"] == "false" and row["median_ms"]]
                    if unstable:
                        self.message(f"WARMUP_UNSTABLE {case.label()} rows={','.join(unstable)}")
                    self.progress(case, rows, time.monotonic() - start, state.upper(), index)
                except (RuntimeError, ValueError) as error:
                    self.failed += 1
                    self.save_checkpoint(case, [], "failed", reason=reason, detail=str(error))
                    self.synchronize_aliases(case)
                    self.refresh_csv(experiment)
                    self.message(f"FAILED {index}/{len(self.cases)} {case.label()} {error}")
            self.dispersion(experiment)
            self.message(f"EXPERIMENT_END {experiment} elapsed_s={time.monotonic()-stage_start:.3f} load={load_state()} power={power_state()!r}")
        current = []
        for case in self.cases:
            receipt = self.read_checkpoint(case)
            if self.current(receipt, case):
                current.append(case)
        self.message(
            f"END complete_current_cases={len(current)}/{len(self.cases)} "
            f"blocked_cases={self.blocked} timed_out_cases={self.timed_out} failed_cases={self.failed} elapsed_s={time.monotonic()-self.started:.3f}"
        )
        if self.failed:
            return 1
        return 0 if len(current) == len(self.cases) else 3

    def close(self):
        self.log.close()
        fcntl.flock(self.lock, fcntl.LOCK_UN)
        self.lock.close()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("smoke", "formal"), default="smoke")
    parser.add_argument("--only", action="append", default=[], metavar="EXPERIMENT[,EXPERIMENT]",
                        help="select experiments; aggregation_checks and sensitivity_layouts require explicit selection")
    parser.add_argument("--scheme", action="append", default=[], metavar="SCHEME[,SCHEME]")
    parser.add_argument("--out", type=Path, help="output directory, default runs/smoke, runs/formal or runs/diagnostics")
    parser.add_argument("--force", action="store_true", help="replace every selected case")
    parser.add_argument("--reason", help="record the trigger for this measurement or retest in checkpoint history")
    parser.add_argument("--select", type=parse_selector, action="append", default=[], metavar="KEY=VALUE[,KEY=VALUE]",
                        help="restrict cases; repeated selectors are alternatives")
    parser.add_argument("--repeat", type=parse_selector, action="append", default=[], metavar="KEY=VALUE[,KEY=VALUE]",
                        help="select and replace matching cases, retaining other rows")
    parser.add_argument("--warmup", type=int)
    parser.add_argument("--runs", type=int)
    parser.add_argument("--unit-runs", type=int)
    inspection = parser.add_mutually_exclusive_group()
    inspection.add_argument("--dry-run", action="store_true", help="print the case matrix without building or measuring")
    inspection.add_argument("--diagnostics", action="store_true", help="record participant and trace diagnostics without timing")
    args = parser.parse_args()
    for name in ("warmup", "runs", "unit_runs"):
        value = getattr(args, name)
        minimum = 0 if name == "warmup" else 1
        if value is not None and value < minimum:
            parser.error(f"--{name.replace('_', '-')} must be at least {minimum}")
    return args


def run_diagnostics(root, args, cases):
    target = root / "target" / "diagnostics"
    subprocess.run(
        ["cargo", "build", "--release", "--locked", "--bin", "measure",
         "--features", "op-count", "--target-dir", str(target)],
        cwd=root, stdin=subprocess.DEVNULL, check=True,
    )
    columns = ("scheme", "purpose", "registered_slots", "participants_logical", "participating_slots",
               "f_nonzero", "f_coefficients", "masked_f_nonzero", "masked_f_coefficients",
               "trace_left_generated", "trace_right_generated", "trace_converted", "trace_right_visited",
               "trace_right_expected", "trace_right_lookups", "trace_table_entries")
    results = io.StringIO(newline="")
    writer = csv.writer(results, lineterminator="\n")
    writer.writerow(("experiment", *DIMENSIONS, *columns))
    for case in cases:
        if case.experiment == "unit_costs":
            continue
        result = subprocess.run(
            [str(target / "release" / "measure"), *case.values(), "0", "1", "smoke", "--diagnostics"],
            cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True, check=True,
        )
        rows = list(csv.reader(io.StringIO(result.stdout)))
        if not rows or any(len(row) != len(columns) for row in rows):
            raise ValueError(f"invalid diagnostics for {case.label()}")
        for row in rows:
            schemes = COMPARISON_SCHEMES if case.scheme == "comparison" else (case.scheme,)
            if row[0] not in schemes:
                raise ValueError(f"unexpected diagnostic scheme {row[0]} for {case.label()}")
            dimensions = ["" if getattr(case, name) == "-" else getattr(case, name) for name in DIMENSIONS]
            if row[0] in ("fll25", "fll25_opt"):
                dimensions[0] = ""
            writer.writerow((case.experiment, *dimensions, *row))
    output = args.out.resolve() if args.out else root / "runs" / "diagnostics"
    atomic_text(output / "participants.csv", results.getvalue())
    print(f"Participant diagnostics for {len(cases)} cases: {output / 'participants.csv'}")
    return 0


def main():
    args = parse_args()
    try:
        cases = selected_cases(args)
        if args.dry_run:
            total_rows = total_repetitions = reused_rows = 0
            for case in cases:
                warmup, runs = configuration(args, case)
                identities = expected_identities(case)
                timed_rows = sum(name not in BYTE_ROWS for _, name, _ in identities)
                metric_rows = len(identities)
                reuse = alias_source(case) is not None
                total_rows += metric_rows
                total_repetitions += 0 if reuse else timed_rows * runs
                reused_rows += metric_rows if reuse else 0
                action = "canonical_reuse" if reuse else "child"
                print(f"PLAN {case.label()} action={action} minimum_warmup_runs={max(10,warmup)} minimum_warmup_s=1 "
                      f"runs={runs} required_metric_rows={metric_rows} required_timed_rows={timed_rows}")
            print(f"TOTAL cases={len(cases)} child_invocations={sum(alias_source(case) is None for case in cases)}")
            for experiment in EXPERIMENTS:
                selected = [case for case in cases if case.experiment == experiment]
                if selected:
                    rows = sum(len(expected_identities(case)) for case in selected)
                    repetitions = sum(sum(name not in BYTE_ROWS for _, name, _ in expected_identities(case))
                                      * configuration(args, case)[1] for case in selected if alias_source(case) is None)
                    print(f"EXPERIMENT {experiment} cases={len(selected)} required_metric_rows_exact={rows} "
                          f"unique_algorithm_repetitions_nominal={repetitions}")
            print(f"TOTAL_REQUIRED metric_rows={total_rows} reused_metric_rows={reused_rows} "
                  f"unique_algorithm_repetitions_nominal={total_repetitions} "
                  "warmup_excluded=true slow_adjustment_excluded=true trailing_sentinel_separate=true")
            return 0
        root = Path(__file__).resolve().parents[1]
        if args.diagnostics:
            return run_diagnostics(root, args, cases)
        output = args.out.resolve() if args.out else root / "runs" / args.profile
        build = subprocess.run(["cargo", "build", "--release", "--locked", "--bin", "measure"],
                               cwd=root, stdin=subprocess.DEVNULL, check=False)
        if build.returncode:
            return build.returncode
        binary = root / "target" / "release" / "measure"
        runner = Runner(root, output, args, cases, binary)
        try:
            return runner.run()
        finally:
            runner.close()
    except KeyboardInterrupt:
        print("Interrupted. Completed case checkpoints are retained for resumption.", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Benchmark runner: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
