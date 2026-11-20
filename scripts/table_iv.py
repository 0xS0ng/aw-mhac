#!/usr/bin/env python3
"""Render the paper's default-parameter timing table as Markdown."""

import argparse
import csv
from pathlib import Path

from plot import median_label


SCHEMES = ("fhll26", "fll25", "hints", "aw_mhac")
LABELS = ("FHLL26", "FLL25", "hinTS", "AW-MHAC")
DIMENSIONS = {
    "fhll26": ("", "1", "1"),
    "fll25": ("", "16", "8"),
    "hints": ("32", "16", "8"),
    "aw_mhac": ("32", "16", "8"),
}
OPERATIONS = {
    "HKeyGen": ("device", None, "holder", "holder"),
    "Issue": ("issuer", "issuer", "issuer", "issuer"),
    "Accept": ("host", "holder", None, "host"),
    "PartSign": ("secure_element", "holder", "holder", "holder"),
    "Show": ("host", None, "host", "host"),
    "Verify": ("verifier", "verifier", "verifier", "verifier"),
    "Trace": (None, None, None, "auditor"),
    "Judge": (None, None, None, "judge"),
}


def render(path):
    with path.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    yield "| Algorithm | " + " | ".join(LABELS) + " |"
    yield "| --- | ---: | ---: | ---: | ---: |"
    for algorithm, roles in OPERATIONS.items():
        cells = [algorithm]
        for scheme, role in zip(SCHEMES, roles):
            if role is None:
                cells.append("—")
                continue
            matches = [
                row["median_ms"] for row in rows
                if (row["scheme"], row["algorithm"], row["role"]) == (scheme, algorithm, role)
                and (row["N"], row["b"], row["k"]) == DIMENSIONS[scheme]
                and (row["n"], row["h"], row["weight_bits"], row["layout"]) == ("10", "7", "1", "0")
            ]
            if len(matches) != 1 or not matches[0]:
                raise ValueError(f"Expected one timing for {scheme}/{algorithm}/{role}")
            cells.append(median_label(matches[0]))
        yield "| " + " | ".join(cells) + " |"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data"), help="directory containing the timing CSV")
    args = parser.parse_args()
    try:
        print("\n".join(render(args.data / "time_cost_table.csv")))
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f"table_iv.py: {error}\n")


if __name__ == "__main__":
    main()
