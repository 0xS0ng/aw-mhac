#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${PYTHON:-python3}"

if command -v caffeinate >/dev/null 2>&1; then
    export BENCHMARK_SLEEP_PREVENTION='caffeinate -i -m'
    exec caffeinate -i -m "$python_bin" "$script_dir/run_experiments.py" "$@"
elif command -v systemd-inhibit >/dev/null 2>&1; then
    export BENCHMARK_SLEEP_PREVENTION='systemd-inhibit --what=sleep --mode=block'
    exec systemd-inhibit --what=sleep --mode=block --who='Benchmark runner' \
        --why='Completing benchmark cases' "$python_bin" "$script_dir/run_experiments.py" "$@"
else
    export BENCHMARK_SLEEP_PREVENTION='unavailable'
    exec "$python_bin" "$script_dir/run_experiments.py" "$@"
fi
