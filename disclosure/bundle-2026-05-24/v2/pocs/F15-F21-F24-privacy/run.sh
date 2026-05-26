#!/usr/bin/env bash
# F15+F21+F24 PoC runner. No GNU Radio dependency.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
for f in poc_F15_default.py poc_F21_dead_guard.py poc_F24.py; do
    echo "==================================================================="
    echo "Running $f"
    echo "==================================================================="
    python3 "$HERE/$f" || echo "  (non-zero exit code from $f)"
    echo
done
