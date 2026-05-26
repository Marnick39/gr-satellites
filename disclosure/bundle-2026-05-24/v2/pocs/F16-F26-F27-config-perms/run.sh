#!/usr/bin/env bash
# F16+F26+F27 PoC runner. No GNU Radio dependency.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
for f in poc_F16_world_readable.py poc_F26_mkdir_race.py poc_F27_dir_traversable.py; do
    echo "==================================================================="
    echo "Running $f"
    echo "==================================================================="
    python3 "$HERE/$f"
    echo
done
