#!/usr/bin/env bash
# F18 cluster PoC runner. No GNU Radio dependency.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "==================================================================="
echo "Running F18 cluster reproducer (6 sub-findings)"
echo "==================================================================="
python3 "$HERE/poc_F18_cluster.py"
