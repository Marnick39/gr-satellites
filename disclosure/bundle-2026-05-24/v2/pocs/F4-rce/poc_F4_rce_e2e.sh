#!/usr/bin/env bash
# F4 RCE end-to-end PoC runner.
#
# Self-contained: no docker dependency, no install required, runs in any
# Python 3.x environment. Isolates from the host's real ~/.local/ by
# using PYTHONUSERBASE=/tmp/F4ub. Cleans up after itself.
#
# Run:
#     ./poc_F4_rce_e2e.sh
#
# Expected: prints a "[PASS]" line and exits 0. On failure prints
# [FAIL] with a specific step number and exits non-zero.
#
# For maintainers who want full container isolation, a Dockerfile is
# also provided in this directory; build with `docker build -t f4 .`
# and run with `docker run --rm --network=none f4`.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

echo "===================================================================="
echo "  F4 end-to-end RCE PoC"
echo "===================================================================="
echo

# Pre-flight: make sure the markers don't already exist from a prior run.
rm -rf /tmp/F4ub /tmp/RCE_MARKER 2>/dev/null

python3 "$HERE/poc_F4_rce_e2e.py"
RC=$?

# Best-effort cleanup so reruns are deterministic.
rm -rf /tmp/F4ub /tmp/RCE_MARKER 2>/dev/null

echo
if [ $RC -eq 0 ]; then
    echo "===================================================================="
    echo "  PASS — F4 8.0 score validated end-to-end."
    echo "===================================================================="
    exit 0
else
    echo "===================================================================="
    echo "  FAIL — F4 chain did not complete (exit $RC). See output above."
    echo "===================================================================="
    exit "$RC"
fi
