#!/usr/bin/env bash
# F22 submitter-robustness PoC runner. Reimplements each submitter
# block's handle_msg verbatim, drives it with a mock server that
# returns malformed responses / closes the TCP early / hangs, and
# asserts the unpatched handler raises an exception that would kill
# the GR scheduler thread. No GNU Radio dependency.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "==================================================================="
echo "Running F22c urllib reproducer"
echo "==================================================================="
python3 "$HERE/poc_F22c_urllib.py"
