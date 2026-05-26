#!/usr/bin/env bash
# F104 PoC runner. No GNU Radio dependency.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "Running F104 SatYAML-SSRF PoC..."
echo "================================="
python3 "$HERE/poc_F104_satyaml_ssrf.py"
RC=$?
echo "================================="
echo "Exit: $RC"
