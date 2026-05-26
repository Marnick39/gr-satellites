#!/usr/bin/env bash
# F4 PoC runner. No GNU Radio dependency.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "Running F4 path-traversal PoC..."
echo "================================="
python3 "$HERE/poc_F4_path_traversal.py"
RC=$?
echo "================================="
echo "Exit: $RC"
if [ $RC -eq 0 ]; then
    echo "F4 path traversal PASS — write escaped base dir."
    echo "If you intend to verify the patch fixes this, apply"
    echo "patches/0001-F4-qo100-multimedia-filename-sanitization.patch"
    echo "to your gr-satellites checkout and re-run this script."
fi
