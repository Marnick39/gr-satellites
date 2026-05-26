#!/usr/bin/env bash
# F60 PoC runner. Expects gr-satellites source tree at the path given
# as argv[1] (defaults to ../../../../../src so it resolves out of the
# bundled location into the in-repo source).

set -uo pipefail

SRC="${1:-$(dirname "$0")/../../../../../src}"
SRC="$(cd "$SRC" && pwd)"

if [ ! -f "$SRC/lib/viterbi.c" ]; then
    echo "ERROR: $SRC/lib/viterbi.c not found"
    echo "Usage: $0 <path-to-gr-satellites-src>"
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
# Build in the PoC dir itself: /tmp on the audit host is mounted noexec.
BUILD_TMP="$(mktemp -d -p "$HERE" build.XXXXXX)"
BIN="$BUILD_TMP/poc_F60"
trap 'rm -rf "$BUILD_TMP"' EXIT

echo "Building against $SRC/lib/viterbi.c ..."
gcc -O0 -g -fno-omit-frame-pointer \
    -I "$SRC/lib" \
    -o "$BIN" \
    "$HERE/poc_F60_double_free.c" \
    "$SRC/lib/viterbi.c"
echo "Built $BIN"

echo
echo "Running PoC (glibc malloc check enabled by default on modern distros)..."
echo "===================================================================="
"$BIN"
RC=$?
echo "===================================================================="
echo "Exit code: $RC"
if [ $RC -ne 0 ]; then
    echo "PoC behaved as expected on unpatched build (crash on second delete)."
else
    echo "Process exited cleanly — bundle patch 0003 likely already applied."
fi
