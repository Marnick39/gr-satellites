#!/usr/bin/env bash
# F112 hygiene PoC — show that a plain `cmake .. && make` build of
# gr-satellites produces a libgnuradio-satellites.so without the
# distro-injected hardening flags, until patch 0098 lands.
#
# Needs: cmake, make, gnu-radio dev headers (usual gr-satellites build deps).
# Optional: hardening-check (from devscripts package on Debian/Ubuntu).
set -uo pipefail

SRC="${1:-../../../../../src}"
SRC="$(cd "$SRC" && pwd 2>/dev/null || true)"

if [ -z "${SRC}" ] || [ ! -f "${SRC}/CMakeLists.txt" ]; then
    echo "ERROR: gr-satellites source dir not found"
    echo "Usage: $0 <path-to-gr-satellites-src>"
    exit 1
fi

echo "=== F112 PoC — checksec-style verification ==="
echo "Source tree: ${SRC}"
echo

BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT

echo "Configuring with plain cmake (no distro flags)..."
(cd "$BUILD" && cmake "$SRC" >/dev/null 2>&1)

echo "Building (this takes a few minutes)..."
(cd "$BUILD" && make -j2 >/dev/null 2>&1) || {
    echo "make failed; this PoC needs the GR build deps installed"
    exit 2
}

LIB=$(find "$BUILD" -name 'libgnuradio-satellites*.so*' -type f | head -1)
if [ -z "$LIB" ]; then
    echo "Could not find built libgnuradio-satellites; check $BUILD"
    exit 3
fi

echo "Built: $LIB"
echo
if command -v checksec >/dev/null 2>&1; then
    echo "checksec output:"
    checksec --file="$LIB"
elif command -v hardening-check >/dev/null 2>&1; then
    echo "hardening-check output:"
    hardening-check "$LIB"
else
    echo "Neither 'checksec' nor 'hardening-check' is installed."
    echo "Falling back to readelf / objdump heuristics:"
    echo
    echo "RELRO:"
    readelf -l "$LIB" 2>/dev/null | grep -E 'GNU_RELRO|GNU_STACK' || echo "  none"
    echo
    echo "Symbols suggestive of fortified glibc calls (after patch should be present):"
    objdump -d "$LIB" 2>/dev/null | grep -cE 'strcpy_chk|memcpy_chk|sprintf_chk' \
        | xargs -I{} echo "  fortify-chk callsites: {}"
fi

echo
echo "Expected after patches/0098-F112-cmake-hardening.patch is applied:"
echo "  RELRO       Full"
echo "  Canary      yes"
echo "  PIE         PIE enabled"
echo "  Fortify     fortified strings present"
