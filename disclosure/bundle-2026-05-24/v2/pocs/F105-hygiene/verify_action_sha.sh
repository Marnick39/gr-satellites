#!/usr/bin/env bash
# F105 hygiene PoC — verify the pinned SHA in build-ubuntu.yml matches
# the documented v2.1.0 tag against api.github.com.
#
# No GNU Radio needed; needs curl.
set -uo pipefail

EXPECTED_SHA="e9aa8f8569301c797dcaffb3a99f25c00ed3d0d3"
TAG="v2.1.0"
REPO="daniestevez/gr-satellites-ci-action"

echo "=== F105 PoC — verify CI action pin matches advertised tag ==="
echo
echo "Querying api.github.com/repos/${REPO}/git/refs/tags/${TAG} ..."
ACTUAL_SHA=$(curl -sL "https://api.github.com/repos/${REPO}/git/refs/tags/${TAG}" \
    | python3 -c 'import json, sys; d=json.load(sys.stdin); print(d["object"]["sha"])')

echo "  Expected SHA: ${EXPECTED_SHA}"
echo "  Live SHA:     ${ACTUAL_SHA}"
echo

if [ "${EXPECTED_SHA}" = "${ACTUAL_SHA}" ]; then
    echo "  [PASS] Pin matches tag at the time of writing the patch."
else
    echo "  [MISMATCH] The tag was moved or the SHA in the patch needs"
    echo "  updating. Re-verify and update patches/0097-F105-pin-action-by-sha.patch"
    echo "  with the new SHA before applying."
    exit 1
fi

echo
echo "=== Why pin by SHA, not tag ==="
echo "Tags in GitHub are mutable. A maintainer (or attacker with maintainer"
echo "credentials) can re-point v2.1.0 to a different commit at any time."
echo "Every PR that runs the workflow inherits whatever the tag points to"
echo "at run time. Pinning by SHA freezes the workflow to the audited commit."
echo "OpenSSF Scorecard's 'Pinned-Dependencies' check rewards SHA pinning."
