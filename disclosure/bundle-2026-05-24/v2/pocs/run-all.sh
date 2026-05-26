#!/usr/bin/env bash
# Run every PoC in this directory and print PASS/FAIL.
#
# Run from inside the audit repo so the F60 PoC can find ../../../../../src.
# Skipping unavailable PoCs (e.g. missing build deps for F112) is fine; this
# script returns non-zero only when a PoC that DID run reported FAIL.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

OVERALL=0

run_poc () {
    local label="$1"
    local cmd="$2"
    echo "==================================================================="
    echo "  $label"
    echo "==================================================================="
    if eval "$cmd"; then
        echo "  -> ran cleanly"
    else
        rc=$?
        echo "  -> exited $rc"
        # exit 134 is SIGABRT, which is the EXPECTED outcome for the F60 PoC
        # against an unpatched build. Treat that one as success-by-design.
        if [ "$label" = "F60 viterbi double-free (PASS = abort)" ] && \
           [ "$rc" -eq 134 ]; then
            echo "  (expected abort on unpatched build)"
        else
            OVERALL=1
        fi
    fi
    echo
}

run_poc "F4 end-to-end RCE (.pth auto-exec chain)" \
        "bash '$HERE/F4-rce/poc_F4_rce_e2e.sh'"

run_poc "F4 path-traversal (T3 isolation-only)" \
        "python3 '$HERE/F4-rce/poc_F4_path_traversal.py'"

# F109/F110 is dockerized; skip if docker not available OR if `docker run`
# can't actually start containers (some sandboxed hosts have a docker
# client + daemon that allow exec but not run-nested).
DOCKER_OK=0
if command -v docker >/dev/null 2>&1; then
    if docker run --rm alpine:latest echo ok >/dev/null 2>&1; then
        DOCKER_OK=1
    fi
fi
if [ "$DOCKER_OK" -eq 1 ]; then
    run_poc "F109+F110 LAN-amplifier (docker)" \
            "bash '$HERE/F109-F110-lan-amp/run_poc.sh'"
else
    echo "[skip] F109+F110 needs working 'docker run'; using saved run_poc.log:"
    tail -10 "$HERE/F109-F110-lan-amp/run_poc.log" 2>/dev/null || \
        echo "  (saved log missing)"
    echo
fi

run_poc "F60 viterbi double-free (PASS = abort)" \
        "bash '$HERE/F60-viterbi-double-free/run.sh'"

run_poc "F10+F12 PMT heap leak (no-GR logic check)" \
        "python3 '$HERE/F10-F12-heap-leak/poc_F10_logic_only.py'"

run_poc "F22 submitter robustness" \
        "python3 '$HERE/F22-submitter-robustness/poc_F22c_urllib.py'"

run_poc "F18 cluster (F23, F65, F71, F72, F73, F98)" \
        "python3 '$HERE/F18-parser-narrow-except/poc_F18_cluster.py'"

run_poc "F15+F21+F24 privacy" \
        "bash '$HERE/F15-F21-F24-privacy/run.sh'"

run_poc "F104 SatYAML SSRF" \
        "python3 '$HERE/F104-satyaml-ssrf/poc_F104_satyaml_ssrf.py'"

run_poc "F16+F26+F27 config perms" \
        "bash '$HERE/F16-F26-F27-config-perms/run.sh'"

run_poc "F101 (hygiene) KISS rebind" \
        "python3 '$HERE/F101-hygiene/poc_F101_kiss_list_rebind.py'"

run_poc "F105 (hygiene) action SHA pin" \
        "bash '$HERE/F105-hygiene/verify_action_sha.sh'"

echo
if [ $OVERALL -eq 0 ]; then
    echo "All PoCs ran with expected behaviour."
else
    echo "Some PoCs exited unexpectedly — see output above."
fi
exit $OVERALL
