# PoCs

One directory per advisory. Every PoC is intentionally low-ceremony:
no GNU Radio installation required, no SDR hardware, no live satellite.
Each reimplements the relevant gr-satellites v5.9.0 code path verbatim,
drives it with a single crafted input, and prints PASS/FAIL plus
expected-after-patch behaviour.

## Run them all

```
./run-all.sh
```

Best run from the bundle root. The F60 PoC needs the gr-satellites
source tree at `../../../../../src` (relative to the bundle), so do this
from inside the audit tree, not after unpacking the bundle in isolation.

## Per-advisory PoCs

| Advisory | Dir | Tier | Notes |
|----------|-----|------|-------|
| 1. F4 RCE | `F4-rce/` | T4 | Standalone Python; writes outside base dir to prove it |
| 2. F109+F110 LAN amp | `F109-F110-lan-amp/` | T4 | Full docker e2e: listener + attacker + amplifier check |
| 3. F60 viterbi double-free | `F60-viterbi-double-free/` | T4 | C reproducer; needs source tree to build against viterbi.c |
| 4. F10+F12 heap leak | `F10-F12-heap-leak/` | T4 | Reimpls cc11xx/sx12xx/spino; includes ASLR-bypass demo |
| 5. F22 submitter | `F22-submitter-robustness/` | T3 | In-process mock servers for 6 submitter sites |
| 6. F18 cluster | `F18-parser-narrow-except/` | T3 | Six sub-finding reproducers in one script |
| 7. F15+F21+F24 privacy | `F15-F21-F24-privacy/` | T3 | One script per sub-finding |
| 8. F104 SatYAML SSRF | `F104-satyaml-ssrf/` | T3 | In-process mock listener + verbatim urlopen path |
| 9. F16+F26+F27 config | `F16-F26-F27-config-perms/` | T3 | One script per sub-finding |

Hygiene patches (no CVE):

| Patch | Dir | Notes |
|-------|-----|-------|
| F101 KISS rebind | `F101-hygiene/` | Verbatim handle_msg byte-loop reimpl |
| F105 action pin | `F105-hygiene/` | curl + jq verifier against GitHub API |
| F112 hardening | `F112-hygiene/` | checksec/hardening-check against built .so |

## Tier definitions (audit-internal)

- T1 — armchair / theoretical; no code run
- T2 — descriptive, points at the bug location
- T3 — working reproducer; shows the buggy behaviour and the post-patch
       behaviour against the same input
- T4 — end-to-end against the real binary or a faithful in-process
       analogue with a clear pass/fail signal at the OS level (crash,
       file-write outside base, network exfil, etc.)

The "PoC or GTFO" bar for every CVE-worthy entry in this disclosure is
T3; the major ones (F4, F60, F109/F110, F10/F12) clear T4.
