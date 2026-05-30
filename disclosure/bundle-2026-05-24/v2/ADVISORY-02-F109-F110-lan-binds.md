# Advisory 2 — Example flowgraphs bind to wildcard interface, amplifying RF-only bugs to LAN

CVSS 3.1: `AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` = **6.3 Medium**
CWE: CWE-1327 (binding to unrestricted IP), CWE-306 (missing authentication)
Affected: gr-satellites `>= 1.0.0, <= 5.9.0`
Audit reference: F109 + F110

## What happens

Eleven example `.grc` flowgraphs (twelve file-edits across them; tanusha3_pm + df2et each contribute one edit) ship with their KISS `socket_pdu` (TCP_SERVER on port 52001) or UDP source (port 7355) bound to the wildcard address: `host: ''` for TCP, `ipaddr: 0.0.0.0` or `::` for UDP. A LAN-adjacent attacker can connect to those ports and inject crafted KISS or IQ frames into the operator's gr-satellites flowgraph without needing RF transmit hardware.

Many of the other findings in this disclosure are RF-only in their raw form (F18 parser DoS, F31 adapter math errors, F58 memory growth, etc.). Combined with the wildcard binds, they become LAN-reachable for any operator using one of the affected examples. The PoC demonstrates this end-to-end: a separate process connects to `127.0.0.1:52001`, sends a 41-byte KISS-framed AX.25 UI frame containing a non-ASCII byte, and triggers the F18 `UnicodeDecodeError` permanent thread death in `telemetry_parser`.

## Affected files

TCP_SERVER (`host: ''` → bind 0.0.0.0:52001):
```
src/examples/ax25/afsk.grc:361
src/examples/ax25/bpsk.grc:415
src/examples/ax25/bpsk9k6.grc:415
src/examples/ax25/fsk.grc:285
src/examples/satellites/tanusha3_pm.grc:376
```

UDP source (`ipaddr: 0.0.0.0` / `'::'` / unset):
```
src/examples/qo100-multimedia-beacon/qo100_multimedia_beacon_ea4gpz.grc:130
src/examples/satellites/nx_decoder/dstar_one.grc:184
src/examples/satellites/equisat.grc:344
src/examples/satellites/tanusha3_pm.grc:390
src/examples/satellites/nx_decoder/beesat.grc:230
src/examples/qo100-multimedia-beacon/qo100_multimedia_beacon_df2et.grc:880
```

`qo100_multimedia_beacon.grc` already sets `host: 127.0.0.1` correctly on its TCP_SERVER instance; df2et's TCP_SERVER is also correct but its `network_udp_source` still needs `ipv4_addr: '127.0.0.1'`. The TCP correct pattern is the template to mirror.

## Proof of concept

`pocs/F109-F110-lan-amp/`:

```
# terminal 1
python3 f109_listener.py       # spins up the AX.25 example flowgraph

# terminal 2
ss -ltnp | grep 52001          # confirms LISTEN on 0.0.0.0:52001
python3 f109_attacker.py       # sends crafted KISS frame from a separate process
```

Output of the attacker shows the frame delivered; the listener's `telemetry_parser` thread vanishes from `/proc/<pid>/task/`, and any subsequent messages to the block stay queued forever.

## Fix

Twelve single-line changes across the eleven files. Patch: `patches/0002-F109-F110-bind-examples-to-localhost.patch`. Operators who deliberately want LAN reach can override per file via the GRC `host` / `ipaddr` parameter.

## Behaviour change for existing operators

Operators who hand-edited their copy of any affected `.grc` to set
`host: '0.0.0.0'` for legitimate reasons (remote SDR ingest from
another LAN host, multi-machine flowgraph splits) will have their
overrides preserved — the patch only touches files that still ship
the default wildcard. However, operators who run the **shipped**
example flowgraphs directly and depend on LAN reachability will need
to either (a) edit `host:` to `0.0.0.0` in the GRC GUI, or (b) point
their downstream consumer at `127.0.0.1` and run it on the same host.
Maintainer release notes should call this out.

## Notes

Reported by Marnick Vandecauter security@marnick.net as part of an independent security audit of gr-satellites v5.9.0 (May 2026). Research supported by Mamato Labs.
