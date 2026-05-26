# Advisory 5 — Unhandled network exceptions in telemetry submitters kill the GR scheduler thread

CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5 High**
CWE: CWE-755 (improper exception handling)
Affected: gr-satellites `>= 1.0.0, <= 5.9.0`
Audit reference: F22a + F22b + F22c + F20 + F33 + F34 + F35 + F36 (eight sites, one fix)

## Why AC:L

The BME warehouse path self-triggers on every flowgraph start: `gnd.bme.hu:8080` completes the TLS handshake and then closes the stream on anonymous connections, raising `ConnectionError` on the first frame. No attacker action required.

## What happens

Each of the telemetry-submitter blocks wraps a network call (`requests.post`, `requests.put`, `urlopen`, `WebSocket.send`) inside the GNU Radio `handle_msg` entry point without a `try/except` clause. GNU Radio's thread-per-block scheduler catches uncaught exceptions only at the very top of the thread function; once caught, the thread exits and is not respawned. The block's input queue keeps accepting messages — they just stay queued and never get processed.

When the operator's network has any transient failure (DNS timeout, TCP RST from the warehouse, TLS handshake failure, slow server, network change), the submitter's `requests.post()` raises a Python exception, the handler thread dies, and every subsequent telemetry submission is silently dropped. The flowgraph keeps running so there's no visible error; the operator believes they're uploading but the queue is being discarded.

I verified each of the four warehouse endpoints is currently live (see the table below for the per-endpoint status). The BME server in particular completes a TLS handshake then closes the stream on anonymous connections, which raises `ConnectionError` on the very first frame after every flowgraph start — operators running BME submission hit the bug without any attacker present.

## Eight call sites, one fix

| Site | File:line | Trigger |
|------|-----------|---------|
| F22a | `funcube_submit.py:58` | `requests.post()` outside try/except |
| F22b | `pwsat2_submitter.py:83,112` | `requests.put()` + `.post()` outside try/except |
| F22c | `submit.py:130-140` | partial wrap; mid-stream errors escape |
| F20 | `bme_submitter.py:80-87` | `putPacket` response JSON parse uncaught |
| F33 | `bme_submitter.py:50` | authenticate response JSON parse uncaught |
| F34 | `bme_submitter.py:53` | authenticate keyError on missing field |
| F35 | `bme_submitter.py:71-73` | putPacket keyError on missing field |
| F36 | `bme_ws_submitter.py:31,48,49` | no `timeout=` on connect/send/recv — `connect` is unwrapped, `send`/`recv` are wrapped at the handler level but a stalled server still hangs the thread indefinitely |

## Live endpoint status (verified 2026-05-24)

| Submitter | Endpoint | Live | Exploit today |
|-----------|----------|------|---------------|
| FUNcube AMSAT-UK | `http://data.amsat-uk.org/api/data/hex/...` | yes (400 on test path) | yes |
| BME | `https://gnd.bme.hu:8080/api/tokens` | yes — self-triggers on every connection | yes, no attacker needed |
| SatNOGS DB | `https://db.satnogs.org/api/telemetry/` | yes (401 auth challenge) | yes; largest reach (~409 sats) |
| PW-Sat2 | `http://radio.pw-sat.pl/api/authenticate` | host up, app gone (satellite deorbited 2021-02-13) | historical only |


## Proof of concept

`pocs/F22-submitter-robustness/`:

- `poc_F22c_urllib.py` — verbatim reimpl of `submit.py`'s submitter loop; drives it against a mock HTTP server that closes the stream mid-response, shows the exception escaping the parser to the GR-scheduler boundary
- `run.sh` — invokes the reproducers and prints a per-site pass/fail summary

## Fix

`patches/0005-F22-submitter-try-except-and-timeouts.patch`. Wrap each `handle_msg` body in `try/except Exception` with a `logger.error("submission failed: ...")` line. Add `timeout=10` to every `requests.*` and websocket call. Eight sites in five files; the patch is small.

## Notes

Reported by Marnick Vandecauter security@marnick.net as part of an independent security audit of gr-satellites v5.9.0 (May 2026). Research supported by Mamato Labs.
