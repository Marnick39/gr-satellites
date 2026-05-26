# Advisory 4 — Heap memory disclosure in PMT u8vector handling

CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = **5.3 Medium**
CWE: CWE-908 (use of uninitialized resource), CWE-200 (exposure of sensitive information)
Affected: gr-satellites `>= 1.0.0, <= 5.9.0`
Audit reference: F10 + F12 (three call sites with shared root cause)

## What happens

Three Python blocks call `pmt.init_u8vector(N, source)` where `N` derives from an attacker-controlled length field in the received RF frame and may exceed `len(source)`. The PMT helper reads `N` bytes from the source list regardless, picking up uninitialized heap content from CPython's obmalloc anon-arena. The bytes ship downstream as the output PDU.

Three call sites, one fix:

- `python/cc11xx_packet_crop.py:44` — leaks roughly 127 bytes per frame
- `python/sx12xx_packet_crop.py:47` — same primitive
- `python/components/deframers/spino_deframer.py:46` — 16-bit attacker-controlled length field, up to 65,551 bytes per frame

## What leaks

`pocs/F10-F12-heap-leak/heap_content_analysis.py` runs 1000 iterations of the cc11xx over-read and classifies the leaked bytes: the published PDUs carry libc-mapped pointer bytes (`0x7f...`-prefixed words) on the large majority of trials. One frame is enough to fingerprint the libc base address and defeat ASLR on the operator's gr-satellites process.

The bytes come from CPython's obmalloc, so the attacker observes what happens to be in the arena at the moment of allocation — they can't plant specific content. That makes this an info-leak / ASLR oracle, not a write primitive.

## Why it reaches the public internet

The `submit_tlm: 'yes'` default (see Advisory 7) plus a measured CRC-16 false-pass rate of ~1/71,000 for random buffers (~1/50,000 for heap-content buffers — closer to the actual leak class) means roughly one leaked-pointer fragment slips past the CRC every ~50,000 received frames per receiver, gets hex-encoded as the `frame=` field, and is POSTed to `https://db.satnogs.org/api/telemetry/`. Submissions persist in SatNOGS DB and are accessible to any registered SatNOGS DB user (registration is open).

An attacker who wants ASLR information for a future exploit doesn't need to transmit — they register a free SatNOGS DB account and query the authenticated telemetry API. Coordination on this side: Libre Space Foundation should verify the DB frontend escapes the `frame` field before public disclosure.


## What this is not

No chainable write primitive elsewhere in gr-satellites; F4 is the only RCE path. This finding is an info-leak, not an RCE.

## Proof of concept

`pocs/F10-F12-heap-leak/`:

- `poc_f10.py` — verbatim reimpl of the buggy `handle_msg` from `cc11xx_packet_crop.py`; runs 100 stress iterations and shows the leaked bytes
- `poc_F10_logic_only.py` — no-GR reproducer of the over-read condition (runs anywhere)
- `aslr_bypass_demo.py` — extracts libc pointer offsets from a single leaked frame
- `heap_content_analysis.py` — 1000-iteration classification of what the obmalloc arena spills

## Fix

At each of the three call sites, drop the frame when the in-band length field would over-read the source (`if packet_length > len(packet): return`) and slice the source before handing it to `pmt.init_u8vector` (`pmt.init_u8vector(packet_length, packet[:packet_length])`). The slice makes the over-read impossible even if the length-guard is later relaxed. Patch: `patches/0004-F10-F12-zero-init-pmt-vectors.patch`.

## Notes

Reported by Marnick Vandecauter security@marnick.net as part of an independent security audit of gr-satellites v5.9.0 (May 2026). Research supported by Mamato Labs.
