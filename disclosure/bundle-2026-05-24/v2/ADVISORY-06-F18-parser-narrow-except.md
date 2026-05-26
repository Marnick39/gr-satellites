# Advisory 6 — Narrow exception catches in telemetry parser cluster permit single-frame DoS

CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5 High**
CWE: CWE-755 (improper exception handling)
Affected: gr-satellites `>= 1.0.0, <= 5.9.0`
Audit reference: F18 + F23 + F65 + F66 + F68 + F69 + F70 + F71 + F72 + F73 + F98 (eleven sub-finding sites). The patch fixes six (F18, F23, F65, F71, F72, F73) — those verified end-to-end with PoCs. The remaining five are documented in the table for maintainer review.

## Why AC:L

The F23/F72 sub-finding self-triggers on real satellite signals: BY70-1 transmits `rssi_fm_tc=0` during no-carrier intervals, the RSSIAdapter's `log10(0)` raises `ValueError`, which escapes the parser's narrow `except ConstructError` and kills the parser thread. No attacker action required.

The other sub-findings (F18 unicode, F65/F71 short input, F98 reshape) need malformed-but-CRC-valid frames and would score AC:H on their own; cluster score reflects the most-reachable sub-finding.

## What happens

`telemetry_parser` and several deframer/cropper blocks catch parse errors with `except ConstructError:`. That clause only matches exceptions thrown by the `construct` library's own parser. It does not match common Python exceptions that real frames genuinely produce:

- `UnicodeDecodeError` from `construct.PaddedString('ascii')` when a high-bit byte arrives (F18)
- `ValueError` from `math.log10(0)` in `RSSIAdapter._decode` when BY70-1 sends `rssi_fm_tc=0` during idle periods (F23, F72)
- `IndexError` / `struct.error` when a deframer receives a PDU shorter than its hard-coded slice (F65, F68, F71, F98)

The GR scheduler kills the block's thread on any uncaught exception (reproducer at `pocs/F18-parser-narrow-except/poc_F18_cluster.py` exercises each sub-finding's escape path and shows the per-thread thread death pattern). One malformed-but-CRC-valid frame from the satellite, an RF attacker, or the LAN amplifier in Advisory 2 disables telemetry decoding for the satellite for the rest of the gr-satellites process lifetime.

The F23/F72 chain on BY70-1 fires on real satellite signals — the RSSI=0 condition occurs naturally during no-carrier intervals. Operators don't need an attacker to hit this bug; their decoder dies on its own.

## Eleven sub-finding sites, one fix

| Sub-ID | File:line | Trigger |
|--------|-----------|---------|
| F18 | `components/datasinks/telemetry_parser.py:65-69` | non-ASCII byte in `PaddedString` field |
| F23 | `components/datasinks/telemetry_parser.py:65-69` and `telemetry/by70_1.py:62-63` | `log10(0)` on RSSI=0 |
| F65 | `usp/usp_ax25_crop.py:43-44` | short input |
| F66 | `usp/usp_pls_crop.py:65-68` | empty input to `np.argmax` |
| F68 | `mobitex_to_datablocks.py:248-251` | short input |
| F69 | `ccsds/space_packet_primaryheader_adder.py:55,65` | input > 65535 bytes |
| F70 | `ccsds/telemetry_packet_reconstruction.py:53,64` | header passes, payload fails |
| F71 | `components/deframers/sanosat_deframer.py:44` and `hades_deframer.py:44` | empty input |
| F72 | `filereceiver/by70_1.py:22-25` | catches only `ConstructError`, not `ValueError` |
| F73 | `components/datasinks/file_receiver.py:65` | no try/except around `push_chunk` |
| F98 | `python/snet_deframer.py:41` | `bits[:210].reshape((15,14))` ValueError |

## Affected satellites

Around 55 distinct satellites across the sub-findings:

- F18: AmicalSat, SMOG-P, SMOG-1, ATL-1, TUBIN, MRC-100 (and any with PaddedString fields)
- F23/F72/F73: BY70-1, MIRSAT-1
- F65: 28 USP-framing satellites
- F68: 16 Mobitex / BEESAT-family satellites
- F71: HADES-R, HYDRA-T, HYDRA-W, SanoSat-1


## Proof of concept

`pocs/F18-parser-narrow-except/poc_F18_cluster.py` is a single script with six independent reproducers — one per fixed sub-finding (F18 unicode, F23/F72 RSSI=0, F65 short USP, F71 empty SanoSat/HADES, F73 file_receiver dispatch, F98 reshape). Each demonstrates the unpatched exception escaping `except ConstructError:` and the post-patch behaviour that drops the frame instead. `run.sh` builds the gr-satellites Python path and invokes the script.

## Fix

`patches/0006-F18-parser-broaden-except.patch`. Broadens `except ConstructError:` to `except Exception:` in the seven sites verified end-to-end with PoCs (`telemetry_parser`, both `by70_1` modules, `usp_ax25_crop`, `sanosat_deframer`, `hades_deframer`, `file_receiver`) and adds length guards where the code indexes into input without checking. Other `handle_msg` definitions in the Python tree may share the architectural pattern; the patch deliberately covers only the sites with reproducers and leaves per-site review to the maintainer.

## Notes

Reported by Marnick Vandecauter security@marnick.net as part of an independent security audit of gr-satellites v5.9.0 (May 2026). Research supported by Mamato Labs.
