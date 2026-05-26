# Advisory 7 — Privacy: default-on telemetry submission combined with broken opt-out

CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = **5.3 Medium**
CWE: CWE-1188 (insecure default initialization), CWE-571 (expression is always true)
Affected: gr-satellites `>= 3.0.0, <= 5.9.0` (the F15 default-write requires `python/utils/config.py` which was introduced in commit `28cc751f`, 2019-11-10, first released in v3.0.0; F21 is older but the cluster is bounded by F15)
Audit reference: F15 + F21 + F24 (three interlocking defects, one fix)

## What happens

Three bugs combine to defeat the operator's reasonable belief that they have opted out of public telemetry submission.

**F15 — the default contradicts the documentation.** `python/utils/config.py:48` writes `submit_tlm = yes` into a freshly created config file. The docs at `docs/source/command_line.rst:531` show `submit_tlm = no` as the example. An operator following the docs and expecting opt-out-by-default gets opt-in-by-default.

**F21 — the lat/lon zero guard is dead code.** `python/submit.py:104-106` tries to skip submission when the operator hasn't set GPS coordinates:

```python
if data['latitude'] == 0 and data['longitude'] == 0:
    return
```

Upstream the fields are stringified to `'0.0E'` and `'0.0N'`, so the comparison is `'0.0E' == 0` which is always False. The guard never fires. Operators who leave their coordinates at the default to avoid disclosing their station location still get their coordinates uploaded.

**F24 — the environment variable opt-out crashes on natural values.** `python/core/gr_satellites_flowgraph.py:215-217` parses `GR_SATELLITES_SUBMIT_TLM` with `bool(int(value))`. The empirical 16-value test matrix:

| Value tried | Result |
|-------------|--------|
| `no`, `false`, `off`, `disabled`, `yes`, `true`, `on`, `No`, `False`, `OFF`, `''` | flowgraph crashes with ValueError (`int('no')` etc. all raise) |
| `-1`, `2`, `999` | submission silently enabled (`bool(int('-1'))` is `True`) |
| `0`, `1` | honors operator intent |

The config-file path uses `configparser.getboolean()` which accepts the seven natural tokens; the env path uses bare `int()` which doesn't. Same project, two parsers, inconsistent semantics.

## Combined effect

An operator who reasonably believes they have opted out — by leaving lat/lon at defaults, by exporting `GR_SATELLITES_SUBMIT_TLM=no`, or by trusting the documented default — is silently submitting telemetry to the public SatNOGS DB. The DB stores submissions indefinitely. The operator's callsign (often correlatable via QRZ.com), GPS coordinates, and per-frame RF hex bytes are publicly queryable.


## Proof of concept

`pocs/F15-F21-F24-privacy/run.sh` invokes three small verbatim reimplementations of the unpatched code paths:

- `poc_F15_default.py` — calls `write_default_config()` against a fresh temp dir and shows the resulting file has `submit_tlm = yes` despite the docs saying `no`
- `poc_F21_dead_guard.py` — exercises the `if data['latitude'] == 0 and data['longitude'] == 0` guard with the stringified `'0.0E'` / `'0.0N'` values gr-satellites actually produces and shows the comparison is always False
- `poc_F24.py` — exercises `bool(int(os.environ['GR_SATELLITES_SUBMIT_TLM']))` across a 16-value matrix and prints which values crash, which silently enable, and which honor operator intent

## Fix

`patches/0007-F15-F21-F24-privacy-defaults.patch`. Three small changes:

1. Default `submit_tlm: 'no'` in `config.py`
2. Compare lat/lon as floats in `submit.py`
3. Replace `bool(int(env))` with `configparser.ConfigParser().getboolean()` semantics

## Behaviour change for existing operators

**F15 only affects fresh installs.** Operators with an existing
`~/.gr_satellites/config.ini` will see no change — `write_default_config`
is only called when the file does not exist. Net effect: first-time
operators after the patch lands no longer auto-opt-in, but the patch
does not silently flip telemetry off for anyone already running.
Release notes should still call this out so operators know the default
is now privacy-preserving.

F21 has no behaviour change — the guard never fired before; now it
fires for operators who left lat/lon at 0,0, which is the documented
opt-out path.

F24 changes the env-var grammar: `GR_SATELLITES_SUBMIT_TLM=no` will
now turn submission off cleanly instead of crashing. Operators using
`-1`, `2`, `999` to "force enable" (a documented misfeature) will need
to switch to `1` or `true`.

## Notes

Reported by Marnick Vandecauter security@marnick.net as part of an independent security audit of gr-satellites v5.9.0 (May 2026). Research supported by Mamato Labs.
