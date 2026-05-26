# Advisory 9 — Credential file mode exposes telemetry-submitter tokens to other local users

CVSS 3.1: `AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` = **4.4 Medium**
CWE: CWE-732 (incorrect permission assignment), CWE-377 (insecure temporary file)
Affected: gr-satellites `>= 3.0.0, <= 5.9.0` (`utils/config.py` introduced in commit `28cc751f`, 2019-11-10, first released in v3.0.0)
Audit reference: F16 + F26 + F27 (three related defects, one fix)

## What happens

gr-satellites writes telemetry-submitter credentials in plaintext to `~/.gr_satellites/config.ini`. The file is created with the default umask, which on typical systems yields mode `0o644` (file) and `0o755` (parent directory). Any other unprivileged user on the same Unix host can read the credentials.

The config file commonly contains:

- `[FUNcube] auth_code` — AMSAT-UK warehouse authentication token
- `[BME] password` — BME (Budapest Univ. of Tech) ground station password, plaintext
- `[PW-Sat2] credentials_file` — path pointing to a JSON file with PW-Sat2 credentials (the JSON file inherits the same default mode)

Three related defects bundle here:

- **F16** — `config.py:25,65` creates the file without constraining the mode
- **F26** — `config.py:24-25` calls `Path.mkdir()` without `exist_ok=True`; two simultaneous gr-satellites starts can race and one aborts with `FileExistsError`
- **F27** — parent directory `~/.gr_satellites/` is created world-traversable, which lets another user reach the config path

## Who's actually affected

Multi-user Unix hosts where the gr-satellites operator shares the machine with other users. The realistic populations:

- University and amateur-radio-club ground stations (KSU SatLab, TU Berlin, BME-MARTOS, AMSAT-DL, etc.) where students rotate access on a shared Raspberry Pi or workstation. Globally: dozens of stations, each with 5-20 active accounts.
- Multi-user VPS receivers (citizen-science groups running observers on shared cloud)
- Shared lab Pis with `pi:raspberry` default and a secondary account on the same hardware

Single-user home installations (most SatNOGS Pi deployments) are not directly affected. The fix benefits them anyway by reducing accidental exposure surface from backup-restore mishaps or accidental `chmod -R 777`.

## What the leaked credentials get you

| Credential | What an attacker can do |
|------------|--------------------------|
| BME password | Authenticated upload to `gnd.bme.hu`. Submit forged telemetry under the victim's callsign. Reputation impact; no monetary loss; no SSH access. |
| FUNcube auth_code | Authenticated POST to `data.amsat-uk.org`. Same forged-telemetry impact under the victim's site_id. |
| PW-Sat2 credentials | Historical only. Satellite deorbited 2021-02-13; the endpoint host is up but the app is gone. Residual risk is operator password reuse on other ham-radio services. |

The credential ecosystem is constrained to warehouse / auth tokens. No SSH key compromise, no remote-network attack.


## Proof of concept

`pocs/F16-F26-F27-config-perms/run.sh` invokes three verbatim reimplementations of the unpatched config-write paths under a `tempfile.TemporaryDirectory()`:

- `poc_F16_world_readable.py` — writes a config containing a sentinel credential (`HUNTER2_SECRET`, `FUNCUBE_TOKEN_DEADBEEF`), then re-reads it as a different process and prints the credential, demonstrating that the default mode lets another local-uid read the file
- `poc_F26_mkdir_race.py` — a two-thread test that yields `FileExistsError` deterministically from the unguarded `Path.mkdir()` call
- `poc_F27_dir_traversable.py` — shows the parent dir is created world-traversable so a non-owner can reach the config path

A multi-user-host walkthrough (`useradd attacker; su - attacker -c 'cat /home/victim/.gr_satellites/config.ini'`) reproduces the same outcome on any Linux box but is not shipped as a script — the in-process PoCs cover the same primitive without needing root.

## Fix

`patches/0009-F16-F26-F27-config-mode.patch`:

```python
import os
path.parent.mkdir(mode=0o700, exist_ok=True)
fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as f:
    config.write(f)
# For existing files: os.chmod(path, 0o600) on load
```

## Behaviour change for existing operators

The fix calls `os.chmod(config.ini, 0o600)` on load if the existing
file has any non-owner mode bits set. Operators relying on a sidecar
process (monitoring scripts, log shippers) running as a different uid
to grep `~/.gr_satellites/config.ini` for `callsign=` or similar will
now get `EACCES` on those reads. The recommended migration is for the
sidecar to read from a separate, intentionally-shared status file
rather than the credentials-bearing config.ini. Release notes should
call this out.

## Notes

Reported by Marnick Vandecauter security@marnick.net as part of an independent security audit of gr-satellites v5.9.0 (May 2026). Research supported by Mamato Labs.
