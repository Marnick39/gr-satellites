# Advisory 1 — RCE via path traversal in QO-100 multimedia file receiver

CVSS 3.1: `AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H` = **8.4 High**
CWE: CWE-22 (path traversal), chaining to CWE-829 (inclusion from untrusted control sphere) via Python `.pth`
Affected: gr-satellites `>= 4.7.0, <= 5.9.0` (the `qo100_multimedia` receiver was added in commit 4fc636d, first released in v4.7.0)
Audit reference: F4

## What happens

`FileReceiverQO100Multimedia.file_id()` at `python/filereceiver/qo100_multimedia.py:70-84` reads 50 ASCII bytes from a received frame and passes them straight to `Path.__truediv__` in `FileReceiver._new_file()` at `python/filereceiver/filereceiver.py:206-217`. `pathlib` doesn't strip `..` segments when composing paths, so an attacker who can transmit a QO-100 multimedia beacon frame can choose any path the operator's user can write to.

Writing a Python `.pth` file into `~/.local/lib/python3.X/site-packages/` gets the file executed by CPython's `site.addpackage()` on the next `python3` invocation — including `pip`, `jupyter`, build scripts, and the operator's next `gr_satellites` launch. The execution crosses the gr-satellites process boundary into the operator's user account.

## Proof of concept

End-to-end RCE chain in `pocs/F4-rce/`:

```
./poc_F4_rce_e2e.sh
```

Reimplements `FileReceiverQO100Multimedia.file_id()` and
`FileReceiver._new_file()` verbatim from commit `f663ee4`, drives them
with one crafted 219-byte chunk, then spawns `python3 -c pass` so
CPython's `site` module auto-scans the planted `.pth`. Host isolation
is via `PYTHONUSERBASE=/tmp/F4ub` so the host's real `~/.local` is
never touched. Cleans up after itself.

Observed output (gr-sat-audit host, 2026-05-25):

```
[1] file_id(chunk) returned: '/tmp/F4ub/lib/python3.10/site-packages/o.pth'
[2] _new_file() opened:      /tmp/F4ub/lib/python3.10/site-packages/o.pth
    inside receiver base?    False
[3] Wrote 162 bytes to /tmp/F4ub/lib/python3.10/site-packages/o.pth
[5] child python3 -c pass exited 0
[6] Marker file created at:  /tmp/RCE_MARKER
    contents:                RCE-EXECUTED-IN-PYTHON pid=94644 exe=/usr/bin/python3 argv=['-c']
[PASS] F4 chain confirmed end-to-end
```

The marker file's PID does not match the PoC parent's PID — proof the
payload executed in a freshly-spawned `python3 -c pass`, not in the
PoC's own interpreter.

A T3 arbitrary-write-only PoC also ships at
`pocs/F4-rce/poc_F4_path_traversal.py` for cases where only the
path-traversal step needs verifying. A `Dockerfile` is included for
maintainers who prefer container isolation; the non-docker path
covers the same ground without docker as a dependency.

## Who's affected

Anyone running the `examples/qo100-multimedia-beacon/*.grc` flowgraphs or wiring `FileReceiverQO100Multimedia` into a custom flowgraph. Operationally that's the AMSAT-DL QO-100 multimedia beacon receiver community — the maintainer estimates fewer than ten active operators globally, all within Es'hail-2's footprint (Europe, Africa, Middle East, western Asia, parts of South America). The example was intended as a demo of multimedia-beacon decoding rather than a production decoder, which constrains the realistic affected population.

The Americas, East Asia, Australia, and CONUS are out of the geostationary footprint and cannot be reached.

Venv and Conda users don't auto-execute `.pth` files outside their venv site-packages, so they're not affected by the `.pth` vector specifically. They are still affected by the underlying arbitrary file write — `~/.bashrc`, `~/.ssh/authorized_keys`, autostart files all work as alternative payload targets.

## Why AV:A + AC:H

**AC:H**: landing the `.pth` payload needs the operator's Python minor version, username, home-directory layout, and non-venv state to line up. Without those, the file lands somewhere harmless.

**AV:A**: as noted by Daniel E. that practical exploitation requires either RF proximity to the victim's antenna boresight (directional 10 GHz dish) or QO-100 uplink power exceeding the legitimate beacon — which AMSAT-DL's LEILA interference suppression would clip and the operator community would notice.

## Fix

8-line change in `file_id()` strips path components, normalises with `os.path.basename(os.path.normpath(...))`, and rejects empty / `.` / `..` results before `_new_file()` is reached. Patch: `patches/0001-F4-qo100-multimedia-filename-sanitization.patch`.

## Notes

Reported by Marnick Vandecauter security@marnick.net as part of an independent security audit of gr-satellites v5.9.0 (May 2026). Research supported by Mamato Labs.
