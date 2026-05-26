# F4 PoCs — qo100_multimedia path traversal -> RCE

Two PoCs covering the same vulnerability at different evidence tiers:

```
./poc_F4_rce_e2e.sh                 # T4 end-to-end RCE
python3 poc_F4_path_traversal.py    # T3 arbitrary-write isolation
```

## T4 — end-to-end RCE chain (poc_F4_rce_e2e.sh / .py)

Self-contained, no GNU Radio installation required. Demonstrates the
full chain from RF-supplied filename to attacker code executing inside
a `python3` process running as the operator user.

Pipeline:

```
crafted multimedia chunk
    -> file_id()  returns the attacker's 50-byte ASCII string
        -> _new_file()  composes Path(receiver_base) / fid
                        (absolute rhs wins; the result is the
                        attacker's path, not inside the base)
            -> open(path, 'wb')  writes the payload
                -> .pth file lands in a site-packages directory
                    -> any subsequent python3 invocation
                        -> CPython site.py auto-execs the line
                            -> attacker code runs as operator
```

The PoC isolates from the host's real `~/.local` by setting
`PYTHONUSERBASE=/tmp/F4ub`, so a fresh user-site directory is created
under `/tmp` and the host environment is never modified. Cleans up
after itself.

Last observed output (gr-sat-audit host, 2026-05-25):

```
[1] file_id(chunk) returned: '/tmp/F4ub/lib/python3.10/site-packages/o.pth'
[2] _new_file() opened:      /tmp/F4ub/lib/python3.10/site-packages/o.pth
    inside receiver base?    False
[3] Wrote 162 bytes to /tmp/F4ub/lib/python3.10/site-packages/o.pth
[5] child python3 -c pass exited 0
[6] Marker file created at:  /tmp/RCE_MARKER
    contents:                RCE-EXECUTED-IN-PYTHON pid=94644 exe=/usr/bin/python3 argv=['-c']
[PASS] F4 chain confirmed end-to-end
CVSS 3.1 (validated): AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H = 8.4 High
```

The PoC reimplements `FileReceiverQO100Multimedia.file_id()` and
`FileReceiver._new_file()` verbatim from
`src/python/filereceiver/qo100_multimedia.py` and
`src/python/filereceiver/filereceiver.py` (gr-satellites v5.9.0,
commit `f663ee4`). No mocks at the vulnerable code level. The Python
interpreter, the `site` module, and the `.pth` auto-execution
mechanism are all stock CPython 3.x.

### Containerised alternative

A Dockerfile is provided for maintainers who want strict isolation:

```
docker build -t f4 .
docker run --rm --network=none f4
```

Same PoC inside a python:3.10-slim container with an unprivileged user
named `op`. (Skip this if your host can't run nested containers — the
non-docker path covers the same ground.)

## T3 — arbitrary file write only (poc_F4_path_traversal.py)

The earlier reproducer; demonstrates the write-outside-base primitive
without exercising the `.pth` chain. Kept for the case where you only
want to verify the path-traversal step.

## After patches/0001-F4-qo100-multimedia-filename-sanitization.patch

Apply the patch, re-run the e2e PoC. Expected outcome:

```
[1] file_id(chunk) returned: 'o.pth'      <- path components stripped
[2] _new_file() opened:      /tmp/grs_recv/o.pth
    inside receiver base?    True
[3] Wrote 162 bytes to /tmp/grs_recv/o.pth
[4] .pth file present at:    /tmp/F4ub/.../o.pth
[FAIL] .pth did not land at /tmp/F4ub/lib/python3.10/site-packages/o.pth
```

Step 4 fails because the patch redirects the write into the receiver
base; `/tmp/F4ub/lib/python3.10/site-packages/o.pth` is never created;
the child python3 has nothing to autoload; no marker file.

## Why this is RCE, not just file write

`.pth` files in any `site-packages` directory are auto-processed by
CPython's `site` module at every interpreter startup, before user code
runs. Lines starting with `import ` (or `import\t`) are passed to
`exec()` verbatim. So an attacker who can write to a `.pth` file in
any site-packages on `sys.path` gets code execution under the user
that invokes Python next.

For a SatNOGS-style ground-station Pi running gr-satellites as the
default `pi` user, that user-site directory is
`~/.local/lib/pythonX.Y/site-packages/`. For a multi-user university
ground station with the operator running gr_satellites under their
own account, same pattern. For a root-as-operator install (legacy
deployments where gr-satellites needs raw socket access), the
attacker can also write to `/usr/lib/pythonX.Y/dist-packages/`.

The receive directory of the QO-100 multimedia decoder is operator-
controlled but typically `/tmp/` or `~/.gr_satellites/multimedia/`,
neither of which is on the .pth scan path; the path traversal /
absolute-path primitive is what makes the chain work.
