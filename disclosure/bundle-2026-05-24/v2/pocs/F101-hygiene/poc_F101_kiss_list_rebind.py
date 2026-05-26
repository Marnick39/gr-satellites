#!/usr/bin/env python3
"""F101 hygiene PoC — KISS packet buffer rebind across multi-FEND TM frame.

Reimplements the unpatched handle_msg byte-loop from
python/components/transports/tm_kiss_transport.py:60-77. Drives it with
a synthesized TM payload that contains TWO KISS FEND delimiters and
asserts the second-published packet contains only the bytes received
AFTER the first FEND, not the orphan accumulation from the rebound
list.

No GNU Radio needed.

Run:
    python3 poc_F101_kiss_list_rebind.py
"""

FEND = 0xC0
TFEND = 0xDC
TFESC = 0xDD
FESC = 0xDB


def handle_unpatched(payload):
    """Verbatim from tm_kiss_transport.py:60-77 pre-F101 fix."""
    packets = {0: []}
    transpose = {0: False}
    published = []

    vc = 0
    packet = packets[vc]

    for c in payload:
        if c == FEND:
            if len(packet) > 0:
                published.append(list(packet))   # publish the current list
                packets[vc] = []                 # <-- the bug: rebind dict
                                                 #     entry; local 'packet'
                                                 #     still points at the
                                                 #     orphan
        elif transpose[vc]:
            if c == TFEND:
                packet.append(FEND)
            elif c == TFESC:
                packet.append(FESC)
            transpose[vc] = False
        elif c == FESC:
            transpose[vc] = True
        else:
            packet.append(c)

    return published


def handle_patched(payload):
    """Post-F101: clear in place via packet.clear() instead of rebinding."""
    packets = {0: []}
    transpose = {0: False}
    published = []

    vc = 0
    packet = packets[vc]

    for c in payload:
        if c == FEND:
            if len(packet) > 0:
                published.append(list(packet))
                packet.clear()   # <-- the fix
        elif transpose[vc]:
            if c == TFEND:
                packet.append(FEND)
            elif c == TFESC:
                packet.append(FESC)
            transpose[vc] = False
        elif c == FESC:
            transpose[vc] = True
        else:
            packet.append(c)
    return published


def main():
    # Payload contains TWO complete KISS packets separated by FEND:
    #   packet 1: 0x11 0x22 0x33
    #   FEND
    #   packet 2: 0xAA 0xBB 0xCC
    #   FEND
    payload = [0x11, 0x22, 0x33, FEND, 0xAA, 0xBB, 0xCC, FEND]

    pub_unpatched = handle_unpatched(payload)
    pub_patched = handle_patched(payload)

    print('=== F101 — multi-FEND list-rebind hygiene PoC ===')
    print(f'  input payload:        {payload}')
    print(f'  unpatched published:  {pub_unpatched}')
    print(f'  patched published:    {pub_patched}')
    print()

    # On the unpatched code, the SECOND packet appears as published —
    # but it landed in the orphan list, not the fresh one. The
    # accumulation actually drained into the orphan list AND the
    # rebound entry was never repopulated, so the second iteration
    # published the ORPHAN's content (which kept growing across the
    # rebind boundary).
    expected_unpatched_corruption = [[0x11, 0x22, 0x33],
                                     [0x11, 0x22, 0x33, 0xAA, 0xBB, 0xCC]]
    if pub_unpatched == expected_unpatched_corruption:
        print('  [PASS] F101 confirmed: second published packet contains the '
              'orphan accumulation')
        print('         (bytes from BEFORE the first FEND leak into the '
              'second publication)')
    elif pub_patched == [[0x11, 0x22, 0x33], [0xAA, 0xBB, 0xCC]]:
        print('  [PASS] patched code publishes the two packets correctly')


if __name__ == '__main__':
    main()
