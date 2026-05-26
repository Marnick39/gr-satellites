#!/usr/bin/env python3
"""F10/F12 — bug-condition reproducer without GNU Radio.

The "real" PoCs (poc_f10.py, aslr_bypass_demo.py, heap_content_analysis.py)
need `pmt` from GNU Radio installed because the actual heap leak fires
inside CPython's PMT vector helper. This script is the no-GR
demonstration that the buggy CONDITION is reachable: it reimplements the
three call sites without the pmt.init_u8vector call and shows that an
attacker-controlled length field reliably produces `packet_length >
len(packet)`, which is the precondition for the over-read.

If pmt is installed, also runs poc_f10.py for the real-leak demo.

Run:
    python3 poc_F10_logic_only.py
"""

import importlib.util
import struct
import sys


# ----------------------------------------------------------------------
# cc11xx_packet_crop.handle_msg reimpl WITHOUT the pmt.init_u8vector call
# ----------------------------------------------------------------------
def cc11xx_unpatched(packet_bytes, use_crc16=True):
    """Returns (would_overread: bool, packet_length: int)."""
    crc_len = 2 if use_crc16 else 0
    # The length byte at packet[0] is attacker-controlled (it comes from RF)
    packet_length = packet_bytes[0] + 1 + crc_len
    return packet_length > len(packet_bytes), packet_length


def cc11xx_patched(packet_bytes, use_crc16=True):
    crc_len = 2 if use_crc16 else 0
    packet_length = packet_bytes[0] + 1 + crc_len
    if packet_length > len(packet_bytes):
        return None  # drop the frame
    return packet_bytes[:packet_length]


# ----------------------------------------------------------------------
# spino_deframer.handle_msg reimpl WITHOUT pmt.init_u8vector
# ----------------------------------------------------------------------
def spino_unpatched(msg):
    """16-bit length field; attacker-controlled 0..65535+16 range."""
    length = struct.unpack('<H', bytes(msg[16:18]))[0]
    length += 16   # AX.25 headers + CRC
    return length > len(msg), length


def main():
    print('=== F10/F12 — bug condition without GNU Radio ===')
    print()

    # cc11xx: declared length 0xff (attacker maximum)
    rf_frame = bytearray(131)   # actual received bytes
    rf_frame[0] = 0xff          # attacker says "really there are 255 bytes"
    overread, declared = cc11xx_unpatched(rf_frame)
    print(f'  cc11xx_packet_crop:')
    print(f'    received {len(rf_frame)} bytes; declared length {declared} '
          f'(packet[0]=0xff + 1 + 2)')
    print(f'    over-read condition reached: {overread}')
    print(f'    patched output: {"None (drop)" if cc11xx_patched(rf_frame) is None else "OK"}')
    print()

    # spino: 16-bit length field
    spino_frame = bytearray(50)
    struct.pack_into('<H', spino_frame, 16, 0xffff)
    overread, declared = spino_unpatched(spino_frame)
    print(f'  spino_deframer:')
    print(f'    received {len(spino_frame)} bytes; declared length {declared} '
          f'(16-bit attacker field 0xffff + 16)')
    print(f'    over-read condition reached: {overread}')

    print()
    print('[PASS] F10/F12 condition reachable: attacker-controlled length'
          ' field exceeds')
    print('       received-buffer size in both call sites. In production')
    print('       (with pmt.init_u8vector), this causes the over-read to'
          ' publish heap')
    print('       bytes downstream — see poc_f10.py for the real-leak demo'
          ' (needs GR).')

    if importlib.util.find_spec('pmt') is not None:
        print()
        print('GR/pmt available — also running poc_f10.py:')
        import subprocess, os
        here = os.path.dirname(os.path.abspath(__file__))
        subprocess.call([sys.executable,
                         os.path.join(here, 'poc_f10.py')])


if __name__ == '__main__':
    main()
