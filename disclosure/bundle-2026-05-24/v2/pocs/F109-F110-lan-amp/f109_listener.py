#!/usr/bin/env python3
"""
F109/F110 LAN-amplifier listener (verbatim port of the shipped
examples' TCP_SERVER socket_pdu block).

Models exactly what `examples/ax25/afsk.grc` line 361 produces when grcc
compiles it: a `network.socket_pdu(type='TCP_SERVER', host='', port='52001')`.
A separate downstream PDU-debug block prints any PDU received from the
network. That downstream block stands in for the satellites_kiss_to_pdu /
hdlc_framer chain that the shipped flowgraph wires up — anything an
attacker sends over TCP flows into it.

Runs inside `gr-sat-audit:latest`. No SDR, no RF, no audio.
"""
import sys
import time
import threading

from gnuradio import gr, network, blocks
import pmt


class ChainFListener(gr.top_block):
    """
    Verbatim Python equivalent of `network_socket_pdu_0` from
    examples/ax25/afsk.grc lines 355-374:

        - name: network_socket_pdu_0
          id: network_socket_pdu
          parameters:
            host: ''            # <-- THIS IS F109
            port: '52001'
            type: TCP_SERVER
            mtu: '10000'
            tcp_no_delay: 'True'

    `host=''` is the shipped default; GR's `gr::network::socket_pdu`
    treats this as "bind 0.0.0.0" — i.e. all interfaces (LAN-reachable).
    """

    def __init__(self):
        gr.top_block.__init__(self, "F109 listener")

        # Verbatim GR block instantiation that grcc emits for the .grc.
        # This is the same call grcc generates from afsk.grc's YAML.
        self.network_socket_pdu_0 = network.socket_pdu(
            'TCP_SERVER',   # type
            '',             # host  <-- F109: empty -> 0.0.0.0
            '52001',        # port
            10000,          # MTU
            True,           # tcp_no_delay
        )

        # Sink: print every incoming PDU. Stand-in for the satellites_*
        # downstream chain in afsk.grc (pdu_to_tagged_stream → kiss_to_pdu
        # → hdlc_framer → ...). The presence of bytes here proves the LAN
        # attacker reached the GR scheduler.
        self.received = []
        self.received_lock = threading.Lock()

        def sink_handler(msg_pmt):
            if pmt.is_pair(msg_pmt):
                vec = pmt.cdr(msg_pmt)
                if pmt.is_u8vector(vec):
                    payload = bytes(pmt.u8vector_elements(vec))
                    with self.received_lock:
                        self.received.append(payload)
                    print(f'[listener] PDU received: {len(payload)} bytes  '
                          f'first16={payload[:16].hex()}', flush=True)

        # Use a blocks.message_debug to consume and store the PDUs.
        self.message_sink = blocks.message_debug()
        self.msg_connect(
            (self.network_socket_pdu_0, 'pdus'),
            (self.message_sink, 'store'),
        )

        # Also register our Python handler so we can see it without
        # poking GR internals from outside.
        # (message_debug stores PDUs internally; we mirror via a custom
        # handler block.)
        self._handler_block = blocks.copy(gr.sizeof_char)  # placeholder
        self._sink_handler = sink_handler


def main():
    print('#' * 72)
    print('# F109/F110 LAN-amplifier listener')
    print('# Replicates afsk.grc TCP_SERVER socket_pdu bind (host="")')
    print('#' * 72)

    tb = ChainFListener()
    print('[listener] Starting flowgraph...', flush=True)
    tb.start()

    # Confirm the bind is on 0.0.0.0:52001 by checking netstat-equivalent
    # information from /proc/net/tcp. GR opens the socket inside start().
    time.sleep(0.5)

    import re
    bind_seen = False
    try:
        with open('/proc/net/tcp', 'r') as f:
            for line in f:
                # local_address is hex:port — '0.0.0.0:52001' = 00000000:CB21
                # 52001 = 0xCB21
                m = re.search(r'\s00000000:CB21\s', line)
                if m:
                    bind_seen = True
                    print(f'[listener] /proc/net/tcp shows: '
                          f'LISTEN on 0.0.0.0:52001  (F109 confirmed)',
                          flush=True)
                    break
    except Exception as e:
        print(f'[listener] could not read /proc/net/tcp: {e}', flush=True)

    if not bind_seen:
        print('[listener] WARNING: did not find 0.0.0.0:52001 in '
              '/proc/net/tcp — bind may not be wildcard', flush=True)

    # Wait for incoming PDUs for a short window (attacker will inject).
    print('[listener] Waiting for attacker injection (max 15s)...',
          flush=True)
    deadline = time.time() + 15.0
    n_seen = 0
    while time.time() < deadline:
        time.sleep(0.5)
        # Pull stored PDUs out of message_debug
        n = self_pdu_count(tb.message_sink)
        if n > n_seen:
            for i in range(n_seen, n):
                pdu = tb.message_sink.get_message(i)
                if pmt.is_pair(pdu):
                    vec = pmt.cdr(pdu)
                    if pmt.is_u8vector(vec):
                        payload = bytes(pmt.u8vector_elements(vec))
                        print(f'[listener] downstream block received: '
                              f'{len(payload)} bytes — '
                              f'first16={payload[:16].hex()}',
                              flush=True)
                        # If KISS framing visible, decode
                        if payload[:1] == b'\xc0':
                            print(f'[listener]   -> begins with KISS FEND '
                                  f'(0xC0): the byte stream IS recognized '
                                  f'as a KISS frame by downstream blocks',
                                  flush=True)
            n_seen = n
            # Got our injection; exit early.
            break

    tb.stop()
    tb.wait()

    print()
    print('#' * 72)
    print(f'# RESULT: bind_observed={bind_seen}  pdus_received={n_seen}')
    print('#' * 72)
    return 0 if (bind_seen and n_seen > 0) else 1


def self_pdu_count(message_debug):
    """gr blocks.message_debug exposes num_messages() per port."""
    try:
        return message_debug.num_messages()
    except Exception:
        return 0


if __name__ == '__main__':
    sys.exit(main())
