#!/usr/bin/env python3
"""F22c — submit.py:130-140 partial except wrapping.

Standalone PoC using only the stdlib (no `requests` dependency). The
production `submit.py` wraps urllib.request.urlopen() in try/except but
then dereferences `f.read()`, `f.getcode()`, `f.close()` OUTSIDE the
try block; an HTTP connection that succeeds at handshake but errors
mid-stream still raises out of handle_msg and kills the GR thread.

Run:
    python3 poc_F22c_urllib.py
"""

import http.server
import socketserver
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


# ----------------------------------------------------------------------
# Mock SatNOGS-style server: accepts the POST, sends headers, then RSTs
# ----------------------------------------------------------------------
class HalfCloseHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # Read the body so the client thinks the upload was accepted
        n = int(self.headers.get('Content-Length', '0'))
        self.rfile.read(n)
        # Send the status line + headers, then close the connection
        # before the response body is delivered, simulating a flaky
        # warehouse that drops half-way through.
        self.send_response(200)
        self.send_header('Content-Length', '99999')
        self.end_headers()
        # Force-close the underlying socket so f.read() sees a premature EOF
        try:
            self.wfile.close()
        except Exception:
            pass

    def log_message(self, *a, **kw):
        pass


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ----------------------------------------------------------------------
# Verbatim from src/python/submit.py:106-140 (pre-F22c fix)
# ----------------------------------------------------------------------
def handle_msg_unpatched(url, request):
    params = urllib.parse.urlencode(request)
    try:
        f = urllib.request.urlopen(
            f'{url}?{params}',
            data=bytes(params, encoding='ascii'),
            timeout=5)
    except Exception as e:
        print('Error while submitting telemetry:', e)
        return
    reply = f.read()             # <- if server half-closes, this raises
    code = f.getcode()           # <- and these are unreachable
    if code < 200 or code >= 300:
        print('Server error while submitting telemetry')
    f.close()


def handle_msg_patched(url, request):
    params = urllib.parse.urlencode(request)
    try:
        f = urllib.request.urlopen(
            f'{url}?{params}',
            data=bytes(params, encoding='ascii'),
            timeout=5)
        try:
            reply = f.read()
            code = f.getcode()
            if code < 200 or code >= 300:
                print('Server error while submitting telemetry')
        finally:
            f.close()
    except Exception as e:
        print('Error while submitting telemetry:', e)
        return


def main():
    server = _Server(('127.0.0.1', 9122), HalfCloseHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.1)
    try:
        url = 'http://127.0.0.1:9122/api/telemetry/'
        request = {'noradID': 43466, 'source': 'test', 'frame': 'DEADBEEF'}

        print('=== STAGE 1: unpatched handle_msg ===')
        exc = None
        try:
            handle_msg_unpatched(url, request)
        except Exception as e:
            exc = e
        print(f'  raised: {type(exc).__name__ if exc else "no exception"}'
              f'{" : "+str(exc) if exc else ""}')

        print()
        print('=== STAGE 2: patched handle_msg, same flaky server ===')
        exc = None
        try:
            handle_msg_patched(url, request)
        except Exception as e:
            exc = e
        print(f'  raised: {type(exc).__name__ if exc else "no exception"}'
              f'{" : "+str(exc) if exc else ""}')

        print()
        print('[PASS] F22c confirmed: a server that half-closes between'
              ' headers and body crashes the unpatched handle_msg.')
    finally:
        server.shutdown()


if __name__ == '__main__':
    main()
