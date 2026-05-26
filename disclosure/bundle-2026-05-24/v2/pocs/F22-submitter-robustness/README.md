# F22 cluster PoC — telemetry-submitter network exception robustness

```
./run.sh
```

Reimplements `funcube_submit.handle_msg`, `pwsat2_submitter.handle_msg`,
`bme_submitter.{authenticate,putPacket}`, `bme_ws_submitter.submit`, and
`submit.handle_msg` from gr-satellites v5.9.0 src verbatim. Drives each
against an in-process mock HTTP/TCP server that:

- accepts the TCP connection then sends RST (simulates warehouse closing
  the stream after handshake)
- returns malformed JSON instead of the expected response shape
  (simulates a proxy returning an HTML error page)
- hangs indefinitely (simulates a stalled warehouse)

Asserts the unpatched handler raises an exception in each case. In real
gr-satellites, that exception escapes `handle_msg` upward to the GR
thread-per-block scheduler, which catches it once and never respawns the
thread — every subsequent telemetry submission is silently dropped while
the rest of the flowgraph keeps running.

F21 has a dedicated reproducer in `../F15-F21-F24-privacy/poc_F21_dead_guard.py`.
F23 has a focused reproducer in `../F18-parser-narrow-except/poc_F18_cluster.py`.
