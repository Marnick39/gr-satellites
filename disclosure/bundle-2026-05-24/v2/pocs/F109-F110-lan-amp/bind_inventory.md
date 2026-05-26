# F109/F110 — bind-default inventory (gr-satellites v5.9.0)

Evidence captured 2026-05-24. Every cited line is verbatim from the
shipped `.grc` (verified via `grep -nE "host:.*''|host:.*0\.0\.0\.0|ipaddr"`
against the in-tree `src/examples/` tree).

## 1. KISS TCP_SERVER `socket_pdu` — bind defaults to `host: ''` (= 0.0.0.0)

GNU Radio's `gr::network::socket_pdu` resolves an empty `host`/`addr`
string to `INADDR_ANY` (0.0.0.0) when `TCP_SERVER`. Empirically confirmed
via `cat /proc/net/tcp` inside `gr-sat-audit:latest` showing
`00000000:CB21 ... 0A` (LISTEN on 0.0.0.0:52001) after a flowgraph using
the shipped parameters is started — see `run_poc.log`.

| File | Line | Block id | Param | Port |
|------|------|----------|-------|------|
| `src/examples/ax25/afsk.grc` | 361 | `network_socket_pdu` (`network_socket_pdu_0`) | `host: ''` | 52001 |
| `src/examples/ax25/bpsk.grc` | 415 | `network_socket_pdu` (`network_socket_pdu_0`) | `host: ''` | 52001 |
| `src/examples/ax25/bpsk9k6.grc` | 415 | `network_socket_pdu` (`network_socket_pdu_0_0`) | `host: ''` | 52001 |
| `src/examples/ax25/fsk.grc` | 285 | `network_socket_pdu` (`network_socket_pdu_0`) | `host: ''` | 52001 |
| `src/examples/satellites/tanusha3_pm.grc` | 376 | `network_socket_pdu` (`network_socket_pdu_0`) | `host: ''` | 52001 |

All five files set `type: TCP_SERVER` with an empty `host:` — i.e.
operator's TCP socket on port 52001 is reachable from every interface,
not just `lo`.

## 2. UDP source — bind defaults to `0.0.0.0` / `::`

Two patterns observed:

### 2a. Explicit `ipaddr:` to all-zero
| File | Line | Block | Default |
|------|------|-------|---------|
| `src/examples/qo100-multimedia-beacon/qo100_multimedia_beacon_ea4gpz.grc` | 130 | `blocks_udp_source` | `ipaddr: 0.0.0.0` |
| `src/examples/satellites/nx_decoder/dstar_one.grc` | 90 (block), 174-184 (variable) | `blocks_udp_source` | `ipaddr: ip` where the `ip` parameter `value: '::'` (line 184 — IPv6 unspecified, dual-stack wildcard) |

### 2b. `network_udp_source` blocks with no `ipaddr` parameter at all (defaults to 0.0.0.0 per the GR YAML default)
| File | Line | Block id |
|------|------|----------|
| `src/examples/satellites/equisat.grc` | 344 | `network_udp_source_0` |
| `src/examples/satellites/tanusha3_pm.grc` | 390 | `network_udp_source_0` |
| `src/examples/satellites/nx_decoder/sokrat.grc` | 230 | `network_udp_source_0` |
| `src/examples/satellites/nx_decoder/beesat.grc` | 230 | `network_udp_source_0` |
| `src/examples/satellites/nx_decoder/amgu_1.grc` | 230 | `network_udp_source_0` |
| `src/examples/qo100-multimedia-beacon/qo100_multimedia_beacon_df2et.grc` | 880 | `network_udp_source_0` |

Note: `qo100_multimedia_beacon_df2et.grc` line 866 sets the OUTGOING
`network_socket_pdu_0` `host: 127.0.0.1` (safe), but its
`network_udp_source_0` block at line 880 has no `ipaddr:` field and
therefore inherits the YAML default of `0.0.0.0`.

## 3. Files that are SAFE (set explicit `127.0.0.1`)

| File | Line | Block | Param |
|------|------|-------|-------|
| `src/examples/qo100-multimedia-beacon/qo100_multimedia_beacon.grc` | 335 | `blocks_socket_pdu` | `host: 127.0.0.1` |
| `src/examples/qo100-multimedia-beacon/qo100_multimedia_beacon_df2et.grc` | 866 | `network_socket_pdu` | `host: 127.0.0.1` |

These are the only two TCP socket_pdu defaults that don't bind wildcard.

## 4. Summary

- **5 / 5** shipped TCP_SERVER `socket_pdu` instances in AX.25 +
  tanusha3_pm examples bind 0.0.0.0:52001 (F109).
- **6+** UDP source instances (qo100-ea4gpz, dstar_one, equisat,
  tanusha3_pm, sokrat, beesat, amgu_1, qo100-df2et) bind 0.0.0.0/:: (F110).
- `gr-sat-audit:latest` empirical confirmation: `00000000:CB21 ... 0A`
  in `/proc/net/tcp` proves wildcard bind. See `run_poc.log`.
