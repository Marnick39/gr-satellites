# F101 hygiene PoC — tm_kiss_transport multi-FEND list rebind

Filed as a hygiene patch, not a CVE — impact is one stale telemetry
value on the ASRTU-1 dashboard per multi-packet TM frame; no security
significance in any deployed scenario. Included so the maintainer can
verify the patch logic without having to set up a TM-KISS flowgraph.

```
python3 poc_F101_kiss_list_rebind.py
```

## Why this matters at all

Multiple `KISS FEND` delimiters in a single CCSDS TM frame are legal
(the TM payload is a continuous octet stream that may carry several
KISS-framed packets back-to-back). The shipped code published the
first packet correctly, then `self.packets[vc] = []` rebound the dict
entry to a fresh list, but the local `packet` variable still pointed
at the just-published list — so subsequent bytes landed on that
orphan, not on the empty fresh list. The next FEND then published
the orphan's contents instead of just the new packet.

In practice this manifests as the wrong APID showing on operator
dashboards by one frame after every multi-FEND TM. Real bug, marginal
impact, easy fix — `packet.clear()` instead of dict rebind.
