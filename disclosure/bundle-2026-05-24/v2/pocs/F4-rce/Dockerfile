# F4 RCE end-to-end PoC environment.
#
# The image is a minimal Python 3.10 install configured to look like a
# SatNOGS-style ground-station Pi: an unprivileged operator user named
# `op` whose home contains a fresh user-site-packages directory that
# Python's `site` module will auto-scan for `.pth` files at every
# interpreter startup.
#
# After the vulnerable gr-satellites code lands a hostile `.pth` in
# that directory, any subsequent `python3` invocation by the operator
# executes the attacker's payload before user code runs.

FROM python:3.10-slim

RUN useradd -m -s /bin/bash op

# Pre-create the user-site directory so we don't depend on the operator
# having previously run `pip install --user` to materialize it. site.py
# scans this path regardless of how it got there.
RUN mkdir -p /home/op/.local/lib/python3.10/site-packages \
    && chown -R op:op /home/op/.local

# The receiver's base directory; matches the documented
# gr_satellites --file-output-path default the audit assumed.
RUN mkdir -p /tmp/grs_recv && chown op:op /tmp/grs_recv

COPY poc_F4_rce_e2e.py /home/op/poc_F4_rce_e2e.py
RUN chown op:op /home/op/poc_F4_rce_e2e.py

USER op
WORKDIR /home/op
CMD ["python3", "/home/op/poc_F4_rce_e2e.py"]
