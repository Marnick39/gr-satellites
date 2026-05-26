#!/usr/bin/env bash
# F109/F110 end-to-end PoC runner. docker-cp pattern (no -v mount, per
# task constraint). Builds a fresh container, copies the two Python
# scripts in, starts listener, runs attacker, captures output, cleans up.
set -euo pipefail

CID=$(docker create --rm \
    --security-opt seccomp=unconfined \
    gr-sat-audit:latest \
    sleep 90)

trap 'docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT

HERE="$(cd "$(dirname "$0")" && pwd)"

docker cp "$HERE/f109_listener.py" "$CID:/tmp/f109_listener.py"
docker cp "$HERE/f109_attacker.py" "$CID:/tmp/f109_attacker.py"

docker start "$CID" >/dev/null

# Start the listener in the background inside the container.
echo "=========================================================================="
echo "Starting listener (background)..."
echo "=========================================================================="
docker exec -d "$CID" bash -c \
    'python3 /tmp/f109_listener.py > /tmp/listener.log 2>&1 &
     echo $! > /tmp/listener.pid'

# Give it a moment to bind.
sleep 4

# Show /proc/net/tcp evidence of 0.0.0.0:52001 LISTEN from another exec.
echo "=========================================================================="
echo "Container netstat snapshot (LISTEN on 0.0.0.0:52001 = F109):"
echo "=========================================================================="
docker exec "$CID" bash -c '
  echo "-- /proc/net/tcp --";
  cat /proc/net/tcp;
  echo "-- /proc/net/tcp6 --";
  cat /proc/net/tcp6;
  echo "-- lsof on 52001 --";
  (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true) | grep -E "52001|LISTEN" || echo "(ss/netstat not available)";
'

# Run the attacker from a different exec session (different PID, same host).
echo "=========================================================================="
echo "Running attacker (separate process, same host = LAN-attacker analog)..."
echo "=========================================================================="
docker exec "$CID" python3 /tmp/f109_attacker.py

# Let listener flush.
sleep 3

echo "=========================================================================="
echo "Listener log:"
echo "=========================================================================="
docker exec "$CID" cat /tmp/listener.log || true

echo "=========================================================================="
echo "Done. Container will be removed by trap."
echo "=========================================================================="
