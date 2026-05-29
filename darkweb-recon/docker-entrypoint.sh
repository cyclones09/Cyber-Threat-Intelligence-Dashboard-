#!/usr/bin/env bash
# Start Tor (only when running live), then launch the OBSIDIAN web app.
set -e

mkdir -p "$(dirname "${OBSIDIAN_DATABASE:-/data/obsidian.db}")"

if [ "${OBSIDIAN_DEMO_MODE}" != "true" ]; then
  echo "[obsidian] live mode — starting Tor..."
  # tor starts as root, binds the SOCKS port, then drops privileges to debian-tor.
  cat > /tmp/torrc <<EOF
SocksPort 9050
User debian-tor
DataDirectory /var/lib/tor
EOF
  chown -R debian-tor:debian-tor /var/lib/tor 2>/dev/null || true
  tor -f /tmp/torrc &

  echo "[obsidian] waiting for Tor to bootstrap..."
  for i in $(seq 1 30); do
    if curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip >/dev/null 2>&1; then
      echo "[obsidian] Tor is up."
      break
    fi
    sleep 2
  done
else
  echo "[obsidian] demo mode — Tor not started (offline fixtures)."
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
