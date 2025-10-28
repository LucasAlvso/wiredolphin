#!/usr/bin/env bash
set -euo pipefail

# Defaults
: "${IFACE:=tun0}"
: "${TUN_UNDERLAY_IF:=eth0}"
: "${TUN_START:=true}"
: "${TUN_WAIT_TIMEOUT:=20}"

echo "[entrypoint] Starting with IFACE=${IFACE}, TUN_UNDERLAY_IF=${TUN_UNDERLAY_IF}, TUN_START=${TUN_START}"

# Ensure /dev/net/tun is present (should be provided by the host via device mapping)
if [[ ! -e /dev/net/tun ]]; then
  echo "[entrypoint] /dev/net/tun not found. Creating..."
  mkdir -p /dev/net || true
  if ! [[ -c /dev/net/tun ]]; then
    mknod /dev/net/tun c 10 200 || true
  fi
fi

# Optionally start the tunnel (server mode)
if [[ "${TUN_START}" == "true" ]]; then
  if [[ ! -x /usr/local/bin/traffic_tunnel ]]; then
    echo "[entrypoint] ERROR: /usr/local/bin/traffic_tunnel not found in the image."
    echo "Ensure the 'tunnel/' directory with sources is included in the Docker build context."
    exit 1
  fi

  echo "[entrypoint] Enabling IP forwarding..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null || true

  echo "[entrypoint] Starting traffic_tunnel on ${TUN_UNDERLAY_IF} (server mode)..."
  /usr/local/bin/traffic_tunnel "${TUN_UNDERLAY_IF}" -s &

  # Wait for tun0 to be created
  echo "[entrypoint] Waiting for ${IFACE} to appear... (timeout ${TUN_WAIT_TIMEOUT}s)"
  SECS=0
  until ip link show dev "${IFACE}" >/dev/null 2>&1; do
    sleep 1
    SECS=$((SECS+1))
    if (( SECS >= TUN_WAIT_TIMEOUT )); then
      echo "[entrypoint] ERROR: ${IFACE} did not appear within ${TUN_WAIT_TIMEOUT}s"
      exit 1
    fi
  done
  echo "[entrypoint] ${IFACE} is up."
else
  echo "[entrypoint] Skipping tunnel startup (TUN_START=false). Assuming ${IFACE} exists."
fi

echo "[entrypoint] Starting wiredolphin on ${IFACE}..."
cd /logs
exec /app/wiredolphin "${IFACE}"
