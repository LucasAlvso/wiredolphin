#!/usr/bin/env bash
set -euo pipefail

# Defaults
: "${IFACE:=tun0}"
: "${TUN_UNDERLAY_IF:=eth0}"
: "${TUN_START:=true}"
: "${TUN_WAIT_TIMEOUT:=20}"
# Optional: configure IP and NAT on the TUN interface (useful if tunnel binary doesn't do it)
: "${TUN_ADDR_CIDR:=172.31.66.1/24}"
: "${TUN_ENABLE_NAT:=true}"

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
  # Ensure interface is up
  if ! ip link show dev "${IFACE}" | grep -q "state UP"; then
    echo "[entrypoint] Bringing ${IFACE} up..."
    ip link set dev "${IFACE}" up || true
  fi

  # Ensure it has an IP address; only assign if none present
  if ! ip addr show dev "${IFACE}" | grep -q "inet "; then
    echo "[entrypoint] Assigning ${TUN_ADDR_CIDR} to ${IFACE}..."
    ip addr add "${TUN_ADDR_CIDR}" dev "${IFACE}" || true
  fi

  # Optionally enable simple MASQUERADE on underlay interface for egress
  if [[ "${TUN_ENABLE_NAT}" == "true" ]]; then
    echo "[entrypoint] Ensuring NAT (MASQUERADE) on ${TUN_UNDERLAY_IF}..."
    if ! iptables -t nat -C POSTROUTING -o "${TUN_UNDERLAY_IF}" -j MASQUERADE 2>/dev/null; then
      iptables -t nat -A POSTROUTING -o "${TUN_UNDERLAY_IF}" -j MASQUERADE || true
    fi
  fi

  # Provide simple TCP listeners on 80 and 443 so clients can generate HTTP/HTTPS over the tunnel
  if command -v nc >/dev/null 2>&1; then
    echo "[entrypoint] Starting simple TCP listeners on 0.0.0.0:80 and :443 for HTTP/HTTPS testing..."
    # Accept and immediately close; payload from clients is enough for app-layer detection
    ( while true; do nc -l -p 80 -q 1 >/dev/null; done ) &
    ( while true; do nc -l -p 443 -q 1 >/dev/null; done ) &
  fi

  echo "[entrypoint] ${IFACE} is ready."
else
  echo "[entrypoint] Skipping tunnel startup (TUN_START=false). Assuming ${IFACE} exists."
fi

echo "[entrypoint] Starting wiredolphin on ${IFACE}..."
cd /logs
exec /app/wiredolphin "${IFACE}"
