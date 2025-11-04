#!/usr/bin/env bash
set -euo pipefail

: "${IFACE:=tun0}"
: "${CLIENT_UNDERLAY_IF:=eth0}"
: "${CLIENT_SCRIPT:=/client-config/client1.sh}"
: "${TUN_WAIT_TIMEOUT:=20}"
# Optional: traffic generator controls
: "${GEN_TRAFFIC:=false}"
: "${GEN_DHCP:=false}"
: "${PING_TARGET:=}"
: "${PING_COUNT:=3}"
: "${HTTP_URL:=}"
: "${DNS_NAME:=}"
: "${DNS_SERVER:=}"
: "${NTP_SERVER:=}"

echo "[client] Starting traffic_tunnel client with IFACE=${IFACE}, CLIENT_UNDERLAY_IF=${CLIENT_UNDERLAY_IF}, CLIENT_SCRIPT=${CLIENT_SCRIPT}"

# Ensure /dev/net/tun exists
if [[ ! -e /dev/net/tun ]]; then
  echo "[client] /dev/net/tun not found. Creating..."
  mkdir -p /dev/net || true
  if ! [[ -c /dev/net/tun ]]; then
    mknod /dev/net/tun c 10 200 || true
  fi
fi

if [[ ! -f "${CLIENT_SCRIPT}" ]]; then
  echo "[client] ERROR: CLIENT_SCRIPT ${CLIENT_SCRIPT} not found. Mount ./tunnel/clients into /client-config."
  exit 1
fi

echo "[client] Launching traffic_tunnel client..."
/usr/local/bin/traffic_tunnel "${CLIENT_UNDERLAY_IF}" -c "${CLIENT_SCRIPT}" &

echo "[client] Waiting for ${IFACE} to appear... (timeout ${TUN_WAIT_TIMEOUT}s)"
SECS=0
until ip link show dev "${IFACE}" >/dev/null 2>&1; do
  sleep 1
  SECS=$((SECS+1))
  if (( SECS >= TUN_WAIT_TIMEOUT )); then
    echo "[client] ERROR: ${IFACE} did not appear within ${TUN_WAIT_TIMEOUT}s"
    exit 1
  fi
done

# Bring interface up if down
if ! ip link show dev "${IFACE}" | grep -q "state UP"; then
  echo "[client] Bringing ${IFACE} up..."
  ip link set dev "${IFACE}" up || true
fi

echo "[client] ${IFACE} is ready."

if [[ "${GEN_TRAFFIC}" == "true" ]]; then
  echo "[client] Generating sample traffic"
  PING_TARGET="${PING_TARGET}" PING_COUNT="${PING_COUNT}" \
  HTTP_URL="${HTTP_URL}" DNS_NAME="${DNS_NAME}" DNS_SERVER="${DNS_SERVER}" \
  NTP_SERVER="${NTP_SERVER}" GEN_DHCP="${GEN_DHCP}" /generate-traffic.sh || true
fi

echo "[client] Client is running. Sleeping indefinitely."
tail -f /dev/null
