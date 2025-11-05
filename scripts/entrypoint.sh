#!/usr/bin/env bash
set -euo pipefail

ip_forward_prev=""
ip_forward_changed=0

cleanup() {
  if [[ ${ip_forward_changed} -eq 1 ]]; then
    if [[ -n "${ip_forward_prev}" ]]; then
      echo "[entrypoint] Restoring net.ipv4.ip_forward=${ip_forward_prev}" >&2
      if command -v sysctl >/dev/null 2>&1; then
        sysctl -w net.ipv4.ip_forward="${ip_forward_prev}" >/dev/null 2>&1 || \
          echo "[entrypoint] Warning: failed to restore net.ipv4.ip_forward via sysctl" >&2
      elif [[ -w /proc/sys/net/ipv4/ip_forward ]]; then
        echo "${ip_forward_prev}" >/proc/sys/net/ipv4/ip_forward 2>/dev/null || \
          echo "[entrypoint] Warning: failed to restore net.ipv4.ip_forward via /proc" >&2
      fi
    fi
  fi
}

trap cleanup EXIT

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
  if command -v sysctl >/dev/null 2>&1; then
    if prev_val=$(sysctl -n net.ipv4.ip_forward 2>/dev/null); then
      if [[ "${prev_val}" != "1" ]]; then
        if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
          ip_forward_prev="${prev_val}"
          ip_forward_changed=1
        else
          echo "[entrypoint] Warning: failed to enable net.ipv4.ip_forward via sysctl" >&2
        fi
      else
        echo "[entrypoint] IP forwarding already enabled." >&2
      fi
    else
      echo "[entrypoint] Warning: unable to read current net.ipv4.ip_forward" >&2
    fi
  elif [[ -r /proc/sys/net/ipv4/ip_forward ]]; then
    prev_val=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "")
    if [[ "${prev_val}" != "1" && -w /proc/sys/net/ipv4/ip_forward ]]; then
      if echo 1 >/proc/sys/net/ipv4/ip_forward 2>/dev/null; then
        ip_forward_prev="${prev_val}"
        ip_forward_changed=1
      else
        echo "[entrypoint] Warning: failed to enable net.ipv4/ip_forward via /proc" >&2
      fi
    else
      echo "[entrypoint] IP forwarding already enabled or /proc/sys/net/ipv4/ip_forward unwritable." >&2
    fi
  else
    echo "[entrypoint] Warning: cannot manage net.ipv4.ip_forward (sysctl unavailable)." >&2
  fi

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
/app/wiredolphin "${IFACE}"
status=$?
exit ${status}
