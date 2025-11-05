#!/usr/bin/env bash
set -euo pipefail

# Configuration via environment variables (optional)
: "${PING_TARGET:=}"
: "${PING_COUNT:=3}"
: "${HTTP_URL:=}"
: "${DNS_NAME:=}"
: "${DNS_SERVER:=}"
: "${NTP_SERVER:=}"
: "${GEN_DHCP:=false}"
: "${DHCP_TARGET:=172.31.66.1}"

send_ntp_payload() {
  printf '\x1b'
  # 47 zero bytes to complete minimal SNTP client request
  printf '\0%.0s' {1..47}
}

send_ntp_probe() {
  local target="$1"
  local label="$2"
  if [[ -z "${target}" ]]; then
    return
  fi
  local suffix=""
  if [[ -n "${label}" ]]; then
    suffix=" (${label})"
  fi
  echo "[gen] NTP client packet to ${target}:123${suffix}"
  local dest_ip=""
  if [[ "${target}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    dest_ip="${target}"
  else
    local resolved=""
    if resolved=$(getent ahostsv4 "${target}" 2>/dev/null | awk 'NR==1 {print $1}'); then
      dest_ip="${resolved}"
    else
      echo "[gen] Note: unable to resolve ${target}, skipping UDP send" >&2
    fi
  fi

  if [[ -n "${dest_ip}" ]]; then
    if command -v nc >/dev/null 2>&1; then
      send_ntp_payload | nc -u -w1 "${dest_ip}" 123 >/dev/null 2>&1 || true
    fi
    send_ntp_payload >"/dev/udp/${dest_ip}/123" 2>/dev/null || true
  fi
}

echo "[gen] Starting traffic generation..."

if [[ -n "${PING_TARGET}" ]]; then
  echo "[gen] Pinging ${PING_TARGET} (${PING_COUNT}x)"
  # Prefer IPv4 ping if available to avoid v6-only attempts in some stacks
  if command -v ping >/dev/null 2>&1; then
    ping -c "${PING_COUNT}" "${PING_TARGET}" || true
  fi
fi

if [[ -n "${HTTP_URL}" ]]; then
  echo "[gen] HTTP GET (IPv4) ${HTTP_URL}"
  # Force IPv4 to ensure NAT path and drive TCP+HTTP counters
  curl -4 -sS -L -m 5 -o /dev/null "${HTTP_URL}" || true
  # Also try HTTPS over IPv4 to drive HTTPS counters (ignore certs for demo)
  proto_host="${HTTP_URL#*//}"
  host_only="${proto_host%%/*}"
  if [[ -n "${host_only}" ]]; then
    curl -4 -sS -k -m 5 -o /dev/null "https://${host_only}" || true
  fi
  # Initiate a bare TCP connect to port 80 to ensure TCP counter increments even without payload
  if command -v nc >/dev/null 2>&1; then
    nc -4 -z -w1 "${host_only:-example.com}" 80 >/dev/null 2>&1 || true
    # Send a minimal HTTP request to drive HTTP application parsing
    {
      printf 'GET / HTTP/1.1\r\n'
      printf 'Host: %s\r\n' "${host_only:-example.com}"
      printf 'User-Agent: gen-traffic/1.0\r\n'
      printf 'Accept: */*\r\n\r\n'
    } | nc -4 -w2 "${host_only:-example.com}" 80 >/dev/null 2>&1 || true
    # Connect to HTTPS to drive HTTPS port-based counting
    nc -4 -z -w1 "${host_only:-example.com}" 443 >/dev/null 2>&1 || true
  fi
fi

if [[ -n "${DNS_NAME}" ]]; then
  if [[ -n "${DNS_SERVER}" ]]; then
    echo "[gen] DNS A ${DNS_NAME} @${DNS_SERVER}"
    dig +time=2 +tries=1 "@${DNS_SERVER}" "${DNS_NAME}" A >/dev/null 2>&1 || true
  else
    echo "[gen] DNS A ${DNS_NAME} (system resolver)"
    dig +time=2 +tries=1 "${DNS_NAME}" A >/dev/null 2>&1 || true
  fi
fi

fallback_ntp="${DHCP_TARGET:-}"

if [[ -n "${NTP_SERVER}" ]]; then
  send_ntp_probe "${NTP_SERVER}" "primary"
fi

if [[ -n "${fallback_ntp}" && "${fallback_ntp}" != "${NTP_SERVER}" ]]; then
  send_ntp_probe "${fallback_ntp}" "fallback"
fi

if [[ "${GEN_DHCP}" == "true" ]]; then
  echo "[gen] DHCP DISCOVER to ${DHCP_TARGET}:67"
  tmpfile=$(mktemp)
  mac_bytes=$(mktemp)
  head -c 6 /dev/urandom >"${mac_bytes}"
  # Build BOOTP header with random transaction ID and client MAC
  {
    printf '\x01\x01\x06\x00'          # op=BOOTREQUEST, htype=Ethernet, hlen=6, hops=0
    dd if=/dev/urandom bs=1 count=4 status=none   # xid
    printf '\x00\x00\x80\x00'          # secs=0, flags broadcast
    dd if=/dev/zero bs=1 count=16 status=none     # ciaddr, yiaddr, siaddr, giaddr
    cat "${mac_bytes}"                      # chaddr (MAC)
    dd if=/dev/zero bs=1 count=10 status=none     # chaddr padding
    dd if=/dev/zero bs=1 count=192 status=none    # sname + file
    printf '\x63\x82\x53\x63'          # magic cookie
    printf '\x35\x01\x01'               # option 53: DHCP Discover
    printf '\x3d\x07\x01'               # option 61: client identifier (type 1 + MAC)
    cat "${mac_bytes}"
    printf '\x37\x03\x01\x03\x06'     # option 55: parameter request list (Subnet, Router, DNS)
    printf '\xff'                         # end
  } >"${tmpfile}"

  if command -v nc >/dev/null 2>&1; then
    nc -u -w1 -p 68 "${DHCP_TARGET}" 67 <"${tmpfile}" >/dev/null 2>&1 || true
  elif command -v socat >/dev/null 2>&1; then
    socat -u FILE:"${tmpfile}" UDP-DATAGRAM:"${DHCP_TARGET}":67,sourceport=68 >/dev/null 2>&1 || true
  else
    # Fallback using bash /dev/udp pseudo-device
    cat "${tmpfile}" >"/dev/udp/${DHCP_TARGET}/67" 2>/dev/null || true
  fi
  rm -f "${tmpfile}" "${mac_bytes}"
fi

echo "[gen] Traffic generation complete."
