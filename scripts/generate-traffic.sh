#!/usr/bin/env bash
set -euo pipefail

# Configuration via environment variables (optional)
: "${PING_TARGET:=}"
: "${PING_COUNT:=3}"
: "${HTTP_URL:=}"
: "${DNS_NAME:=}"
: "${DNS_SERVER:=}"
: "${NTP_SERVER:=}"

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

if [[ -n "${NTP_SERVER}" ]]; then
  echo "[gen] NTP client packet to ${NTP_SERVER}:123"
  # Minimal SNTP client request: first byte 0x1B (LI=0, VN=3, Mode=3), rest zero (48 bytes total)
  {
    printf '\x1b'
    dd if=/dev/zero bs=1 count=47 status=none
  } | nc -u -w1 "${NTP_SERVER}" 123 >/dev/null 2>&1 || true
fi

if [[ -n "${GEN_DHCP}" ]] && [[ "${GEN_DHCP}" == "true" ]]; then
  echo "[gen] DHCP DISCOVER (broadcast)"
  # Construct a minimal DHCP-like packet with magic cookie at offset 236 so analyzer recognizes it.
  # Send from UDP source port 68 to destination port 67 to broadcast address.
  {
    dd if=/dev/zero bs=1 count=236 status=none
    # DHCP magic cookie + minimal DHCP Discover option (DHCP Message Type = 1)
    printf '\x63\x82\x53\x63\x35\x01\x01\xff'
  } | nc -u -w1 -p 68 255.255.255.255 67 >/dev/null 2>&1 || true
fi

echo "[gen] Traffic generation complete."
