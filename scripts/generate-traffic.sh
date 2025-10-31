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
  ping -c "${PING_COUNT}" "${PING_TARGET}" || true
fi

if [[ -n "${HTTP_URL}" ]]; then
  echo "[gen] HTTP GET ${HTTP_URL}"
  curl -sS -m 5 -o /dev/null "${HTTP_URL}" || true
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
  # Minimal SNTP client request: first byte 0x1B (LI=0, VN=3, Mode=3), rest zero
  req=$(printf '\033' && printf '\0%.0s' {1..47})
  # shellcheck disable=SC2059
  printf "%b" "${req}" | nc -u -w1 "${NTP_SERVER}" 123 >/dev/null 2>&1 || true
fi

echo "[gen] Traffic generation complete."
