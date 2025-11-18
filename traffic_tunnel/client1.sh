#!/bin/sh

# Configure `tun0` and add source-based routing so we don't remove
# the container's existing Docker default route (keeps DNS/host reachability).
# Uses `ip`/iproute2 when available; falls back to ifconfig/route.

IP_ADDR=172.31.66.101
NETMASK=255.255.255.0
GW=172.31.66.1
TABLE=100

if command -v ip >/dev/null 2>&1; then
	ip link set dev tun0 mtu 1472 up 2>/dev/null || ip link set dev tun0 up
	ip addr add ${IP_ADDR}/24 dev tun0 2>/dev/null || true
	ip route replace 172.31.66.0/24 dev tun0 scope link 2>/dev/null || true

	# Ensure source-based routing: traffic from the tun0 address uses table $TABLE
	ip rule add from ${IP_ADDR}/32 table ${TABLE} 2>/dev/null || true
	ip route add default via ${GW} dev tun0 table ${TABLE} 2>/dev/null || true

	echo "[tun] configured tun0 ${IP_ADDR}/24"
	ip addr show dev tun0 || true
	echo "[tun] ip rule" 
	ip rule show || true
	echo "[tun] ip route (table ${TABLE})"
	ip route show table ${TABLE} || true
	echo "[tun] main routing table"
	ip route show || true
else
	# Fallback for minimal containers without iproute2
	ifconfig tun0 mtu 1472 up ${IP_ADDR} netmask ${NETMASK} || true

	# Try to add a default via tun0 without deleting the existing default
	route add default gw ${GW} tun0 2>/dev/null || true

	echo "[tun-fallback] ifconfig tun0"
	ifconfig tun0 || true
	echo "[tun-fallback] routes"
	route -n || true
fi
