#!/bin/sh

# Assign an IP address and mask to 'tun0' interface
ifconfig tun0 mtu 1472 up 10.66.66.102 netmask 255.255.255.0

# Modify IP routing tables for new default gw
route del default
route add default gw 10.66.66.1 tun0
