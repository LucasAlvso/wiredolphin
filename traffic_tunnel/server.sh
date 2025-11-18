#!/bin/sh

# Assign an IP address and mask to 'tun0' interface
ifconfig tun0 mtu 1472 up 10.66.66.1 netmask 255.255.255.0 

# Enable IP forwarding
echo 1 | dd of=/proc/sys/net/ipv4/ip_forward

# Add an iptables rule to masquerade for the tunnel subnet
iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -j MASQUERADE
