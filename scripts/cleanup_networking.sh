#!/bin/sh

# Disable masquerading
iptables -t nat -D POSTROUTING -o "$2" -j MASQUERADE

# Disable forwarding
iptables -D FORWARD -i "$2" -o "$1" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -D FORWARD -i "$1" -o "$2" -j ACCEPT

# Disable DNS redirect
iptables -t nat -D PREROUTING -i "$1" -p udp --dport 53 -j REDIRECT --to-ports 53
iptables -t nat -D PREROUTING -i "$1" -p tcp --dport 53 -j REDIRECT --to-ports 53

# Disable IP forwarding
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0

# Flush addresses and return the interface to NetworkManager
ip link set "$1" down
ip addr flush "$1"
nmcli device set "$1" managed yes

# Bring the interface back up
ip link set "$1" up

exit 0
