#!/bin/sh

# Free up interface for broadcasting
nmcli device set "$1" managed no

# Set the IP and MAC addresses that will be used for the gateway
ip link set "$1" down
ip addr flush "$1"
ip addr add "$3"/24 dev "$1"
if [ "$4" != "0" ]; then
    ip link set "$1" address "$4"
fi
ip link set "$1" up

# Enable IP address forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Enable masquerading
iptables -t nat -A POSTROUTING -o "$2" -j MASQUERADE

# Forward station traffic to the Internet
iptables -A FORWARD -i "$2" -o "$1" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i "$1" -o "$2" -j ACCEPT

# Redirect TCP and UDP DNS traffic to the machine
iptables -t nat -A PREROUTING -i "$1" -p udp --dport 53 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -i "$1" -p tcp --dport 53 -j REDIRECT --to-ports 53

# Block QUIC/HTTP3 (UDP port 443). Forces DoH to fall back to using TLS over TCP
iptables -A FORWARD -p udp --dport 443 -j REJECT

exit 0
