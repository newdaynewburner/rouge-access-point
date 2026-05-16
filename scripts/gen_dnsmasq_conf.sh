#!/bin/sh

CONFIG_FILE=$5
touch "$CONFIG_FILE"
echo "no-resolv" >> "$CONFIG_FILE"
echo "interface=$1" >> "$CONFIG_FILE"
echo "dhcp-range=$2,$3,12h" >> "$CONFIG_FILE"
echo "dhcp-option=3,$4" >> "$CONFIG_FILE"
echo "dhcp-option=6,$5" >> "$CONFIG_FILE"
echo "port=0" >> "$CONFIG_FILE"

echo "Generated dnsmasq configuration file at '$CONFIG_FILE'"
exit 0
