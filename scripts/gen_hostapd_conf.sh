#!/bin/sh

CONFIG_FILE=$5
touch "$CONFIG_FILE"
echo "interface=$1" >> "$CONFIG_FILE"
echo "driver=nl80211" >> "$CONFIG_FILE"
echo "ssid=$2" >> "$CONFIG_FILE"
echo "hw_mode=$3" >> "$CONFIG_FILE"
echo "channel=$4" >> "$CONFIG_FILE"
echo "auth_algs=1" >> "$CONFIG_FILE"

echo "Generated hostapd configuration file at '$CONFIG_FILE'"
exit 0
