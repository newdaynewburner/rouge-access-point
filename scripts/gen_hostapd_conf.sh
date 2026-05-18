#!/bin/sh

# Create an empty file for the config and remove the old one if present
CONFIG_FILE=$5
if [ -f "$CONFIG_FILE" ]; then
    rm "$CONFIG_FILE"
fi
touch "$CONFIG_FILE"

# Write the values passed in the arguments to the config file
echo "ctrl_interface=/var/run/hostapd" >> "$CONFIG_FILE"
echo "interface=$1" >> "$CONFIG_FILE"
echo "driver=nl80211" >> "$CONFIG_FILE"
echo "ssid=$2" >> "$CONFIG_FILE"
echo "hw_mode=$3" >> "$CONFIG_FILE"
echo "channel=$4" >> "$CONFIG_FILE"
echo "auth_algs=1" >> "$CONFIG_FILE"
exit 0
