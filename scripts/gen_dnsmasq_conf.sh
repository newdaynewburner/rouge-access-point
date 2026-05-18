#!/bin/sh

# Create an empty file for the config and remove the old one if present
CONFIG_FILE=$6
if [ -f "$CONFIG_FILE" ]; then
    rm "$CONFIG_FILE"
fi
touch "$CONFIG_FILE"

# Write the values passed in the arguments to the config file
echo "no-resolv" >> "$CONFIG_FILE"
echo "interface=$1" >> "$CONFIG_FILE"
echo "dhcp-range=$2,$3,12h" >> "$CONFIG_FILE"
echo "dhcp-option=3,$4" >> "$CONFIG_FILE"
echo "dhcp-option=6,$5" >> "$CONFIG_FILE"
echo "port=0" >> "$CONFIG_FILE"
exit 0
