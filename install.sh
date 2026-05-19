#!/bin/sh

# install.sh
#
# Filesystem destinations:
# rouge-access-point.py           -   /usr/lib/rouge-access-point/rouge-access-point.py
# lib/                            -   /usr/lib/rouge-access-point/lib/
# scripts/                        -   /etc/rouge-access-point/scripts/
# rsc/                            -   /etc/rouge-access-point/rsc/
# config/rouge-access-point.ini   -   /etc/rouge-access-point/rouge-access-point.ini

# Make sure script is run as root
echo "Checking permissions"
if [[ $EUID != 0 ]]; then
    echo "Permission check failed! This script MUST be ran as root! Quitting!"
    exit 1
fi

# Start message
echo "Permission check passed. Beginning the installation now"

# Create /etc/rouge-access-point
echo "Creating /etc/rouge-access-point/ filesystem directory"
if [ -d "/etc/rouge-access-point" ]; then
    echo "/etc/rouge-access-point/ already exists! It will be deleted and recreated!"
    rm -rf "/etc/rouge-access-point/"
fi
echo "Creating /etc/rouge-access-point/"
mkdir "/etc/rouge-access-point/"
echo "Copying config/rouge-access-point.ini to /etc/rouge-access-point/rouge-access-point.ini"
cp "config/rouge-access-point.ini" "/etc/rouge-access-point/rouge-access-point.ini"
echo "Copying scripts/ to /etc/rouge-access-point/scripts/"
cp -r "scripts/" "/etc/rouge-access-point/scripts/"
echo "Granting execute permissions to /etc/rouge-access-point/scripts/*"
chmod +x "/etc/rouge-access-point/scripts/*"
echo "Copying rsc/ to /etc/rouge-access-point/rsc/"
cp -r "rsc/" "/etc/rouge-access-point/rsc/"
echo "Deleting /etc/rouge-access-point/rsc/runner.sh"
rm "/etc/rouge-access-point/rsc/runner.sh"

# Create /usr/lib/rouge-access-point
echo "Creating /usr/lib/rouge-access-point/ filesystem directory"
if [ -d "/usr/lib/rouge-access-point" ]; then
    echo "/usr/lib/rouge-access-point/ already exists! It will be deleted and recreated!"
    rm -rf "/usr/lib/rouge-access-point/"
fi
echo "Creating /usr/lib/rouge-access-point/"
mkdir "/usr/lib/rouge-access-point/"
echo "Copying rouge-access-point.py to /usr/lib/rouge-access-point/rouge-access-point.py"
cp "rouge-access-point.py" "/usr/lib/rouge-access-point/rouge-access-point.py"
echo "Granting execute permissions to /usr/lib/rouge-access-point/rouge-access-point.py"
chmod +x "/usr/lib/rouge-access-point/rouge-access-point.py"
echo "Copying lib/ to /usr/lib/rouge-access-point/lib/"
cp -r "lib/" "/usr/lib/rouge-access-point/lib/"

# Create /var/log/rouge-access-point/
echo "Creating /var/log/rouge-access-point/ filesystem directory"
if [ -d "/var/log/rouge-access-point/" ]; then
    echo "/var/log/rouge-access-point/ already exists! It will be deleted and recreated!"
    rm -rf "/var/log/rouge-access-point"
fi
echo "Creating /var/log/rouge-access-point/"
mkdir "/var/log/rouge-access-point/"

# Create /usr/sbin/rouge-access-point
echo "Copying rsc/runner.sh to /usr/sbin/rouge-access-point"
cp "rsc/runner.sh" "/usr/sbin/rouge-access-point"
echo "Granting execute permissions to /usr/sbin/rouge-access-point"
chmod +x "/usr/sbin/rouge-access-point"

# Completion message
echo "Installation complete! Installation script will now exit"
exit 0


