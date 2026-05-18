#!/bin/sh

################################################################
# genrandmac.sh                                                #
#                                                              #
# Generates a random MAC address and prints it to the terminal #
################################################################

# Generate the MAC address and print it
printf '02:%02X:%02X:%02X:%02X:%02X\n' \
$(od -An -N5 -tu1 /dev/urandom)

exit 0
