"""
lib/system.py

Handles system configuration tasks
"""

import os
import sys
import subprocess

def setup_networking(interface_objects, config=None, logger=None):
    """ Set up networking
    """

    if bool(config["SYSTEM"]["kill_networkmanager"]):
        subprocess.call(["systemctl", "stop", "NetworkManager"])
    if bool(config["SYSTEM"]["kill_wpa_supplicant"]):
        subprocess.call(["systemctl", "stop", "wpa_supplicant"])
    if bool(config["SYSTEM"]["kill_hostapd"]):
        subprocess.call(["systemctl", "stop", "hostapd"])
    if bool(config["SYSTEM"]["kill_dnsmasq"]):
        subprocess.call(["systemctl", "stop", "dnsmasq"])

    if config["SYSTEM"]["nm_compatability_mode"] == "true":
        for interface in interface_objects.values():
            interface.stop_management()

    interface_objects["broadcast"].set_state("down")
    interface_objects["broadcast"].flush_ipaddrs()
    interface_objects["broadcast"].add_ipaddr(config["NETWORK"]["gateway"], config["NETWORK"]["subnet_mask_cidr"])
    if config["AP"]["bssid"]:
        interface_objects["broadcast"].set_hwaddr(config["AP"]["bssid"])
    interface_objects["broadcast"].set_state("up")

    for command in [
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"]
    ]:
        subprocess.call(command)
    subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", interface_objects["broadcast"].name, "-j", "MASQUERADE"])

    if config["HARDWARE"]["forward_iface"]:
        for command in [
            ["iptables", "-A", "FORWARD", "-i", interface_objects["forward"].name, "-o", interface_objects["broadcast"].name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            ["iptables", "-A", "FORWARD", "-i", interface_objects["broadcast"].name, "-o", interface_objects["forward"].name, "-j", "ACCEPT"]
        ]:
            subprocess.call(command)

    return None


