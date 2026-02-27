"""
lib/system.py

Handles system configuration tasks
"""

import os
import sys
import subprocess
from . import exceptions

class SystemProcessManager(object):
    """ Handles process and service management tasks
    """

    def __init__(self, config=None, logger=None):
        """ Initialize the object
        """
        self.config = config
        self.logger = logger

    def start_service(self, service):
        """ Start a service with systemctl
        """
        try:
            subprocess.call(["systemctl", "start", service])
        except subprocess.CalledProcessError as err_msg:
            raise exceptions.SystemProcessManagerError(f"Encountered an exception while trying to start service '{service}'! Error message: {err_msg}")
        return None

    def stop_service(self, service):
        """ Start a service with systemctl
        """
        try:
            subprocess.call(["systemctl", "stop", service])
        except subprocess.CalledProcessError as err_msg:
            raise exceptions.SystemProcessManagerError(f"Encountered an exception while trying to stop service '{service}'! Error message: {err_msg}")
        return None

class SystemNetworkingManager(object):
    """ Handles system level networking configuration tasks
    """

    def __init__(self, interfaces, config=None, logger=None):
        """ Initialize the object
        """
        self.config = config
        self.logger = logger
        self.interfaces = interfaces
        self.radio_blocked = None
        self.ip_forwarding_enabled = None
        self.masquerading_enabled = None
        self.traffic_forwarding_enabled = None

    def master_radio_block(self):
        """ Block all wireless interfaces with rfkill
        """
        subprocess.call(["rfkill", "block", "all"])
        self.radio_blocked = True
        return None

    def master_radio_unblock(self):
        """ Unblock all wireless interfaces with rfkill
        """
        subprocess.call(["rfkill", "unblock", "all"])
        self.radio_blocked = False
        return None

    def set_ip_forwarding(self, val):
        """ Enable or disable IPv4 and IPv6 forwarding
        """
        if val:
            sysctl_value = "1"
            self.ip_forwarding_enabled = True
        else:
            sysctl_value = "0"
            self.ip_forwarding_enabled = False
        try:
            for command in [
                ["sysctl", "-w", f"net.ipv4.ip_forward={sysctl_value}"],
                ["sysctl", "-w", f"net.ipv6.conf.all.forwarding={sysctl_value}"]
            ]:
                subprocess.call(command)
        except subprocess.CalledProcessError as err_msg:
            raise exceptions.SystemNetworkingManagerError(f"Failed to change IP forwarding settings! Error message: {err_msg}")
        return None

    def set_masqueradeing(self, val):
        """ Enable or disable masquerading
        """
        try:
            if val:
                self.masquerading_enabled = True
                subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", self.interfaces["broadcast"].name, "-j", "MASQUERADE"])
            else:
                self.masquerading_enabled = False
                subprocess.call(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", self.interfaces["broadcast"].name, "-j", "MASQUERADE"])
        except subprocess.CalledProcessError as err_msg:
            raise exceptions.SystemNetworkingManagerError(f"Failed to change masquerading settings! Error message: {err_msg}")
        return None

    def forward_traffic(self):
        """ Forward traffic from the broadcast interface to the forward interface
        """
        try:
            self.traffic_forwarding_enabled = True
            for command in [
                ["iptables", "-A", "FORWARD", "-i", self.interfaces["forward"].name, "-o", self.interfaces["broadcast"].name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                ["iptables", "-A", "FORWARD", "-i", self.interfaces["broadcast"].name, "-o", self.interfaces["forward"].name, "-j", "ACCEPT"]
            ]:
                subprocess.call(command)
        except subprocess.CalledProcessError as err_msg:
            raise exceptions.SystemNetworkingManagerError(f"Failed to enable traffic forwarding with error message: {err_msg}")
        return None

def setup_system_networking(interfaces, config=None, logger=None):
    """ Go through the series of configuration tasks necessary to operate a wireless AP
    """
    process_manager = SystemProcessManager(config=config, logger=logger)
    networking_manager = SystemNetworkingManager(interfaces, config=config, logger=logger)

    # 1. Kill conflicting services as configured and ensure radios are unblocked
    if bool(config["SYSTEM"]["kill_networkmanager"]):
        process_manager.stop_service("NetworkManager.service")
    if bool(config["SYSTEM"]["kill_wpa_supplicant"]):
        process_manager.stop_service("wpa_supplicant.service")
    if bool(config["SYSTEM"]["kill_hostapd"]):
        process_manager.stop_service("hostapd.service")
    if bool(config["SYSTEM"]["kill_dnsmasq"]):
        process_manager.stop_service("dnsmasq.service")
    networking_manager.master_radio_unblock()

    # 2. Remove interfaces from NetworkManager management if compatibility mode is enabled
    if bool(config["SYSTEM"]["nm_compatability_mode"]):
        for interface in interfaces.values():
            interface.stop_management()

    # 3. Assign addresses to the broadcast interface
    interfaces["broadcast"].set_state("down")
    interfaces["broadcast"].flush_ipaddrs()
    interfaces["broadcast"].add_ipaddr(config["NETWORK"]["gateway"], config["NETWORK"]["subnet_mask_cidr"])
    if config["AP"]["bssid"]:
        interfaces["broadcast"].set_hwaddr(config["AP"]["bssid"])
    interfaces["broadcast"].set_state("up")

    # 4. Enable IP forwarding and masquerading
    networking_manager.set_ip_forwarding(True)
    networking_manager.set_masqueradeing(True)

    # 5. If a forward interface is present, enable traffic forwarding
    if config["HARDWARE"]["forward_iface"]:
        networking_manager.forward_traffic()

    return None

def takedown_system_networking(interfaces, config=None, logger=None):
    """ Revert the changes made to the system networking configuration before quitting
    """
    process_manager = SystemProcessManager(config=config, logger=logger)
    networking_manager = SystemNetworkingManager(interfaces, config=config, logger=logger)

    # 1. Disable IP forwarding and masquerading
    networking_manager.set_masqueradeing(False)
    networking_manager.set_ip_forwarding(False)

    # 2. Restart NetworkManager if it was killed
    if bool(config["SYSTEM"]["kill_networkmanager"]):
        process_manager.start_service("NetworkManager.service")

    # 3. Remanage interfaces with NM if in compatibility mode
    if bool(config["SYSTEM"]["nm_compatability_mode"]):
        for interface in interfaces.values():
            interface.start_management()

    return None
