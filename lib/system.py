"""
lib/system.py

Handles system configuration tasks
"""

import os
import sys
import subprocess
from . import datatypes
from . import interfaces
from . import exceptions

class SystemInitializer(object):
    """ Preforms the initialization sequence
    """

    def __init__(self, debug, config, logger):
        """ Initialize the object
        """
        self.debug = debug
        self.config = config
        self.logger = logger
        self.components = {}
        self.interfaces = {}

    def _load_components(self):
        """ Stage 1 - Load component programs into their objects
        """

        # Create Component objects for each component and return them
        for component in ("ap-host", "dhcp-server", "dns-server"):
            comp = datatypes.Component(component, self.config)
            self.components[component] = comp
            self.logger.info(f"[Initiailization Sequence] Loaded component: '{component}'")
        return self.components

    def _load_interfaces(self):
        """ Stage 2 - Load network interfaces into their objects
        """
        self.interfaces["broadcast"] = interfaces.WirelessInterface(self.config["HARDWARE"]["broadcast_iface"], manager="networkmanager")
        self.logger.info(f"[Initiailization Sequence] Using '{self.interfaces['broadcast'].name}' as broadcast interface")
        if self.config["HARDWARE"]["forward_iface"]:
            if self.config["HARDWARE"]["forward_iface_type"] == "wired":
                self.interfaces["forward"] = interfaces.WiredInterface(self.config["HARDWARE"]["forward_iface"], manager="networkmanager")
            elif self.config["HARDWARE"]["forward_iface_type"] == "wireless":
                self.interfaces["forward"] = interfaces.WirelessInterface(self.config["HARDWARE"]["forward_iface"], manager="networkmanager")
            else:
                raise Exception(f"Invalid forward interface type specified in the config file!")
            self.logger.info(f"[Initiailization Sequence] Using '{self.interfaces['forward'].name}' as forward interface")
            return self.interfaces

    def _setup_networking(self):
        """ Stage 3 - Set up the networking and routing configuration for the system
        """

        # Kill NetworkManager, wpa_supplicant, hostapd, and dnsmasq as configured
        if bool(self.config["SYSTEM"]["kill_networkmanager"]):
            subprocess.call(["systemctl", "stop", "NetworkManager"])
            self.logger.info(f"[Initialization Sequence] Stopped NetworkManager")
        if bool(self.config["SYSTEM"]["kill_wpa_supplicant"]):
            subprocess.call(["systemctl", "stop", "wpa_supplicant"])
            self.logger.info(f"[Initialization Sequence] Stopped wpa_supplicant")
        if bool(self.config["SYSTEM"]["kill_hostapd"]):
            subprocess.call(["systemctl", "stop", "hostapd"])
            self.logger.info(f"[Initialization Sequence] Stopped hostapd")
        if bool(self.config["SYSTEM"]["kill_dnsmasq"]):
            subprocess.call(["systemctl", "stop", "dnsmasq"])
            self.logger.info(f"[Initialization Sequence] Stopped dnsmasq")

        # NetworkManager compatability mode
        if self.config["SYSTEM"]["nm_compatability_mode"] == "true":
            for interface in self.interfaces.values():
                interface.stop_management()
                self.logger.info(f"[Initialization Sequence] {interface.name} removed from NetworkManager management")

        # Assign broadcast interface's IP address
        self.interfaces["broadcast"].set_state("down")
        self.logger.info(f"[Initiailization Sequence] Brought the broadcast interface down")
        self.interfaces["broadcast"].flush_ipaddrs()
        self.logger.info(f"[Initiailization Sequence] Flushed broadcast interface's IP addresses")
        self.interfaces["broadcast"].add_ipaddr(self.config["NETWORK"]["gateway"], self.config["NETWORK"]["subnet_mask_cidr"])
        self.logger.info(f"[Initiailization Sequence] Set broadcast interface's IP address")

        # Set the MAC address of the broadcast interface
        if self.config["AP"]["bssid"]:
            self.interfaces["broadcast"].set_hwaddr(self.config["AP"]["bssid"])
            self.logger.info(f"[Initiailization Sequence] Set the MAC address of the broadcast interface to '{self.config['AP']['bssid']}'")

        # Bring the interface up and enable IP forwarding for IPv4 and IPv6, then enable masquerading
        self.interfaces["broadcast"].set_state("up")
        self.logger.info(f"[Initiailization Sequence] Brought the broadcast interface up")
        for command in [
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"]
        ]:
            subprocess.call(command)
        self.logger.info(f"[Initiailization Sequence] Enabled IP forwarding")
        subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", self.interfaces["broadcast"].name, "-j", "MASQUERADE"])
        self.logger.info(f"[Initiailization Sequence] Enabled masquerading")

        # If a forward interface is present, route traffic from the broadcast interface to it so clients can access the Internet
        if self.config["HARDWARE"]["forward_iface"]:
            for command in [
                ["iptables", "-A", "FORWARD", "-i", self.interfaces["forward"].name, "-o", self.interfaces["broadcast"].name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                ["iptables", "-A", "FORWARD", "-i", self.interfaces["broadcast"].name, "-o", self.interfaces["forward"].name, "-j", "ACCEPT"]
            ]:
                subprocess.call(command)
            self.logger.info(f"[Initiailization Sequence] Routing configured to forward client traffic from broadcast interface to the forward interface")
        return None

    def preform_initialization_sequence(self, stage=None):
        """ Preform the full initialization sequence, or a single stage of it if specified
        """

        # Initiate return values dictionary
        rvals = {
            "stage_1": {
                "complete": False,
                "rvals": {
                    "components": None
                }
            },
            "stage_2": {
                "complete": False,
                "rvals": {
                    "interfaces": None
                }
            },
            "stage_3": {
                "complete": False,
                "rvals": {}
            }
        }

        # Single stage
        if stage:
            if stage == 1:
                self.logger.info(f"[Initialization Sequence] Preforming stage 1 initialization tasks")
                components = self._load_components()
                rvals["stage_1"]["complete"] = True
                rvals["stage_1"]["rvals"]["components"] = components
            elif stage == 2:
                self.logger.info(f"[Initialization Sequence] Preforming stage 2 initialization tasks")
                interfaces = self._load_interfaces()
                rvals["stage_2"]["complete"] = True
                rvals["stage_2"]["rvals"]["interfaces"] = interfaces
            elif stage == 3:
                self.logger.info(f"[Initialization Sequence] Preforming stage 3 initialization tasks")
                self._setup_networking()
                rvals["stage_3"]["complete"] = True
            else:
                raise Exception(f"Invalid stage '{stage}'! Stage must be either '1', '2', or '3'")
            return None

        # Full sequence
        self.logger.info(f"[Initialization Sequence] Preforming stage 1 initialization tasks")
        components = self._load_components()
        rvals["stage_1"]["complete"] = True
        rvals["stage_1"]["rvals"]["components"] = components
        self.logger.info(f"[Initialization Sequence] Preforming stage 2 initialization tasks")
        interfaces = self._load_interfaces()
        rvals["stage_2"]["complete"] = True
        rvals["stage_2"]["rvals"]["interfaces"] = interfaces
        self.logger.info(f"[Initialization Sequence] Preforming stage 3 initialization tasks")
        self._setup_networking()
        rvals["stage_3"]["complete"] = True

        # Return the execution data
        return rvals




