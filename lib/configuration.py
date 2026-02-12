"""
lib/configuration.py

Handles reading/writing configuration data between
the core components
"""

import os
import sys
import configparser
from . import datatypes
from . import exceptions

def _write_component_config(component_config_path, component_config):
    """ Helper function that writes per-component configuration files
    """
    if not os.path.isdir(os.path.split(component_config_path)[0]):
        os.makedirs(os.path.split(component_config_path)[0])
    with open(component_config_path, "w") as f:
        component_config.write(f)
    return component_config_path

def gen_ap_host_config(config):
    """ Generate ap-host config
    """
    component_config = configparser.ConfigParser()
    component_config["AP"] = {
        "broadcast_iface": config["HARDWARE"]["broadcast_iface"],
        "driver": config["HARDWARE"]["wireless_driver"],
        "essid": config["AP"]["essid"],
        "band": "g" if config["AP"]["band"] == "2.4g" else "a" if config["AP"]["band"] == "5g" else None,
        "channel": config["AP"]["channel"],
        "security": config["AP"]["security"],
        "passphrase": config["AP"]["passphrase"],
        "hostapd_executable": config["SYSTEM"]["hostapd_executable"],
        "hostapd_config_file": config["SYSTEM"]["hostapd_config_file"]
    }
    component_config_path = _write_component_config(os.path.join(config["COMPONENT"]["generated_config_dir"], "ap-host.ini"), component_config)
    return component_config_path

def gen_dhcp_server_config(config):
    """ Generate dhcp-server config
    """
    component_config = configparser.ConfigParser()
    component_config["DHCP"] = {
        "interface": config["HARDWARE"]["broadcast_iface"],
        "pool_start": config["DHCP"]["pool_start"],
        "pool_end": config["DHCP"]["pool_end"],
        "lease_time": config["DHCP"]["lease_time"],
        "static_lease_file": config["DHCP"]["static_lease_file"],
        "gateway": config["NETWORK"]["gateway"],
        "dns_server": config["NETWORK"]["dns_server"],
        "dnsmasq_executable": config["SYSTEM"]["dnsmasq_executable"],
        "dnsmasq_config_file": config["SYSTEM"]["dnsmasq_config_file"],
        "dnsmasq_lease_file": config["SYSTEM"]["dnsmasq_lease_file"],
        "dnsmasq_dhcp_script": config["SYSTEM"]["dnsmasq_dhcp_script"]
    }
    component_config_path = _write_component_config(os.path.join(config["COMPONENT"]["generated_config_dir"], "dhcp-server.ini"), component_config)
    return component_config_path

def gen_dns_server_config(config):
    """ Generate dns-server config
    """
    component_config = configparser.ConfigParser()
    component_config["DNS"] = {
        "zone_file": config["DNS"]["zone_file"],
        "override_file": config["DNS"]["override_file"],
        "primary_upstream": config["DNS"]["primary_upstream"],
        "backup_upstream": config["DNS"]["backup_upstream"],
        "laddr": config["DNS"]["laddr"],
        "lport": config["DNS"]["lport"],
        "ttl": config["DNS"]["ttl"]
    }
    component_config_path = _write_component_config(os.path.join(config["COMPONENT"]["generated_config_dir"], "dns-server.ini"), component_config)
    return component_config_path
