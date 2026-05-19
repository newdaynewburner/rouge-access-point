"""
lib/util.py

Contains various helper functions used in other parts of the script
"""

import os
import sys
import subprocess
import logging

def setup_system_networking(config, logger):
    """ Configure networking on the system
    """
    if not config["AP"]["bssid"]:
        if not config.getboolean("EVASIONS", "always_spoof_mac_address"):
            mac_address = "0"
        else:
            mac_address = subprocess.check_output(["/etc/rouge-access-point/scripts/generate_random_mac.sh"], text=True)
            mac_address = mac_address.strip()
    else:
        mac_address = config["AP"]["bssid"]

    try:
        subprocess.check_call([
            "/etc/rouge-access-point/scripts/setup_networking.sh",
            config["HARDWARE"]["broadcast_iface"],
            config["HARDWARE"]["forward_iface"],
            config["AP"]["gateway"],
            mac_address
        ])
    except subprocess.CalledProcessError as err_msg:
        logger.error(f"Failed to set up networking! Error message: {err_msg}")
        raise err_msg
    return None

def cleanup_system_networking(config, logger):
    """ Revert the systems networking configuration to its previous state
    """
    try:
        subprocess.check_call([
            "/etc/rouge-access-point/scripts/cleanup_networking.sh",
            config["HARDWARE"]["broadcast_iface"],
            config["HARDWARE"]["forward_iface"]
    ])
    except subprocess.CalledProcessError as err_msg:
        logger.error(f"Failed to clean up networking! Error message: {err_msg}")
        raise err_msg
    return None


def gen_hostapd_conf(config, logger):
    """ Generate the hostapd configuration file
    """
    try:
        subprocess.check_call([
            "/etc/rouge-access-point/scripts/gen_hostapd_conf.sh",
            config["HARDWARE"]["broadcast_iface"],
            config["AP"]["essid"],
            "a" if config["AP"]["band"] == "5g" else "g",
            config["AP"]["channel"],
            config["CONFIG"]["hostapd_config_file"]
        ])
    except subprocess.CalledProcessError as err_msg:
        logger.error(f"Failed to generate hostapd configuration file! Error message: {err_msg}")
        raise err_msg
    return config["CONFIG"]["hostapd_config_file"]

def gen_dnsmasq_conf(config, logger):
    """ Generate the dnsmasq configuration file
    """
    try:
        subprocess.check_call([
            "/etc/rouge-access-point/scripts/gen_dnsmasq_conf.sh",
            config["HARDWARE"]["broadcast_iface"],
            config["AP"]["dhcp_start"],
            config["AP"]["dhcp_stop"],
            config["AP"]["gateway"],
            config["AP"]["dns_server"],
            config["CONFIG"]["dnsmasq_config_file"]
        ])
    except subprocess.CalledProcessError as err_msg:
        logger.error(f"Failed to generate dnsmasq configuration file! Error message: {err_msg}")
        raise err_msg
    return config["CONFIG"]["dnsmasq_config_file"]

def gen_dns_overrides_file(config, logger):
    """ Generate the DNS overrides file
    """
    dns_overrides_file = datatypes.DNSOverridesFile(config["ATTACKS"]["dns_overrides_file"], config=config, logger=logger)
    dns_overrides_file.append_doh_blocklist(config["EVASIONS"]["doh_blocklist_file"])
    dns_overrides_file.export()
    return dns_overrides_file
