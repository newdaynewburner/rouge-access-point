#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import logging
import getopt
import configparser
from lib.datatypes import HostapdConfigFile, DnsmasqConfigFile, DNSOverridesFile
from lib.managers import APComponentManager
from lib.util import (
    setup_system_networking,
    cleanup_system_networking,
    gen_hostapd_conf,
    gen_dnsmasq_conf,
    gen_dns_overrides_file
)

##################################################
# HELPER FUNCTIONS                               #
#                                                #
# These make calls to the program's Bash scripts #
##################################################
def setup_system_networking(config, logger):
    """ Configure networking on the system
    """
    if not config["AP"]["bssid"]:
        if not config.getboolean("EVASIONS", "always_spoof_mac_address"):
            mac_address = "0"
        else:
            mac_address = subprocess.check_output(["scripts/generate_random_mac.sh"], text=True)
            mac_address = mac_address.strip()
    else:
        mac_address = config["AP"]["bssid"]

    try:
        subprocess.check_call([
            "scripts/setup_networking.sh",
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
            "scripts/cleanup_networking.sh",
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
            "scripts/gen_hostapd_conf.sh",
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
            "scripts/gen_dnsmasq_conf.sh",
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
    dns_overrides_file = DNSOverridesFile(config["ATTACKS"]["dns_overrides_file"], config=config, logger=logger)
    dns_overrides_file.append_doh_blocklist(config["EVASIONS"]["doh_blocklist_file"])
    dns_overrides_file.export()
    return dns_overrides_file

####################################################
# MAIN FUNCTION                                    #
#                                                  #
# Main function called after progam initialization #
####################################################
def main(config, logger, hostapd_config_file, dnsmasq_config_file, dns_overrides_file):
    """ Main function. Contains the core high-level program logic
    """
    # Initialize the APComponents object to control the programs needed for running the AP
    logger.info(f"Initializing component manager")
    apcompmgr = APComponentManager(
        hostapd_config_file,
        dnsmasq_config_file,
        dns_overrides_file,
        config=config,
        logger=logger
    )

    # Start the components and bring the AP up. Component start order is: dnsmasq, dnschef, hostapd
    logger.info(f"Initialization is complete. Starting necessary daemons and bringing the AP up now")
    for component in ("dnsmasq", "dnschef", "hostapd"):
        logger.info(f"Starting component: {component}")
        apcompmgr.start_component(component)
        time.sleep(3)

    # Loop forever until shutdown command issued
    print(f"The rouge AP has been started and is now running. Commands can be issued to it below.")
    print(f"See 'help' for the command list and usage information.")
    while True:
        cmd = input(f"> ")
        if cmd == "help":
            # Show the command list and usage information
            logger.debug(f"Got command: help")
            print(f"COMMANDS:")
            print(f"\thelp\t-\tShow the command list and usage information")
            print(f"\tclear\t-\tClear the screen")
            print(f"\texit\t-\tExit the command loop and shut down the AP cleanly")
            continue

        elif cmd == "clear":
            # Clear the screen
            logger.debug(f"Got command: clear")
            subprocess.call(["clear"])
            continue

        elif cmd == "exit":
            # Exit the command loop and shut down the AP cleanly
            logger.debug(f"Got command: exit")
            break

        else:
            # Error handling - invalid command
            logger.warning(f"Got invalid command: {cmd}")
            print(f"Invalid command! See 'help' for a list of commands")
            continue

    # Command loop exited, so the components must be stopped, shutting down the AP, then networking must be reverted to its previous state
    logger.info(f"Exit command received! Shutting down cleanly and exiting. Changes to system networking configuration that were made will be reverted")
    for component in ("hostapd", "dnschef", "dnsmasq"):
        logger.info(f"Stopping component: {component}")
        apcompmgr.stop_component(component)
    logger.info(f"Reverting system networking configuration")
    cleanup_system_networking(config, logger)
    return None

# Begin execution
if __name__ == "__main__":
    # Make sure the installer was ran, otherwise it won't work!
    installed = True
    for item in [
        "/usr/sbin/rouge-access-point",
        "/etc/rouge-access-point/",
        "/usr/lib/rouge-access-point/",
        "/var/log/rouge-access-point/"
    ]:
        if not os.path.exists(item):
            installed = False
    if not installed:
        print("It appears that you have not ran the installation script yet. This program will not run correctly unless you do so.")
        if input("Continue anyway? [Y/N]> ").upper() != "Y":
            print("Exiting script now!")
            sys.exit(-1)


    # Read configuration file and set up the logger
    config = configparser.ConfigParser()
    config.read(sys.argv[1])
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(config["LOGGING"]["log_file"]),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger()
    logger.info(f"Program start. Logging started. Using logfile: {config['LOGGING']['log_file']}")

    # Setup system networking
    logger.info(f"Setting up system networking")
    setup_system_networking(config, logger)

    # Generate hostapd config file
    logger.info(f"Generating hostapd configuration file")
    hostapd_config_file = gen_hostapd_conf(config, logger)

    # Generate dnsmasq config file
    logger.info(f"Generating dnsmasq configuration file")
    dnsmasq_config_file = gen_dnsmasq_conf(config, logger)

    # Generate DNS overrides file
    logger.info(f"Generating DNS overrides file")
    dns_overrides_file = gen_dns_overrides_file(config, logger)

    # Enter the main function
    main(config, logger, hostapd_config_file, dnsmasq_config_file, dns_overrides_file)

    # Log final shutdown message and exit successfully
    logger.info(f"Program stop. Logging ended.")
    sys.exit(0)

