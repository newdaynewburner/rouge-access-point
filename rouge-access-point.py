#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import logging
import getopt
import configparser
from lib.listoperations import DnschefOverridesFile

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

def gen_dnschef_overrides_file()

##################################################################
# OBJECTS                                                        #
#                                                                #
# Object class definitions for custom data types and controllers #
##################################################################
class APComponents(object):
    """ Controls AP component services
    """
    def __init__(self, hostapd_config_file=None, dnsmasq_config_file=None, config=None, logger=None):
        if not hostapd_config_file or not dnsmasq_config_file:
            raise Exception(f"Config file paths must be given for both hostapd and dnsmasq")

        self.config = config
        self.logger = logger
        self.processes = {}
        self.components = {
            "hostapd": {
                "executable": "/usr/sbin/hostapd",
                "config_file": hostapd_config_file,
                "log_file": self.config["LOGGING"]["hostapd_log_file"],
                "process": None,
                "status": "not running"
            },
            "dnsmasq": {
                "executable": "/usr/sbin/dnsmasq",
                "config_file": dnsmasq_config_file,
                "log_file": self.config["LOGGING"]["dnsmasq_log_file"],
                "process": None,
                "status": "not running"
            },
            "dnschef": {
                "executable": "/usr/bin/dnschef",
                "config_file": None,
                "log_file": self.config["LOGGING"]["dnschef_log_file"],
                "dns_overrides_file": self.config["ATTACKS"]["dns_overrides_file"],
                "process": None,
                "status": "not running"
            }
        }

    def start_component(self, component: str) -> bool:
        """ Starts the specified component
        """
        if self.components[component]["status"] == "running":
            self.logger.warning(f"Cannot start. Component {component} is already running")
            return False

        if component == "hostapd":
            cmd = [
                self.components["hostapd"]["executable"],
                "-f",
                self.components["hostapd"]["log_file"],
                self.components["hostapd"]["config_file"]
            ]
        elif component == "dnsmasq":
            cmd = [
                self.components["dnsmasq"]["executable"],
                "--log-facility",
                self.components["dnsmasq"]["log_file"],
                "-C",
                self.components["dnsmasq"]["config_file"],
                "--keep-in-foreground"
            ]
        elif component == "dnschef":
            cmd = [
                self.components["dnschef"]["executable"],
                "--interface",
                self.config["AP"]["gateway"],
                "--logfile",
                self.components["dnschef"]["log_file"],
                "--file",
                self.components["dnschef"]["dns_overrides_file"]
            ]
        else:
            self.logger.error(f"An invalid component name was passed to start_component() method of APComponents object! Component name passed: {component}")
            raise Exception(f"An invalid component name was passed to start_component() method of APComponents object! Component name passed: {component}")

        try:
            self.components[component]["process"] = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.components[component]["status"] = "running"
        except subprocess.SubprocessError as err_msg:
            self.logger.error(f"Encountered an error while trying to start the {component} component! Error message: {err_msg}")
            raise err_msg
        return True

    def stop_component(self, component: str) -> bool:
        """ Stops the specified component
        """
        if self.components[component]["status"] == "not running":
            self.logger.warning(f"Cannot stop. Component {component} is not running")
            return False
        self.components[component]["process"].terminate()
        try:
            self.components[component]["process"].wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Could not end {component} component process with SIGTERM, sending SIGKILL")
            self.components[component]["process"].kill()
            self.components[component]["status"] = "not running"
        return True

    def restart_component(self, component):
        """ Restarts the specified component
        """
        if self.components[component]["status"] == "not running":
            self.logger.warning(f"Cannot restart. Component {component} is not running")
            return False

        self.stop_component(component)
        self.start_component(component)
        return True

####################################################
# MAIN FUNCTION                                    #
#                                                  #
# Main function called after progam initialization #
####################################################
def main(config, logger, hostapd_config_file, dnsmasq_config_file):
    """ Main function. Contains the core high-level program logic
    """
    # Initialize the APComponents object to control the programs needed for running the AP
    logger.info(f"Initializing component manager")
    apcompmgr = APComponents(
        hostapd_config_file=hostapd_config_file,
        dnsmasq_config_file=dnsmasq_config_file,
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

    # Enter the main function
    main(config, logger, hostapd_config_file, dnsmasq_config_file)

    # Log final shutdown message and exit successfully
    logger.info(f"Program stop. Logging ended.")
    sys.exit(0)

