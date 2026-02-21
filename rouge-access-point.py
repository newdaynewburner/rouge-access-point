#!/usr/bin/env python3

"""
rouge-access-point.py

Tool for creating a highly-versatile rouge access point
"""

import os
import sys
import time
import logging
import configparser
import getopt
import subprocess
import threading
from lib.system import SystemInitializer

__project_github__ = "https://github.com/newdaynewburner/rouge-access-point"
__version__ = "0.1"
__author__ = "Brandon Hammond"
__author_email__ = "newdaynewburner@gmail.com"

def main(debug, config, logger, initializer, components, interfaces):
    """ Contains main high-level program logic

    Arguments:
        debug - bool - Enables debugging mode if True
        config - ConfigParser object - Readable configuration file data
        logger - Logger object - Active message logger
        initializer - Initializer object - Active Initializer object instance
        components - dict - Contains Component objects for the components
        interfaces - dict - Contains Interface objects for the interfaces

    Returns:
        None
    """

    # Start the core component service daemons
    for component in [
        components["ap-host"],
        components["dhcp-server"],
        components["dns-server"],
    ]:
        component.start_daemon()


    # Start each component
    logger.info(f"[Main Thread] Bringing up the AP now")
    start_order = (components["dhcp-server"], components["ap-host"], components["dns-server"])
    for component in start_order:
        logger.info(f"[Main Thread] Starting '{component}' component as daemon...")
        component.start_daemon()
        logger.info(f"[Main Thread] ...Done! The '{component}' was started successfully!")
    logger.info(f"[Main Thread] All component daemons have been started and the AP is now up!")

    x = 0
    while x < 60:
        for component in start_order:
            component.showouts()
        time.sleep(1)
        x = x + 1

    input("Press [ENTER] to stop the AP")
    components["ap-host"].stop()
    components["dhcp-server"].stop()
    components["dns-server"].stop()

    return None

# Begin execution
if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("This script MUST be ran as root! Quitting!")
        sys.exit(0)

    # Parse command line arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvdc:", (
            "help",
            "version",
            "debug",
            "config=",
        ))
    except getopt.GetoptError as err_msg:
        raise(err_msg)

    debug = False
    config_file = "config/rouge-access-point.ini"

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            # Display the help message
            print("USAGE:")
            print(f"\t{sys.argv[0]} [-h] [-v] [-d] [-c CONFIG_FILE]")
            sys.exit(0)

        elif opt in ("-v", "--version"):
            # Display the version message
            print(f"Rouge Access Point ({__project_github__})")
            print(f"Version {__version__}")
            print(f"By {__author__} <{__author_email__}>")
            sys.exit(0)

        elif opt in ("-d", "--debug"):
            # Enable debugging mode
            debug = True

        elif opt in ("-c", "--config"):
            # Specify an alternative configuration file
            if "~" in arg:
                arg = os.path.expanduser(arg)
            if not os.path.isfile(arg):
                raise Exception("Specified configuration file does not exist! Check the filepath and try again!")
            config_file = arg

    # Read the configuration file
    config = configparser.ConfigParser()
    config.read(config_file)

    # Set up the logger
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger()
    logger.info(f"[Main Process] Begin logging for current run")

    # Preform the main initialization sequence and extract the components and interfaces from the return values
    logger.info(f"[Main Process] Now preforming the main initialization sequence")
    initializer = SystemInitializer(debug, config, logger)
    rvals = initializer.preform_initialization_sequence()
    components = rvals["stage_1"]["rvals"]["components"]
    interfaces = rvals["stage_2"]["rvals"]["interfaces"]
    logger.info(f"[Main Process] Initialization sequence is complete!")

    # Enter the main function
    main(debug, config, logger, initializer, components, interfaces)

