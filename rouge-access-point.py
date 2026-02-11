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

# Begin execution
if __name__ == "__main__":
    # Parse command line arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvdc:", (
            "help",
            "version",
            "debug",
            "config="
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

