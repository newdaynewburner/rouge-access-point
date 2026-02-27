#!/usr/bin/env python3

"""
rouge-access-point.py

Tool for creating a highly-versatile rouge access point
"""

import os
import sys
import time
import subprocess
import logging
import getopt
import configparser
from lib import system, configuration
from lib.datatypes import components, plugins, interfaces
from lib.ui import console

__project_github__ = "https://github.com/newdaynewburner/rouge-access-point"
__version__ = "0.1"
__author__ = "Brandon Hammond"
__author_email__ = "newdaynewburner@gmail.com"

def main(debug, config, logger, component_objects, plugin_objects, interface_objects):
    """ Contains main high-level program logic
    """

    ###################################
    # 10. ENTER THE CONSOLE INTERFACE #
    ###################################
    logger.info(f"Initializing console interface")
    time.sleep(1)
    console_ui = console.ApplicationConsole(component_objects, plugin_objects, interface_objects, config=config, logger=logger)
    console_ui.console_interface()

    #######################################
    # 11. RESTART NETWORKMANAGER AND EXIT #
    #######################################
    logger.info(f"Exited console interface, preforming clean shutdown tasks and exiting")
    for component in component_objects.values():
        d = component.get_daemon()
        d.stop()
    for command in [
        ["systemctl", "start", "NetworkManager"]
    ]:
        subprocess.call(command)

    return None


# Begin execution
if __name__ == "__main__":
    #######################
    # 1. PERMISSION CHECK #
    #######################
    if os.geteuid() != 0:
        print("This script MUST be ran as root! Quitting!")
        sys.exit(0)

    #####################
    # 2. PARSE CLI ARGS #
    #####################
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvdfc:C:P:", (
            "help",
            "version",
            "debug",
            "force-reinstallation"
            "config=",
            "components=",
            "plugins="
        ))
    except getopt.GetoptError as err_msg:
        raise(err_msg)

    debug = False
    force_reinstall = False
    config_file = "config/rouge-access-point.ini"
    component_list = ["ap-host", "dhcp-server", "dns-server"]
    plugin_list = []

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            # Display the help message
            print("USAGE:")
            print(f"\t{sys.argv[0]} [-h] [-v] [-d] [-f] [-c CONFIG_FILE] [-C COMPONENTS] [-P PLUGINS]")
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

        elif opt in ("-f", "--force-reinstallation"):
            # Force reinstall of components and plugins
            force_reinstall = True

        elif opt in ("-c", "--config"):
            # Specify an alternative configuration file
            if "~" in arg:
                arg = os.path.expanduser(arg)
            if not os.path.isfile(arg):
                raise Exception("Specified configuration file does not exist! Check the filepath and try again!")
            config_file = arg

        elif opt in ("-C", "--components"):
            # Specify components to use
            component_list = args.split(",")

        elif opt in ("-P", "--plugins"):
            # Specify the plugins to use
            plugin_list = args.split(",")

    #######################
    # 3. READ CONFIG FILE #
    #######################
    config = configparser.ConfigParser()
    config.read(config_file)

    ###################
    # 4. SETUP LOGGER #
    ###################
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger()
    logger.info(f"Begin logging. Initializing the program now.")

    ######################
    # 5. LOAD COMPONENTS #
    ######################
    component_installer = components.ComponentInstaller()
    component_objects = {}
    for component in component_list:
        if not component_installer.check(component):
            component_installer.install(component)
        if force_reinstall:
            component_installer.uninstall(component)
            component_installer.install(component)
        if component == "ap-host":
            logger.info(f"Generating ap-host configuration file")
            configuration.gen_ap_host_config(components.COMPONENT_DATA["ap-host"]["config"], config)
        elif component == "dhcp-server":
            logger.info(f"Generating dhcp-server configuration file")
            configuration.gen_dhcp_server_config(components.COMPONENT_DATA["dhcp-server"]["config"], config)
        elif component == "dns-server":
            logger.info(f"Generating dns-server configuration file")
            configuration.gen_dns_server_config(components.COMPONENT_DATA["dns-server"]["config"], config)
        logger.info(f"Initializing Component object for component: {component}")
        component_object = component_installer.get_object(component)
        component_objects[component] = component_object
    for component in component_objects.keys():
        logger.info(f"Starting component: {component}")
        d = component_objects[component].get_daemon()
        d.start()

    ###################
    # 6. LOAD PLUGINS #
    ###################
    plugin_installer = plugins.PluginInstaller()
    plugin_objects = {}
    for plugin in plugin_list:
        if not plugin_installer.check(plugin):
            plugin_installer.install(plugin)
        if force_reinstall:
            plugin_installer.uninstall(plugin)
            plugin_installer.install(plugin)
        logger.info(f"Initializing Plugin object for plugin: {plugin}")
        plugin_object = plugin_installer.get_object()
        plugin_objects[plugin] = plugin_object

    ######################
    # 7. LOAD INTERFACES #
    ######################
    interface_objects = {}
    logger.info(f"Loading broadcast interface")
    interface_objects["broadcast"] = interfaces.WirelessInterface(config["HARDWARE"]["broadcast_iface"], manager="networkmanager")
    if config["HARDWARE"]["forward_iface"]:
        logger.info(f"Loading forward interface")
        if config["HARDWARE"]["forward_iface_type"] == "wired":
            interface_objects["forward"] = interfaces.WiredInterface(config["HARDWARE"]["forward_iface"], manager="networkmanager")
        elif config["HARDWARE"]["forward_iface_type"] == "wireless":
            interface_objects["forward"] = interfaces.WirelessInterface(config["HARDWARE"]["forward_iface"], manager="networkmanager")
        else:
            raise Exception(f"Invalid forward interface type specified in the config file!")

    #######################
    # 8. SETUP NETWORKING #
    #######################
    logger.info(f"Setting up system networking")
    system.setup_networking(interface_objects, config=config, logger=logger)

    ##########################
    # 9. ENTER MAIN FUNCTION #
    ##########################
    logger.info(f"Entering main function")
    main(debug, config, logger, component_objects, plugin_objects, interface_objects)

