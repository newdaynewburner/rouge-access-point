"""
lib/ui/console.py

Console interface for issuing commands
"""

import os
import sys
import time
import subprocess
import threading
import configparser
from . import elements
from . import commands
from . import exceptions

class ApplicationConsole(object):
    """ Console interface
    """

    def __init__(self, components, plugins, interfaces, config=None, logger=None):
        """ Initialize the object
        """
        self.config = config
        self.logger = logger
        self.components = components
        self.plugins = plugins
        self.interfaces = interfaces

    def _yn_user_prompt(self, message):
        """ Prompt the user to answer yes or no
        """
        while True:
            response = input(f"{message} [Y/N]: ")
            if response.lower() in ("y", "yes"):
                return True
            elif response.lower() in ("n", "no"):
                return False
            else:
                self.logger.warning(f"Got invalid response to Y/N user prompt: {response}")
                print("Invalid response. Please respond with either 'Y' or 'N'.")

    def _continue_user_prompt(self):
        """ Prompt the user to press enter
        """
        input("Press [ENTER] to continue...")
        return None

    def _cmd_user_prompt(self):
        """ Prompt the user for the next command
        """
        while True:
            cmd_str = input("> ")
            if cmd_str != "":
                break
        cmd, args = commands.command_parser(cmd_str)
        return cmd, args

    def ui_entrypoint(self):
        """ Entrypoint into the console interface
        """
        if self._yn_user_prompt("Initialization sequence complete! Bring the AP up now?"):
            print("Bringing the AP up now...")
            self.logger.info(f"User opted for immediate launch. Bringing the AP up.")
            for component in ("ap-host", "dhcp-server", "dns-server"):
                self.logger.info(f"Starting component '{component}' via call to DBus API endpoint Start")
                api_client = self.components[component].get_api()
                api_client.Start()
                if component == "ap-host":
                    time.sleep(5)
            self.logger.info(f"AP is now up!")
            print("...Done! The AP is now up! It should be visible to client devices and ready to accept connections!")
            self._continue_user_prompt()
        subprocess.call(["clear"])
        print(elements.BANNER)
        self.command_loop()
        return None

    def command_loop(self):
        """ Main command loop
        """
        while True:
            cmd, args = self._cmd_user_prompt()
            if cmd == "help":
                print("COMMAND LIST:")
                print("help")
                print("shell")
                print("exit")
            elif cmd == "shell":
                subprocess.call(["bash"])
            elif cmd == "exit":
                break
        return None




