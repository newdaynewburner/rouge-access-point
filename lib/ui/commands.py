"""
lib/ui/commands.py

Backend console interface command logic
"""

import os
import sys
import subprocess
from . import elements
from . import exceptions

class ConsoleCommands(object):
    """ Contains the logic for console interface commands
    """

    def __init__(self, console, components, interfaces, config=None, logger=None):
        """ Initialize the object
        """
        self.config = config
        self.logger = logger
        self.components = components
        self.interfaces = interfaces
        self.command_history = []

    ####################
    # CONSOLE COMMANDS #
    ####################
    def help_(self):
        """ Show the help message
        """
        print(elements.HELP_MESSAGE)
        print("")
        return None

    def exit_(self):
        """ Exit and initiate shutdown
        """
        confirmation = input("This will exit the console and shut down the rouge access point. Really exit? [Y/N]")
        if confirmation.lower() in ("y", "yes"):
            return True
        else:
            return False

    def clear(self):
        """ Clear the screen
        """
        subprocess.call(["clear"])
        return None

    def banner(self, clear=False):
        """ Show the banner
        """
        if clear:
            self.clear()
        print(elements.BANNER)
        print("")
        return None

    def shell(self):
        """ Enter a system shell
        """
        self.logger.warning(f"[Console]  system shell was called through the console interface")
        subprocess.call(["bash"])
        return None

    def history(self, new_hist_cmd=None):
        """ Displays recently used commands
        """
        if new_hist_cmd:
            self.command_history.append(new_hist_cmd)
            return None
        print("Recently used commands:")
        for command in self.command_history:
            print(command)
        print("")
        return None

    ######################
    # COMPONENT COMMANDS #
    ######################
    def start(self, component):
        """ Start a component
        """
        if not component in self.components.keys():
            raise exceptions.ConsoleCommandError("Invalid component name '{component}'! No such component exists!")
        try:
            api = self.components[component].get_api()
            api.Start()
        except Exception as err_msg:
            raise exceptions.DBusAPIError(f"Got error from DBus API of component {component}! Endpoint: Start - Error Message: {err_msg}")
        return None

    def stop(self, component):
        """ Stop a component
        """
        if not component in self.components.keys():
            raise exceptions.ConsoleCommandError("Invalid component name '{component}'! No such component exists!")
        try:
            api = self.components[component].api
            api.Stop()
        except Exception as err_msg:
            raise exceptions.DBusAPIError(f"Got error from DBus API of component {component}! Endpoint: Stop - Error Message: {err_msg}")
        return None

    def restart(self, component):
        """ Restart a component
        """
        if not component in self.components.keys():
            raise exceptions.ConsoleCommandError("Invalid component name '{component}'! No such component exists!")
        try:
            api = self.components[component].api
            api.Restart()
        except Exception as err_msg:
            raise exceptions.DBusAPIError(f"Got error from DBus API of component {component}! Endpoint: Restart - Error Message: {err_msg}")
        return None

    def configure(self, component, setting, value):
        """ Configure a setting for a component
        """
        if not component in self.components.keys:
            raise exceptions.ConsoleCommandError("Invalid component name '{component}'! No such component exists!")
        try:
            api = self.components[component].api
            api.Configure(setting, value)
        except Exception as err_msg:
            raise exceptions.DBusAPIError(f"Got error from DBus API of component {component}! Endpoint: Configure - Error Message: {err_msg}")
        return None

    ######################
    # SCRIPTING COMMANDS #
    ######################
    def exec_sequence(self, cmd_file):
        """ Load and return the command list for execution
        """
        if "~" in cmd_file:
            cmd_file = os.path.expanduser(cmd_file)
        if not os.path.isfile(cmd_file):
            raise exceptions.ConsoleCommandError(f"File '{cmd_file}' does not exist!")
        command_strings = []
        with open(cmd_file, "r") as cf:
            for command_string in cf:
                if command_string[0] == "#":
                    continue
                else:
                    command_strings.append(command_string)
        if len(command_strings) == 0:
            raise exceptions.ConsoleCommandError(f"File '{cmd_file}' contains no commands!")
        return command_strings
