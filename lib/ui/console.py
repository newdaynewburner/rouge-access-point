"""
lib/ui/console.py

Console interface for issuing commands
"""

import os
import sys
import subprocess
import threading
import configparser
from . import elements
from . import commands

class ConsoleCommandError(Exception):
    """ Raised when an error occurs executing a command from the console interface
    """
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class DBusAPIError(Exception):
    """ Raised when an error occurs making a call to a components DBus API
    """
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class ConsoleCommands(object):
    """ Contains the logic for console interface commands
    """

    def __init__(self, console, components, interfaces, config=None, logger=None):
        """ Initialize the object
        """
        self.config = config
        self.logger = logger
        self.console = console
        self.components = components
        self.interfaces = interfaces

    ####################
    # CONSOLE COMMANDS #
    ####################
    def help_(self):
        """ Show the help message
        """
        print(elements.HELP_MESSAGE)
        print("")
        return None

    def clear(self):
        """ Clear the screen
        """
        self.console._clear_screen()
        return None

    def banner(self):
        """ Show the banner
        """

    def shell(self):
        """ Enter a system shell
        """
        self.logger.warning(f"[Console]  system shell was called through the console interface")
        subprocess.call(["bash"])
        return None

    def history(self):
        """ Displays recently used commands
        """
        print("Recently used commands:")
        for command in self.console.command_history:
            print(command)
        print("")
        return None

    ######################
    # COMPONENT COMMANDS #
    ######################
    def start(self, component):
        """ Start a component
        """
        if not component in self.components.keys:
            raise ConsoleCommandError("Invalid component name '{component}'! No such component exists!")
        try:
            api = self.components[component].api
            api.Start()
        except Exception as err_msg:
            raise DBusAPIError(f"Got error from DBus API of component {component}! Endpoint: Start - Error Message: {err_msg}")
        return None

    def stop(self, component):
        """ Stop a component
        """
        if not component in self.components.keys:
            raise ConsoleCommandError("Invalid component name '{component}'! No such component exists!")
        try:
            api = self.components[component].api
            api.Stop()
        except Exception as err_msg:
            raise DBusAPIError(f"Got error from DBus API of component {component}! Endpoint: Stop - Error Message: {err_msg}")
        return None

    def restart(self, component):
        """ Restart a component
        """
        if not component in self.components.keys:
            raise ConsoleCommandError("Invalid component name '{component}'! No such component exists!")
        try:
            api = self.components[component].api
            api.Restart()
        except Exception as err_msg:
            raise DBusAPIError(f"Got error from DBus API of component {component}! Endpoint: Restart - Error Message: {err_msg}")
        return None

    def configure(self, component, setting, value):
        """ Configure a setting for a component
        """
        if not component in self.components.keys:
            raise ConsoleCommandError("Invalid component name '{component}'! No such component exists!")
        try:
            api = self.components[component].api
            api.Configure(setting, value)
        except Exception as err_msg:
            raise DBusAPIError(f"Got error from DBus API of component {component}! Endpoint: Configure - Error Message: {err_msg}")
        return None

    def show(self, component):
        """ Show the current configuration of a component
        """
        pass





class ApplicationConsole(object):
    """ Contains the primary application interface
    """

    def __init__(self, components, interfaces, config=None, logger=None):
        """ Initialize the object
        """
        self.config = config
        self.logger = logger
        self.components = components
        self.interfaces = interfaces
        self.commands = commands.ConsoleCommands(components, interfaces, config=self.config, logger=self.logger)
        self.command_history = []

    def _clear_screen(self):
        """ Clear the screen
        """
        subprocess.call(["clear"])
        return None

    def _show_banner(self, clear=False):
        """ Show the banner message
        """
        if clear:
            self._clear_screen()
        print(elements.BANNER)
        return None

    def console_interface(self):
        """ Main interface
        """
        def _parse_command(command_string):
            """ Parse the raw command string into the base command and its arguments
            and return both
            """
            parts = command_string.split(" ")
            command = parts[0]
            if len(parts) > 1:
                args = parts[1:]
            else:
                args = []
            return command, args

        # Loop until shutdown initiated
        self._show_banner(clear=True)
        while True:
            # Get the next command from the user and parse it, then add the command to the history
            command_string = input("> ")
            command, args = _parse_command(command_string)
            self.command_history.append(command)

            # Console commands
            if command in ("?", "help"):
                # Show the help message
                self.commands.help_()
            elif command in ("clear"):
                # Clear the screen
                self.commands.clear()
            elif command in ("banner"):
                # Show the banner
                if args:
                    if args[0] == "-c":
                        self.commands.banner(clear=True)
                    else:
                        raise ConsoleCommandError(f"Invalid argument for command: {command}")
                else:
                    self.commands.banner()
            elif command in ("shell"):
                # Start a Bash shell
                self.commands.shell()
            elif command in ("history"):
                # Show the command history
                self.commands.history()

            # Component commands
            elif command in ("start"):
                # Start a component
                self.commands.start(args[0])
            elif command in ("stop"):
                # Stop a component
                self.commands.stop(args[0])
            elif command in ("restart"):
                # Restart a component
                self.commands.restart(args[0])
            elif command in ("configure"):
                # Configure a component
                self.commands.configure(args[0], args[1], args[2])

            # Error handling - Invalid command
            else:
                raise ConsoleCommandError(f"Invalid command '{command}'! See '?' or 'help' for a list of commands")


















