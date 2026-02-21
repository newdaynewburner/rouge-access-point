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
from . import exceptions

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
        self.commands = commands.ConsoleCommands(self, components, interfaces, config=self.config, logger=self.logger)
        self.expected_input_source = "user"
        self.command_sequence = []

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
            # Determine input source, get the input, and parse it
            if expected_input_source == "user":
                # Get user input
                command_string = input("> ")
            elif expected_input_source == "scripted":
                # Get scripted inputs
                if not self.command_sequence:
                    raise exceptions.ConsoleCommandError(f"Cannot have scripted input without a CommandSequence!")
                try:
                    command_string = self.command_sequence.pop(0)
                except IndexError:
                    print("No commands left in sequence! Returning to console!")
                    self.expected_input_source = "user"
                    continue
            else:
                raise exceptions.ConsoleCommandError(f"An invalid value for expected_input_source was given! Acceptable values are: user, scripted")
            command, args = _parse_command(command_string)
            if command[0] == "#":
                continue
            self.commands.history(new_hist_cmd=command_string)

            ####################
            # CONSOLE COMMANDS #
            ####################
            if command in ("?", "help"):
                # Show the help message
                self.commands.help_()

            elif command in ("exit"):
                # Exit and shutdown
                shutdown_confirmed = self.commands.exit_()
                if shutdown_confirmed:
                    break

            elif command in ("clear"):
                # Clear the screen
                self.commands.clear()

            elif command in ("banner"):
                # Show the banner
                clear = False
                if len(args) > 0:
                    if len(args) == 1 and args[0] == "-c":
                        clear = True
                    else:
                        raise exceptions.ConsoleCommandError(f"Invalid usage for command: {command}")
                self.commands.banner(clear=clear)

            elif command in ("shell"):
                # Start a Bash shell
                self.commands.shell()

            elif command in ("history"):
                # Show the command history
                self.commands.history()

            ######################
            # COMPONENT COMMANDS #
            ######################
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

            ######################
            # SCRIPTING COMMANDS #
            ######################
            elif command in ("exec-sequence"):
                """ Execute a list of commands sequentially
                """
                self.command_sequence = self.commands.exec_sequence(args[0])
                self.expected_input_source = "scripted"

            ##################
            # ERROR HANDLING #
            ##################
            else:
                raise exceptions.ConsoleCommandError(f"Invalid command '{command}'! See '?' or 'help' for a list of commands")


















