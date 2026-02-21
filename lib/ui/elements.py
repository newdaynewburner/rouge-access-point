"""
lib/ui/elements.py

Contains UI elements and helpers
"""

import os
import sys

BANNER = """
+----------------------------------------------------------------------------+
| Rouge Access Point (https://github.com/newdaynewburner/rouge-access-point) |
| Version 0.1                                                                |
|                                                                            |
+----------------------------------------------------------------------------+
| Commands can be entered below. Use '?' or 'help' for a list of commands.   |
+----------------------------------------------------------------------------+
"""
HELP_MESSAGE = """
Below is a list of commands sorted by category.

Console:
    help - Display the help message
    clear - Clears the screen
    banner [-c] - Shows the banner, optionally clearing the screen
    shell - Opens a new Bash shell. Returns to the console once shell is exited
    history - Shows the command history

Component:
    start COMPONENT - Start the component's service with its current configuration.
    stop COMPONENT - Stop the component's service
    restart COMPONENT - Restart a component
    configure COMPONENT SETTING VALUE - Set a new value for the specified configuration setting
"""
