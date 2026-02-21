"""
lib/ui/exceptions.py

Custom exception definitions
"""

import warnings

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
