"""
lib/exceptions.py

Custom exception definitions
"""

import warnings

def ComponentInstallerError(Exception):
    """ Raised when an issue with the ComponentInstaller occurs
    """
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

def PluginInstallerError(Exception):
    """ Raised when an issue with the PluginInstaller occurs
    """
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

def InvalidComponentSpecifiedError(Exception):
    """ Raised when a nonexistent component name is passed
    """
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
