"""
lib/exceptions.py

Custom exception definitions
"""

import warnings

def InvalidComponentSpecifiedError(Exception):
    """ Raised when a nonexistent component name is passed
    """
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
