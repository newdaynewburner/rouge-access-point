"""
lib/system.py

Handles system configuration tasks
"""

import os
import sys
import subprocess
from . import datatypes
from . import exceptions

class SystemInitializer(object):
    """ Preforms the initialization sequence
    """

    def __init__(self, debug, config, logger):
        """ Initialize the object
        """
        self.debug = debug
        self.config = config
        self.logger = logger
        self.components = {}

    def _load_components(self):
        """ Load component programs
        """

        # Create Component objects for each component and return them
        for component in ("ap-host", "dhcp-server", "dns-server"):
            comp = datatypes.Component(component, self.config)
            self.components[component] = comp
        return self.components
