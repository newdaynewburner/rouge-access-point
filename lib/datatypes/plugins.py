"""
lib/datatypes/plugins.py

Plugin datatypes
"""

import os
import sys
from . import exceptions

BIN_DIR = "/usr/bin"
DOWNLOAD_DIR = "/opt/rouge-access-point"
PLUGIN_INSTALL_DIR = "/usr/lib/rouge-access-point/plugins"
PLUGIN_CONFIG_DIR = "/etc/rouge-access-point/config/plugins"
PLUGIN_RSC_DIR = "/etc/rouge-access-point/rsc/plugins"
PLUGIN_DATA = {}

class PluginInstaller(object):
    """ Installs plugins
    """

    def __init__(self, plugin_data=PLUGIN_DATA, plugin_install_dir=PLUGIN_INSTALL_DIR, plugin_config_dir=PLUGIN_CONFIG_DIR, download_dir=DOWNLOAD_DIR, config=None, logger=None):
        """ Initialize the object
        """
        self.config = config
        self.logger = logger
        self.plugin_data = plugin_data
        self.plugin_install_dir = plugin_install_dir
        self.plugin_config_dir = plugin_config_dir
        self.download_dir = download_dir

    def _is_valid(self, name):
        """ Check if a plugin name is valid
        """
        if name in self.plugin_data.keys():
            return True
        else:
            return False

    def check(self, name):
        """ Check if a plugin is installed
        """
        pass

    def install(self, name):
        """ Install a plugin
        """
        pass

    def uninstall(self, name):
        """ Uninstall a plugin
        """
        pass

    def get_object(self, name):
        """ Return a new Plugin object
        """
        pass
