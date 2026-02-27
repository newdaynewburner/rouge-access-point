"""
lib/datatypes.py

Custom datatype definitions
"""

import os
import sys
import configparser
from pydbus import SystemBus
from . import daemons
from . import exceptions

BIN_DIR = "/usr/bin"
DOWNLOAD_DIR = "/opt/rouge-access-point"
COMPONENT_INSTALL_DIR = "/usr/lib/rouge-access-point/components"
COMPONENT_CONFIG_DIR = "/etc/rouge-access-point/config/components"
COMPONENT_RSC_DIR = "/etc/rouge-access-point/rsc/components"
COMPONENT_DATA = {
    "ap-host": {
        "repo": "https://github.com/newdaynewburner/ap-host.git",
        "daemon": os.path.join(BIN_DIR, "aphostd"),
        "client": os.path.join(BIN_DIR, "aphostctl"),
        "config": os.path.join(COMPONENT_CONFIG_DIR, "ap-host", "ap-host.ini"),
        "dbus": {
            "name": "com.aphost.APHost",
            "path": "/com/aphost/APHost"
        }
    },
    "dhcp-server": {
        "repo": "https://github.com/newdaynewburner/dhcp-server.git",
        "daemon": os.path.join(BIN_DIR, "dhcpserverd"),
        "client": os.path.join(BIN_DIR, "dhcpserverctl"),
        "config": os.path.join(COMPONENT_CONFIG_DIR, "dhcp-server", "dhcp-server.ini"),
        "dbus": {
            "name": "com.dhcpserver.DHCPServer",
            "path": "/com/dhcpserver/DHCPServer"
        }
    },
    "dns-server": {
        "repo": "https://github.com/newdaynewburner/dns-server.git",
        "daemon": os.path.join(BIN_DIR, "dnsserverd"),
        "client": os.path.join(BIN_DIR, "dnsserverctl"),
        "config": os.path.join(COMPONENT_CONFIG_DIR, "dns-server", "dns-server.ini"),
        "dbus": {
            "name": "com.dnsserver.DNSServer",
            "path": "/com/dnsserver/DNSServer"
        }
    }
}

class ComponentInstaller(object):
    """ Installs components
    """

    def __init__(self, component_data=COMPONENT_DATA, component_install_dir=COMPONENT_INSTALL_DIR, component_config_dir=COMPONENT_CONFIG_DIR, download_dir=DOWNLOAD_DIR, config=None, logger=None):
        """ Initialize the object
        """
        self.config = config
        self.logger = logger
        self.component_data = component_data
        self.component_install_dir = component_install_dir
        self.component_config_dir = component_config_dir
        self.download_dir = download_dir

    def _is_valid(self, name):
        """ Check if a component name is valid
        """
        if name in self.component_data.keys():
            return True
        else:
            return False

    def check(self, name):
        """ Check if a component is installed
        """
        if not self._is_valid(name):
            raise exceptions.ComponentInstallerError(f"Invalid component: {name}")
        daemon_exists = True if os.path.isfile(self.component_data[name]["daemon"]) else False
        client_exists = True if os.path.isfile(self.component_data[name]["client"]) else False
        config_exists = True if os.path.isfile(self.component_data[name]["config"]) else False
        if daemon_exists and client_exists and config_exists:
            return True
        else:
            return False

    def install(self, name):
        """ Install a component
        """
        if not self._is_valid(name):
            raise exceptions.ComponentInstallerError(f"Invalid component: {name}")
        try:
            for command in [
                ["git", "clone", self.component_data[name]["repo"], os.path.join(self.download_dir, name)],
                ["chmod", "+x", os.path.join(self.download_dir, name, "install.sh")],
                [os.path.join(self.download_dir, name, "install.sh")]
            ]:
                subprocess.call(command)
            return True
        except:
            return False

    def uninstall(self, name):
        """ Uninstall a component
        """
        if not self._is_valid(name):
            raise exceptions.ComponentInstallerError(f"Invalid component: {name}")
        try:
            for command in [
                ["rm", "-rf", os.path.join(self.download_dir, name)],
                ["rm", "-rf", os.path.join(self.component_install_dir, name)],
                ["rm", self.component_data[name]["daemon"]],
                ["rm", self.component_data[name]["client"]],
                ["rm", "-rf", os.path.join(self.component_config_dir, name)]
            ]:
                subprocess.call(command)
            return True
        except:
            return False

    def get_object(self, name):
        """ Return a new Component object for the component
        """
        if not self._is_valid(name):
            raise exceptions.ComponentInstallerError(f"Invalid component: {name}")
        component_object = Component(
            name,
            f"{name} component for rouge-access-point",
            self.component_data[name]
        )
        return component_object

class Component(object):
    """ Represents a component
    """

    def __init__(self, name, description, data, config=None, logger=None):
        """ Initialize the object
        """
        self.config = config
        self.logger = logger
        self.name = name
        self.description = description
        self.data = data
        self.daemon = daemons.Daemon(f"{self.data['daemon']} {self.data['config']}", name=self.name, description=self.description)

    def get_daemon(self):
        """ Return the daemon
        """
        return self.daemon

    def get_api(self):
        """ Return a connection to the dbus api
        """
        bus = SystemBus()
        api = bus.get(self.data["dbus"]["name"], self.data["dbus"]["path"])
        return api
