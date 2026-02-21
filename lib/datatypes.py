"""
lib/datatypes.py

Custom datatype definitions
"""

import os
import sys
import configparser
from pydbus import SystemBus
from . import configuration
from . import daemons
from . import exceptions

COMPONENT_SCRIPT_PATHS = {
    "ap-host": {
        "daemon": "/usr/bin/aphostd",
        "client": "/usr/bin/aphostctl",
        "dbus": {
            "name": "com.aphost.APHost",
            "path": "/com/aphost/APHost"
        }
    },
    "dhcp-server": {
        "daemon": "/usr/bin/dhcpserverd",
        "client": "/usr/bin/dhcpserverctl",
        "dbus": {
            "name": "com.dhcpserver.DHCPServer",
            "path": "/com/dhcpserver/DHCPServer"
        }
    },
    "dns-server": {
        "daemon": "/usr/bin/dnsserverd",
        "client": "/usr/bin/dnsserverctl",
        "dbus": {
            "name": "com.dnsserver.DNServer",
            "path": "/com/dnsserver/DNSServer"
        }
    }
}

class Component(object):
    """ Handles installation and loading of components and daemon/client control
    """

    def __init__(self, component_name, comp_paths=COMPONENT_SCRIPT_PATHS, config=None, logger=None):
        """ Initialize the object
        """
        self.config = config
        self.logger = logger
        self.component_name = component_name
        self.daemon = None
        self.bus = None
        self.api = None

        # Make sure the component is installed and install it if not
        if not os.path.isdir(os.path.join(self.config["COMPONENT"]["component_install_dir"], self.component_name)):
            for comp in ("ap-host", "dhcp-server", "dns-server"):
                if comp == self.component_name:
                    component_repository = f"https://github.com/newdaynewburner/{comp}.git"
                    clone_dir = os.path.join(self.config["COMPONENT"]["component_install_dir"], comp)

            self.logger.warning(f"[Component Loader] The {comp} component is not installed. It will be installed from {component_repository}")
            for command in [
                ["git", "clone", component_repository, clone_dir],
                ["chmod", "+x", os.path.join(clone_dir, "install.sh")],
                [os.path.join(clone_dir, "install.sh")]
            ]:
                subprocess.call(command)
            self.logger.warning(f"[Component Loader] The {comp} component was installed successfully")

        # Fetch the daemon and client scripts
        for comp in ("ap-host", "dhcp-server", "dns-server"):
            if comp == self.component_name:
                self.daemon_script = comp_paths[comp]["daemon"]
                self.client_script = comp_paths[comp]["client"]
                self.bus_info = comp_paths[comp]["dbus"]

        # Generate the component config file and create the daemon
        if self.component_name == "ap-host":
            config_file = configuration.gen_ap_host_config(self.config)
        elif self.component_name == "dhcp-server":
            config_file = configuration.gen_dhcp_server_config(self.config)
        elif self.component_name == "dns_server":
            config_file = configuration.gen_dns_server_config(self.config)
        self.daemon = daemons.Daemon(f"{daemon_script} {config_file}", name=comp, description="{comp} component for rouge access point")


    def start_daemon(self):
        """ Start the daemon
        """
        self.daemon.start()
        return None

    def stop_daemon(self):
        """ Stop the daemon
        """
        self.daemon.stop()
        return None

    def get_status(self):
        """ Get the daemons status
        """
        return self.daemon.status

    def connect_dbus(self):
        """ Connect to the daemon's DBus API
        """
        self.bus = SystemBus
        self.api = self.bus.get(self.bus_info["name"], self.bus_info["path"])
        return None


