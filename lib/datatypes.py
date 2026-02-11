"""
lib/datatypes.py

Custom datatype definitions
"""

import os
import sys
import configparser
from . import configuration
from . import daemons
from . import exceptions

class Component(object):
    """ Represents a component program
    """

    def __init__(self, name, config):
        """ Initialize the object
        """
        self.name = name
        self.config = config
        self.install_dir = os.path.join(self.config["COMPONENT"]["component_install_dir"], self.name)
        self.log_dir = self.config["COMPONENT"]["log_dir"]
        if self.name == "ap-host":
            self.desc = "Controls broadcasting and client device authentication for the AP"
            self.script = os.path.join(self.install_dir, "ap-host.py")
            self.component_config_file = configuration.gen_ap_host_config(self.config)
            self.log_file = os.path.join(self.log_dir, "ap-host.log")
        elif self.name == "dhcp-server":
            self.desc = "Provides dynamic IP address assignment to client devices"
            self.script = os.path.join(self.install_dir, "dhcp-server.py")
            self.component_config_file = configuration.gen_dhcp_server_config(self.config)
            self.log_file = os.path.join(self.log_dir, "dhcp-server.log")
        elif self.name == "dns-server":
            self.desc = "Authoritative name server for the network and default DNS server for client devices"
            self.script = os.path.join(self.install_dir, "dns-server.py")
            self.component_config_file = configuration.gen_dns_server_config(self.config)
            self.log_file = os.path.join(self.log_dir, "dns-server.log")
        else:
            raise exceptions.InvalidComponentSpecifiedError(f"'{self.name}' is not a valid component!")
        self.component_config = configparser.ConfigParser()
        self.component_config.read(self.component_config_file)
        self.daemon = daemons.Daemon(
            f"{self.config['COMPONENT']['python']} {self.script} {self.component_config_file}",
            name=self.name,
            description=self.desc
        )

    def start(self):
        """ Start the component
        """
        self.daemon.start()
        return None

    def showouts(self):
        """ Show STDOUT and STDERR
        """
        print(self.daemon.stdout.readline())
        print(self.daemon.stderr.readline())
        return None

    def stop(self):
        """ Stop the component
        """
        self.daemon.stop()
        return None
