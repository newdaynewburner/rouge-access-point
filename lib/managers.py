"""
lib/managers.py

Contains classes for management objects that control rouge AP function
"""

import os
import sys
import subprocess
import logging

class APComponentManager(object):
    """ Controls AP component services
    """
    def __init__(self, hostapd_config_file, dnsmasq_config_file, dns_overrides_file, config=None, logger=None):
        if not hostapd_config_file or not dnsmasq_config_file:
            raise Exception(f"Config file paths must be given for both hostapd and dnsmasq")

        self.config = config
        self.logger = logger
        self.processes = {}
        self.components = {
            "hostapd": {
                "executable": "/usr/sbin/hostapd",
                "config_file": hostapd_config_file,
                "log_file": self.config["LOGGING"]["hostapd_log_file"],
                "process": None,
                "status": "not running"
            },
            "dnsmasq": {
                "executable": "/usr/sbin/dnsmasq",
                "config_file": dnsmasq_config_file,
                "log_file": self.config["LOGGING"]["dnsmasq_log_file"],
                "process": None,
                "status": "not running"
            },
            "dnschef": {
                "executable": "/usr/bin/dnschef",
                "config_file": None,
                "log_file": self.config["LOGGING"]["dnschef_log_file"],
                "dns_overrides_file": dns_overrides_file.file_path,
                "process": None,
                "status": "not running"
            }
        }

    def start_component(self, component: str) -> bool:
        """ Starts the specified component
        """
        if self.components[component]["status"] == "running":
            self.logger.warning(f"Cannot start. Component {component} is already running")
            return False

        if component == "hostapd":
            cmd = [
                self.components["hostapd"]["executable"],
                "-f",
                self.components["hostapd"]["log_file"],
                self.components["hostapd"]["config_file"]
            ]
        elif component == "dnsmasq":
            cmd = [
                self.components["dnsmasq"]["executable"],
                "--log-facility",
                self.components["dnsmasq"]["log_file"],
                "-C",
                self.components["dnsmasq"]["config_file"],
                "--keep-in-foreground"
            ]
        elif component == "dnschef":
            cmd = [
                self.components["dnschef"]["executable"],
                "--interface",
                self.config["AP"]["gateway"],
                "--logfile",
                self.components["dnschef"]["log_file"],
                "--file",
                self.components["dnschef"]["dns_overrides_file"]
            ]
        else:
            self.logger.error(f"An invalid component name was passed to start_component() method of APComponents object! Component name passed: {component}")
            raise Exception(f"An invalid component name was passed to start_component() method of APComponents object! Component name passed: {component}")

        try:
            self.components[component]["process"] = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.components[component]["status"] = "running"
        except subprocess.SubprocessError as err_msg:
            self.logger.error(f"Encountered an error while trying to start the {component} component! Error message: {err_msg}")
            raise err_msg
        return True

    def stop_component(self, component: str) -> bool:
        """ Stops the specified component
        """
        if self.components[component]["status"] == "not running":
            self.logger.warning(f"Cannot stop. Component {component} is not running")
            return False
        self.components[component]["process"].terminate()
        try:
            self.components[component]["process"].wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Could not end {component} component process with SIGTERM, sending SIGKILL")
            self.components[component]["process"].kill()
            self.components[component]["status"] = "not running"
        return True

    def restart_component(self, component):
        """ Restarts the specified component
        """
        if self.components[component]["status"] == "not running":
            self.logger.warning(f"Cannot restart. Component {component} is not running")
            return False

        self.stop_component(component)
        self.start_component(component)
        return True
