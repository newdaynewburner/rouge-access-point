"""
lib/daemons.py

Facilitates the management of daemon programs through the Daemon object
"""

import os
import sys
import time
import subprocess

class Daemon(object):
    """ Represents an instance of a program running as a system daemon
    """

    def __init__(self, command, name=None, description=None):
        """ Initialize the object
        """
        self.command = command
        self.name = name
        self.description = description
        self.is_running = False
        self.start_time = None
        self.stop_time = None
        self.daemon_process = None
        self.daemon_pid = None
        self.daemon_stdout = None
        self.daemon_stderr = None
        self.exit_code = None
        self.daemon_config_file = None
        self.daemon_log_file = None
        self.process_terminate_timeout=5

    def __process_start__(self):
        """ Start the daemon in a seperate process
        """
        print(self.command.split(" "))
        self.daemon_process = subprocess.Popen(
            self.command.split(" "),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        self.start_time = time.time()
        self.daemon_pid = self.daemon_process.pid
        self.stdout = self.daemon_process.stdout
        self.stderr = self.daemon_process.stderr
        self.is_running = True
        return None

    def __process_stop__(self):
        """ Stop the daemon process
        """
        self.daemon_process.terminate()
        try:
            self.daemon_process.wait(timeout=self.process_terminate_timeout)
        except subprocess.TimeoutExpired:
            self.daemon_process.kill()
            self.daemon_process.wait()
        self.exit_code = self.daemon_process.returncode
        self.stop_time = time.time()
        self.is_running = False
        return None

    def configure(self, command=None, name=None, description=None, config_file=None, log_file=None, process_terminate_timeout=None):
        """ Configure parameters related to managing the daemon program
        """
        if command:
            self.command = command
        if name:
            self.name = name
        if description:
            self.description = description
        if config_file:
            self.config_file = config_file
        if log_file:
            self.log_file = log_file
        if process_terminate_timeout:
            self.process_terminate_timeout = process_terminate_timeout
        return None

    def start(self):
        """ Start the daemon
        """
        self.__process_start__()
        return self.is_running

    def stop(self):
        """ Stop the daemon
        """
        self.__process_stop__()
        return self.is_running

    def status(self):
        """ Return the status of the daemon
        """
        status = "running" if self.daemon_process.poll() is None else "not running"
        exit_code = None if status == "running" else self.daemon_process.returncode
        data = {
            "status": status,
            "exit_code": exit_code
        }
        return data
