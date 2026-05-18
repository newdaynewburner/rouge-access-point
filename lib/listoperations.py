"""
listoperations.py

Preforms operations on lists like merging, etc.
"""

import os
import sys
import configparser

class DnschefOverridesFile(object):
    """ Preforms operations on the file used by dnschef for overrides
    """
    def __init__(self, overrides_file, config=None, logger=None):
        self.config = config
        self.logger = logger
        self.overrides_file = configparser.ConfigParser()
        self.overrides_file.read(overrides_file)
        self.file_path = overrides_file
        self.merges = [] # List of ("merged_file", [appended_entries]) tuples

    def _write_file(self):
        """ Write the ConfigParser object values to the file
        """
        self.logger.debug(f"Writing current DNS override entries to overrides file at: {self.file_path}")
        with open(self.file_path, "w") as f:
            self.overrides_file.write(f)
        return None

    def append_doh_blocklist_entries(self, doh_blocklist):
        """ Appends entries from the DNS-over-HTTPS hostname blocklist to the overrides file and
        sinkholes them
        """
        appended_entries = []
        with open(doh_blocklist, "r") as f:
            for l in f.readlines():
                self.logger.debug(f"Sinkholing DoH hostname {l.strip()} with A and AAAA records in overrides file")
                self.overrides_file["A"][l.strip()] = "0.0.0.0"
                appended_entries.append((l.strip(), "0.0.0.0"))
                self.overrides_file["AAAA"][l.strip()] = "::1"
                appended_entries.append((l.strip(), "::1"))
        self.merges.append("doh_blocklist", appended_entries)
        return None


