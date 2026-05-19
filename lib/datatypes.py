"""
datatypes.py

Class definitions for custom datatypes, representative objects, etc.
"""

import os
import sys
import configparser

class HostapdConfigFile(object):
    """ The configuration file for hostapd
    """
    def __init__(self, config=None, logger=None):
        raise NotImplementedError

class DnsmasqConfigFile(object):
    """ The configuration file for dnsmasq
    """
    def __init__(self, config=None, logger=None):
        raise NotImplementedError

class DNSOverridesFile(object):
    """ The file used by dnschef for preforming DNS overrides
    """
    def __init__(self, overrides_file, config=None, logger=None):
        self.config = config
        self.logger = logger
        self.overrides_file = configparser.ConfigParser()
        self.overrides_file.read(overrides_file)
        self._original = self.overrides_file
        self.file_path = overrides_file
        self.merges = []
        self.synced = True

    def import_(self, fname):
        """ Import records from another overrides file
        """
        raise NotImplementedError

    def export(self, fname=None):
        """ Write the ConfigParser object values to the file
        """
        file_path = self.file_path if not fname else fname
        self.logger.debug(f"Writing current DNS override entries to overrides file at: {file_path}")
        with open(file_path, "w") as f:
            self.overrides_file.write(f)
        if not fname or fname == self.file_path:
            self.synced = True
        return None

    def restore_original(self):
        """ Restore the original records from an unaltered copy of the override file's ConfigParser object
        """
        self.overrides_file = self._original
        self.synced = False
        return None

    def append_doh_blocklist(self, doh_blocklist):
        """ Appends entries from the DNS-over-HTTPS hostname blocklist to the overrides file and
        sinkholes them
        """
        appended_entries = []
        with open(doh_blocklist, "r") as f:
            for l in f.readlines():
                # Create an entry in the file's A and AAAA records for the current DoH hostname pointing it to the sinkhole
                # address, then append it to the list of appended entries
                self.logger.debug(f"Sinkholing DoH hostname {l.strip()} with A and AAAA records in DNS override records")

                # A record (IPv4 sinkholing)
                self.overrides_file["A"][l.strip()] = "0.0.0.0"
                appended_entries.append(("A", l.strip(), "0.0.0.0"))

                # AAAA record (IPv6 sinkholing)
                self.overrides_file["AAAA"][l.strip()] = "::1"
                appended_entries.append(("AAAA", l.strip(), "::1"))

        # Append the type of file and it's filepath, as well as the list of entries appended to the file to the object's list of
        # files and the cooresponding data from them that have been merged into the DNS overrides file represented by the object instance
        if len(appended_entries) > 0:
            self.synced = False
        self.merges.append(("doh_blocklist", doh_blocklist, appended_entries))
        return None

    def add_record(self, rtype, rname, rdata):
        """ Append a new record
        """
        if rtype.upper() not in ("A", "AAAA"):
            msg = f"Cannot add record for {rname} with data '{rdata}'! Invalid or unsupported record type: {rtype}"
            self.logger.error(msg)
            raise Exception(msg)

        # Add the record data for the hostname to the appropriate category in the overrides file
        self.logger.debug(f"Adding {rtype} for {rname} with data '{rdata}' to the DNS override records")
        self.overrides_file[rtype.upper()][rname] = rdata
        self.merges.append(("add_record", "internal method", [(rtype, rname, rdata)]))
        return None

    def modify_record(self, rtype, rname, rdata):
        """ Modify an existing record
        """
        raise NotImplementedError

    def delete_record(self, rtype, rname, rdata):
        """ Delete a record
        """
        raise NotImplementedError
