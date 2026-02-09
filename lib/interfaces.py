"""
linuxnetworkinterfaces.py

Module for working with network interfaces in Linux
"""

import os
import sys
import time
import subprocess
import threading
from warnings import warn
from collections import defaultdict
from scapy.all import sniff, PcapWriter, Dot11, Dot11Elt, LLC, SNAP
from scapy.config import conf as scapy_conf

class SystemCallError(Exception):
    """ Raised when a system call returns a non-zero exit code
    """
    def __init__(self, message):
        super().__init__(message)

class AttributeSetSilentFailError(Exception):
    """ Raised when an attempt to set an attribute of the interface is made without returning an error code
    but where the attribute remains unchanged in actuality
    """
    def __init__(self, message):
        super().__init__(message)

class NetworkManager(object):
    """ Backend for NetworkManager network manager
    """

    def __init__(self, iface):
        """ Initialize the object
        """
        self.iface = iface

    def include(self):
        """ Allow NetworkManager to manage the interface
        """
        subprocess.check_output(f"nmcli device set {self.iface.iface} managed yes".split(" ")).decode()
        return None

    def exclude(self):
        """ Disallow NetworkManager from managing the interface
        """
        subprocess.check_output(f"nmcli device set {self.iface.iface} managed no".split(" ")).decode()
        return None

class Interface(object):
	""" Generic parent class object. Represents and controls a
	specific interface on the machine

	Methods:
		__init__() - Initialize the object
	"""

	def __init__(self, iface, debug=False, error_level=0):
		""" Initialize the object
		"""
		# Interface
		self.iface = iface
		self.name = self.__name__()
		self.alias = self.__alias__()
		self.hwaddr = self.__hwaddr__()
		self.permaddr = self.__permaddr__()
		self.ipaddr = self.__ipaddrs__()

		# State
		self.state = self.__state__()

		# Device flags
		self.device_flags = self.__flags__()
		self.noarp = self.__noarp__()
		self.multicast = self.__multicast__()
		self.allmulti = self.__allmulti__()
		self.promisc = self.__promisc__()

		# Messages & error handling
		self.debug = debug
		self.error_level = error_level

	def __name__(self, set_name=None):
		""" Interface name
		"""
		if set_name is not None:
			try:
				if self.debug:
					print(f"DEBUG - Making system call - ip link set {self.iface} name {set_name}")
				subprocess.check_call(f"ip link set {self.iface} name {set_name}".split(" "))
			except subprocess.CalledProcessError as err_msg:
				raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")
			self.iface = set_name
		return self.iface

	def __alias__(self, set_alias=None):
		""" Interface alias name
		"""
		if set_alias is not None:
			try:
				if self.debug:
					print(f"DEBUG - Making system call - ip link set {self.iface} alias {set_alias}")
				subprocess.check_call(f"ip link set {self.iface} alias {set_alias}".split(" "))
			except subprocess.CalledProcessError as err_msg:
				raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")

		sstr = subprocess.check_output(f"ip link show {self.iface}".split(" ")).decode(); slst = sstr.split(" ")
		alias = None
		index = 0
		for part in slst:
			if part == "alias":
				alias = slst[index + 1]
			index = index + 1
		return alias

	def __hwaddr__(self, set_hwaddr=None):
		""" MAC address used by the interface
		"""
		if set_hwaddr is not None:
			try:
				if self.debug:
					print(f"DEBUG - Making system call - ip link set {self.iface} address {set_hwaddr}")
				subprocess.check_call(f"ip link set {self.iface} address {set_hwaddr}".split(" "))
			except subprocess.CalledProcessError as err_msg:
				raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")

		sstr = subprocess.check_output(f"ip link show {self.iface}".split(" ")).decode(); slst = sstr.split(" ")
		hwaddr = None
		index = 0
		for part in slst:
			if part == "link/ether":
				hwaddr = slst[index + 1]
			index = index + 1
		return hwaddr


	def __permaddr__(self):
		""" Permanent MAC address of the device
		"""
		sstr = subprocess.check_output(f"ip link show {self.iface}".split(" ")).decode(); slst = sstr.split(" ")
		permaddr = None
		index = 0
		for part in slst:
			if part == "permaddr":
				permaddr = slst[index + 1]
			index = index + 1
		return permaddr

	def __ipaddrs__(self, set_ipaddr=None):
		""" IP addresses assigned to the device
		"""
		if set_ipaddr is not None:
			try:
				if self.debug:
					print(f"DEBUG - Making system call - ip addr add {set_ipaddr} dev {self.iface}")
				subprocess.check_call(f"ip addr add {set_ipaddr} dev {self.iface}".split(" "))
			except subprocess.CalledProcessError as err_msg:
				raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")
		sstr = subprocess.check_output(f"ip addr show {self.iface}".split(" ")).decode(); slst = sstr.split(" ")
		ipaddrs = []
		index = 0
		for part in slst:
			if part in  ("inet", "inet6"):
				if part == "inet":
					addrtype = "4"
				elif part == "inet6":
					addrtype = "6"
				raw = slst[index + 1]
				ipaddr, netmask = raw.split("/")
				ipaddrs.append((ipaddr, netmask, addrtype))
			index = index + 1
		return ipaddrs

	def __flush_ipaddrs__(self):
		""" Flush IP addresses
		"""
		try:
			if self.debug:
				print(f"DEBUG - Making system call - ip addr flush dev {self.iface}")
			subprocess.check_call(f"ip addr flush dev {self.iface}".split(" "))
		except subprocess.CalledProcessError as err_msg:
			raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")
		return self.__ipaddrs__()

	def __state__(self, set_state=None):
		""" Interface state
		"""
		if set_state is not None:
			try:
				if self.debug:
					print(f"DEBUG - Making system call - ip link set {self.iface} {set_state}")
				subprocess.check_call(f"ip link set {self.iface} {set_state}".split(" "))
			except subprocess.CalledProcessError as err_msg:
				raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")
		sstr = subprocess.check_output(f"ip link show {self.iface}".split(" ")).decode(); slst = sstr.split(" ")
		state = None
		index = 0
		for part in slst:
			if part == "state":
				state = slst[index + 1].lower()
			index = index + 1
		return state

	def __flags__(self):
		""" Return a list of device flags
		"""
		sstr = subprocess.check_output(f"ip link show {self.iface}".split(" ")).decode(); slst = sstr.split(" ")
		fstr = slst[2].strip("<>"); flst = fstr.split(",")
		return flst

	def __noarp__(self, set_flag=None):
		""" NOARP device flag
		"""
		if set_flag is not None:
			sopt = "on" if set_flag == True else "off"
			try:
				if self.debug:
					print(f"DEBUG - Making system call - ip link set {self.iface} arp {sopt}")
				subprocess.check_call(f"ip link set {self.iface} arp {sopt}".split(" "))
			except subprocess.CalledProcessError as err_msg:
				raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")
		has_flag = False
		if "NOARP" in self.__flags__():
			has_flag = True
		return has_flag

	def __multicast__(self, set_flag=None):
		""" MULTICAST device flag
		"""
		if set_flag is not None:
			sopt = "on" if set_flag == True else "off"
			try:
				if self.debug:
					print(f"DEBUG - Making system call - ip link set {self.iface} multicast {sopt}")
				subprocess.check_call(f"ip link set {self.iface} multicast {sopt}".split(" "))
			except subprocess.CalledProcessError as err_msg:
				raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")
		has_flag = False
		if "MULTICAST" in self.__flags__():
			has_flag = True
		return has_flag

	def __allmulti__(self, set_flag=None):
		""" ALLMULTI device flag
		"""
		if set_flag is not None:
			sopt = "on" if set_flag == True else "off"
			try:
				if self.debug:
					print(f"DEBUG - Making system call - ip link set {self.iface} allmulticast {sopt}")
				subprocess.check_call(f"ip link set {self.iface} allmulticast {sopt}".split(" "))
			except subprocess.CalledProcessError as err_msg:
				raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")
		has_flag = False
		if "ALLMULTICAST" in self.__flags__():
			has_flag = True
		return has_flag

	def __promisc__(self, set_flag=None):
		""" PROMISC device flag"""
		if set_flag is not None:
			sopt = "on" if set_flag == True else "off"
			try:
				if self.debug:
					print(f"DEBUG - Making system call - ip link set {self.iface} promisc {sopt}")
				subprocess.check_call(f"ip link set {self.iface} promisc {sopt}".split(" "))
			except subprocess.CalledProcessError as err_msg:
				raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")
		has_flag = False
		if "PROMISC" in self.__flags__():
			has_flag = True
		return has_flag

	def set_device_flag(self, flag, setting):
		""" Set a device flag
		"""
		# Determine the proper flag setting value & handle bad setting argument values
		sval = "on" if setting in ("on", True) else "off" if setting in ("off", False) else None
		if not setting:
			self.__error_handler__(f"Invalid device flag setting '{setting}'!")

		# Set the flag through the appropriate method or call the error handler method if a non-existent flag was specified
		if flag.lower() == "noarp":
			flag_set = self.__noarp__(set_flag=setting)
		elif flag.lower() == "multicast":
			flag_set = self.__multicast__(set_flag=setting)
		elif flag.lower() == "allmulti":
			flag_set = self.__allmulti___(set_flag=setting)
		elif flag.lower() == "promisc":
			flag_set = self.__promisc__(set_flag=setting)
		else:
			raise Exception(f"Unsupported flag '{flag}'!")
			return False

		# Make sure the flag was set and return False if it failed
		if not flag_set:
			raise AttributeSetSilentFailError(f"Tried to set the value of the '{flag}' device flag but its value remains unchanged!")
			return False

		# Return True upon success
		return True

	def start_management(self):
		""" Allow the interface to be controlled by its manager
		"""
		self.manager_backend.include()
		return None

	def stop_management(self):
		""" Do not allow the interface to be controlled by its manager
		"""
		self.manager_backend.exclude()
		return None

	def set_name(self, name):
		""" Set the interface's name
		"""
		cur = self.__name__()
		self.name = self.__name__(set_name=name)
		if self.name == cur:
			if self.error_level == -1:
				warn(f"Tried to change the name of the interface '{self.iface}' to '{name}' but the name was not changed!")
			elif self.error_level == 0:
				pass
			elif self.error_level == 1:
				raise AttributeSetSilentFailError(f"Tried to change the name of the interface '{self.iface}' to '{name}' but the name was not changed!")
		return self.name

	def set_alias(self, alias):
		""" Set the interfaces alias name
		"""
		self.alias = self.__alias__(set_alias=alias)
		return self.alias

	def set_hwaddr(self, hwaddr):
		""" Set a cloned MAC address
		"""
		cur = self.__hwaddr__()
		self.hwaddr = self.__hwaddr__(set_hwaddr=hwaddr)
		if self.hwaddr == cur:
			if self.error_level == -1:
				warn(f"Tried to set the hardware address of the interface but it was not changed!")
			elif self.error_level == 0:
				pass
			elif self.error_level == 1:
				raise AttributeSetSilentFailError(f"Tried to set the hardware address of the interface but it was not changed!")
		return self.hwaddr

	def flush_ipaddrs(self):
		""" Flush IP addresses
		"""
		self.ipaddrs = self.__flush_ipaddrs__()
		return self.ipaddrs

	def add_ipaddr(self, ipaddr, netmask):
		""" Set an IP address
		"""
		cur = self.__ipaddrs__()
		self.ipaddrs = self.__ipaddrs__(set_ipaddr=f"{ipaddr}/{netmask}")
		if self.ipaddrs == cur:
			if self.error_level == -1:
				warn(f"Tried to add an IP address to the interface, but it failed!")
			elif self.error_level == 0:
				pass
			elif self.error_level == 1:
				raise AttributeSetSilentFailError(f"Tried to add an IP address to the interface, but it failed!")
		return self.ipaddrs

	def set_state(self, state):
		""" Set the interface's state
		"""
		cur = self.__state__()
		self.state = self.__state__(set_state=state)
		if self.state == cur:
			if self.error_level == -1:
				warn(f"Tried to change the state of the interface but it was not changed!")
			elif self.error_level == 0:
				pass
			elif self.error_level == 1:
				raise AttributeSetSilentFailError(f"Tried to change the state of the interface but it was not changed!")
		return self.state

class WiredInterface(Interface):
	""" Represents a wired network interface

	Methods:
		__init__() - Initialize the object
	"""

	def __init__(self, iface, manager=None, debug=False):
		""" Initialize the object
		"""
		super().__init__(iface, debug=debug)
		self.iface_type = "wired"
		self.manager = manager
		self.manager_backend = None
		if self.manager == "networkmanager":
			self.manager_backend = NetworkManager(self)

class WirelessInterface(Interface):
	""" Represents a wireless network interface

	Methods:
		__init__() - Initialize the object
	"""

	def __init__(self, iface, manager=None, debug=False, error_level=0):
		""" Initialize the object
		"""
		super().__init__(iface, debug=debug, error_level=0)
		self.iface_type = "wireless"
		self.manager = manager
		self.manager_backend = None
		if self.manager == "networkmanager":
			self.manager_backend = NetworkManager(self)
		self.default_mode = "managed"
		self.mode = self.__mode__()
		self.channel = self.__channel__()
		self.supported_2g_channels, self.supported_5g_channels = self.__supported_channels__()

	def __mode__(self, set_mode=None):
		""" Get or set the mode
		"""
		if set_mode is not None:
			try:
				if self.debug:
					print(f"DEBUG - Making system call - iw dev {self.iface} set type {set_mode}")
				subprocess.check_call(f"iw dev {self.iface} set type {set_mode}".split(" "))
			except subprocess.CalledProcessError as err_msg:
				raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")

		sstr = subprocess.check_output(f"iw dev {self.iface} info".split(" ")).decode(); slst = sstr.split(" ")
		mode = None
		index = 0
		for part in slst:
			if "type" in part:
				mstr = slst[index + 1]
				mode, _ = mstr.split("\n\t")
				break
			index = index + 1
		return mode

	def __channel__(self, set_channel=None):
		""" Get or set the channel
		"""
		if set_channel is not None:
			try:
				if self.debug:
					print(f"DEBUG - Making system call - iw dev {self.iface} set channel {str(set_channel)}")
				subprocess.check_call(f"iw dev {self.iface} set channel {str(set_channel)}".split(" "))
			except subprocess.CalledProcessError as err_msg:
				raise SystemCallError(f"A system-level command returned a non-zero exit code! Full error message: {err_msg}")

		sstr = subprocess.check_output(f"iw dev {self.iface} info".split(" ")).decode(); slst = sstr.split(" ")
		channel = None
		index = 0
		for part in slst:
			if "channel" in part:
				channel = int(slst[index + 1])
				break
			index = index + 1
		return channel

	def __supported_channels__(self):
		""" Get a list of the 2.4G and 5G channels supported by the interface
		"""
		sstr = subprocess.check_output(f"iw list".split(" ")).decode(); slst = sstr.split("\n")
		raw = []
		supported_2g_channels = []
		supported_5g_channels = []
		for line in slst:
			l = line.strip().split()
			if len(l) > 0:
				if l[0] == "*" and "MHz" in l:
					for p in l:
						if p[0] == "[":
							raw.append(l)
		i = 0
		for item in raw:
			b = int(item[1]); sb = str(b)
			c = int(item[3].strip("[]"))
			if sb[0] == "2":
				supported_2g_channels.append(c)
			elif sb[0] == "5":
				supported_5g_channels.append(c)
			else:
				raise Exception(f"WTF is this??? {item}")
		return (supported_2g_channels, supported_5g_channels)

	def set_mode(self, mode):
		""" Set the interface's mode
		"""
		cur = self.__mode__()
		self.mode = self.__mode__(set_mode=mode)
		if self.mode == cur:
			if self.error_level == -1:
				warn(f"Tried to change the interface from {cur} mode to {mode} mode but the mode was not changed!")
			elif self.error_level == 0:
				pass
			elif self.error_level == 1:
				raise AttributeSetSilentFailError(f"Tried to change the interface from {cur} mode to {mode} mode but the mode was not changed!")
		return self.mode

	def set_channel(self, channel):
		""" Set the interface's channel
		"""
		cur = self.__channel__()
		self.channel = self.__channel__(set_channel=channel)
		if self.channel == cur:
			if self.error_level == -1:
				warn(f"Tried to change the interface's channel from {cur} to {channel}, but the channel was not changed!")
			elif self.error_level == 0:
				pass
			elif self.error_level == 1:
				raise AttributeSetSilentFailError(f"Tried to change the interface's channel from {cur} to {channel}, but the channel was not changed!")
		return self.channel

class Scanner(object):
	""" Monitor mode scanner for finding APs and stations
	"""

	def __init__(self, iface, debug=False):
		""" Initialize the object
		"""
		self.iface = iface
		self.debug = debug
		self.is_running = False

	def __hop_channels__(self, bands, interval):
		""" Hop all channels on the specified bands, changing the channel at the specified
		interval
		"""

		channels = []
		if "a" in bands:
			channels = channels + self.iface.supported_5g_channels
		if "bg" in bands:
			channels = channels + self.iface.supported_2g_channels
		channels = channels.sort()
		self.iface.set_channel(str(channels[0]))
		print(channels)

		while True:
			if not self.is_running:
				break
			for channel in channels:
				if not self.is_running:
					break
				try:
					print("")
					print("+-------------------------------------------------------+")
					print(f"Currently on channel: {self.iface.channel}")
					print(f"Changing to channel: {channel}")
					self.iface.set_channel(str(channel))
					print(f"Interface is now using channel: {self.iface.channel}")
					print("+-------------------------------------------------------+")
					print("")
				except Exception as err_msg:
					if self.debug:
						print(f"[DEBUG] Got exception while setting channels: {err_msg}")
				time.sleep(interval)

		return None

	def detect_aps(self):
		""" Scan for access points
		"""

		seen_networks = {}
		available_networks = {}
		self.is_running = True

		def get_encryption(pkt):
			""" Get AP cipher info
			"""
			rsn = None
			wpa = None
			crypto = {
				"crypto_type": "Open"
			}
			elt = pkt.getlayer(Dot11Elt)
			while elt:
				if elt.ID == 48:
					rsn = elt.info
				elif elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x01"):
					wpa = elt.info
				elt = elt.payload.getlayer(Dot11Elt)
			if rsn:
				crypto = parse_rsn(rsn)
			elif wpa:
				crypto = parse_wpa(wpa)
			else:
				cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
				if "privacy" in cap.lower():
					crypto = {
						"crypto_type": "WEP"
					}
			return crypto

		def parse_rsn(rsn_info):
			""" WPA2 data parsing
			"""

			crypto_type = "WPA2"
			version = int.from_bytes(rsn_info[0:2], "little")
			group_cipher_oui = rsn_info[2:6]
			group_cipher = cipher_suite(group_cipher_oui)
			pairwise_count = int.from_bytes(rsn_info[6:8], "little")
			pairwise_oui = rsn_info[8:12]
			pairwise_cipher = cipher_suite(pairwise_oui)
			auth_count = int.from_bytes(rsn_info[12:14], "little")
			auth_oui = rsn_info[14:18]
			auth_type = auth_suite(auth_oui)

			crypto = {
				"crypto_type": crypto_type,
				"version": version,
				"group_cipher": group_cipher,
				"pairwise_cipher": pairwise_cipher,
				"auth_type": auth_type
			}
			return crypto

		def parse_wpa(wpa_info):
			""" WPA data parsing
			"""
			crypto_type = "WPA"
			version = int.from_bytes(wpa_info[4:6], "little")
			group_cipher_oui = wpa_info[6:10]
			group_cipher = cipher_suite(group_cipher_oui)
			pairwise_count = int.from_bytes(wpa_info[10:12], "little")
			pairwise_oui = wpa_info[12:16]
			pairwise_cipher = cipher_suite(pairwise_oui)
			auth_count = int.from_bytes(wpa_info[16:18], "little")
			auth_oui = wpa_info[18:22]
			auth_type = auth_suite(auth_oui)

			crypto = {
				"crypto_type": crypto_type,
				"version": version,
				"group_cipher": group_cipher,
				"pairwise_cipher": pairwise_cipher,
				"auth_type": auth_type
			}
			return crypto

		def cipher_suite(oui):
			""" Determine the cipher being used by the AP
			"""
			suite_types = {
				b"\x00\x0f\xac\x00": "Group cipher suite",
				b"\x00\x0f\xac\x01": "WEP-40",
				b"\x00\x0f\xac\x02": "TKIP",
				b"\x00\x0f\xac\x04": "CCMP (AES)",
				b"\x00\x0f\xac\x05": "WEP-104"
			}
			return suite_types.get(oui, f"Unknown ({oui.hex()})")

		def auth_suite(oui):
			""" Determine auth type
			"""
			auth_types = {
				b"\x00\x0f\xac\x01": "802.1X",
				b"\x00\x0f\xac\x02": "PSK"
			}
			return auth_types.get(oui, f"Unknown ({oui.hex()})")

		def callback(pkt):
			""" Extract network info from sniffed packets
			"""
			if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
				bssid = pkt.addr2
				essid = pkt.info.decode(errors="ignore")
				channel = None
				for elt in pkt.iterpayloads():
					if elt.haslayer(Dot11Elt) and elt.ID == 3:
						channel = ord(elt.info)
				signal = pkt.dBm_AntSignal
				crypto = get_encryption(pkt)
				if bssid not in seen_networks:
					seen_networks[bssid] = (essid, channel, signal, crypto)

		channel_hopper = threading.Thread(target=self.__hop_channels__, args=(("a", "bg"), 0.5), daemon=True)
		channel_hopper.start()

		sniff(iface=self.iface.iface, prn=callback, timeout=15, store=False)

		reformatted = {}
		for id_no, (bssid, values) in enumerate(seen_networks.items(), start=1):
			essid, channel, signal, crypto = values
			reformatted[id_no] = {
				"bssid": bssid,
				"essid": essid,
				"channel": channel,
				"signal": signal,
				"crypto": crypto
			}
		available_networks = reformatted
		self.is_running = False
		channel_hopper.join()
		return available_networks

	def detect_stations(self):
		""" Scan for station devices
		"""

		aps = set()
		stations = set()
		association_map = defaultdict(bool)
		self.is_running = True

		def callback(pkt):
			""" Detect stations
			"""
			if not pkt.haslayer(Dot11):
				return

			dot11 = pkt[Dot11]
			src = dot11.addr2
			dst = dot11.addr1
			bssid = dot11.addr3

			# Detect APs via beacons and probe responses
			if dot11.type == 0 and dot11.subtype in [8, 5]:
				if bssid:
					aps.add(bssid)

			# Detect stations via probe requests and data frames
			if dot11.type == 0 and dot11.subtype == 4:
				if src:
					stations.add(src)
					if src not in association_map:
						association_map[src] = False

			# Data frames also indicate association to an AP from a station
			if dot11.type == 2:
				if src:
					stations.add(src)
				if dst and not dst.startswith("ff:ff:ff"):
					stations.add(dst)

				for mac in [src, dst]:
					if mac and mac in stations:
						if bssid in aps or src in aps or dst in aps:
							association_map[mac] = True

		channel_hopper = threading.Thread(target=self.__hop_channels__, args=(("a", "bg"), 0.5), daemon=True)
		channel_hopper.start()

		sniff(iface=self.iface.iface, prn=callback, timeout=15, store=False)

		results = []
		for sta in stations:
			results.append({
				"station": sta,
				"associated": association_map.get(sta, False)
			})
		self.is_running = False
		channel_hopper.join()
		return results




