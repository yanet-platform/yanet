#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import time
import subprocess
import sys
import signal


services = ["yanet-init", "yanet-dataplane", "yanet-controlplane"]
announcer_config_path = "/etc/yanet/announcer.conf"
machine_target_path = "/etc/yanet/target"


class Table:
	def __init__(self, command):
		out = subprocess.check_output(command, shell=True).decode('ascii').splitlines()

		if len(out) <= 1:
			return

		self.column_lengths = [len(column) for column in out[1].split("  ")]

		offset = 0
		self.headers = []
		for i in range(0, len(self.column_lengths)):
			self.headers.append(out[0][offset:offset + self.column_lengths[i]].strip())
			offset += self.column_lengths[i] + 2

		self.rows = []
		for row_i in range(2, len(out)):
			offset = 0
			columns = {}
			for i in range(0, len(self.column_lengths)):
				columns[self.headers[i]] = out[row_i][offset:offset + self.column_lengths[i]].strip()
				offset += self.column_lengths[i] + 2

			self.rows.append(columns)


def bgp_update_ipv4(prefix):
	global testing
	global announcer_config

	print(f"bgp_update_ipv4: {prefix}")
	if prefix in announcer_config:
		for command in announcer_config[prefix]["update"]:
			print(command)
			if not testing:
				os.system(command)


def bgp_remove_ipv4(prefix):
	global testing
	global announcer_config

	print(f"bgp_remove_ipv4: {prefix}")
	if prefix in announcer_config:
		for command in announcer_config[prefix]["remove"]:
			print(command)
			if not testing:
				os.system(command)


def bgp_update_ipv6(prefix):
	global testing
	global announcer_config

	print(f"bgp_update_ipv6: {prefix}")
	if prefix in announcer_config:
		for command in announcer_config[prefix]["update"]:
			print(command)
			if not testing:
				os.system(command)


def bgp_remove_ipv6(prefix):
	global testing
	global announcer_config

	print(f"bgp_remove_ipv6: {prefix}")
	if prefix in announcer_config:
		for command in announcer_config[prefix]["remove"]:
			print(command)
			if not testing:
				os.system(command)


def bgp_update(prefix):
	if ":" in prefix:
		bgp_update_ipv6(prefix)
	else:
		bgp_update_ipv4(prefix)


def bgp_remove(prefix):
	if ":" in prefix:
		bgp_remove_ipv6(prefix)
	else:
		bgp_remove_ipv4(prefix)


def print_usage():
	print("usage: %s --run" % (sys.argv[0]))
	print("       %s --test" % (sys.argv[0]))


def get_table(command):
	global tables

	if command not in tables:
		tables[command] = Table(command)

	return tables[command]


def get_announces(types):
	for type in types:
		table_decap = get_table(f"yanet-cli {type}")
		table_decap_announce = get_table(f"yanet-cli {type} announce")

		for table_decap_row in table_decap.rows:
			module = table_decap_row["module"]
			next_module = table_decap_row["next_module"]

			announces = []
			for table_decap_announce_row in table_decap_announce.rows:
				if table_decap_announce_row["module"] != module:
					continue

				if table_decap_announce_row["announces"] == "n/s":
					continue

				announces.extend(table_decap_announce_row["announces"].split(","))

			yield {"module": module,
			       "type": type,
			       "announces": announces,
			       "next_module": next_module}


def check_services():
	global testing

	if testing:
		print("check_services()")

	for service in services:
		if os.system("systemctl status %s.service > /dev/null" % (service)):
			raise Exception(f"check_services({service})")


def check_rib(rib_table):
	global testing

	if testing:
		print(f"check_rib('{rib_table}')")

	table = get_table("yanet-cli rib")

	if len(table.rows) == 0:
		raise Exception(f"check_rib('{rib_table}')")

	for row in table.rows:
		if row["table_name"] == rib_table and row["eor"] == "true":
			return

	raise Exception(f"check_rib('{rib_table}')")


def check_default_v4(route):
	global testing

	if testing:
		print(f"check_default_v4('{route}')")

	interfaces = get_table("yanet-cli route interface")
	routes = get_table(f"yanet-cli route get {route} 0.0.0.0/0")

	for route_row in routes.rows:
		for interface_row in interfaces.rows:
			if interface_row["module"] != route:
				continue
			if route_row["egress_interface"] == interface_row["interface"]:
				return

	raise Exception(f"check_default_v4('{route}')")


def check_default_v6(route):
	global testing

	if testing:
		print(f"check_default_v6('{route}')")

	interfaces = get_table("yanet-cli route interface")
	routes = get_table(f"yanet-cli route get {route} ::/0")

	for route_row in routes.rows:
		for interface_row in interfaces.rows:
			if interface_row["module"] != route:
				continue
			if route_row["egress_interface"] == interface_row["interface"]:
				return

	raise Exception(f"check_default_v6('{route}')")


def check_interfaces_neighbor_v4():
	global testing

	if testing:
		print(f"check_interfaces_neighbor_v4()")

	interfaces = get_table("yanet-cli route interface")

	for row in interfaces.rows:
		if row["neighbor_mac_address_v4"] != "n/s":
			return

	raise Exception(f"check_interfaces_neighbor_v4()")


def check_interfaces_neighbor_v6():
	global testing

	if testing:
		print(f"check_interfaces_neighbor_v6()")

	interfaces = get_table("yanet-cli route interface")

	for row in interfaces.rows:
		if row["neighbor_mac_address_v6"] != "n/s":
			return

	raise Exception(f"check_interfaces_neighbor_v6()")


def check_module(module):
	global testing

	try:
		check_services()

		if module["type"] == "tun64":
			check_rib("ipv4 unicast")
			check_rib("ipv6 unicast")
			if module["next_module"].endswith(":tunnel"):
				check_default_v4(module["next_module"][:-7])
				check_default_v6(module["next_module"][:-7])
			else:
				check_default_v4(module["next_module"])
				check_default_v6(module["next_module"])
			check_interfaces_neighbor_v4()
			check_interfaces_neighbor_v6()
		elif module["type"] == "nat64stateful":
			check_rib("ipv4 unicast")
			check_rib("ipv6 unicast")
			if module["next_module"].endswith(":tunnel"):
				check_default_v4(module["next_module"][:-7])
				check_default_v6(module["next_module"][:-7])
			else:
				check_default_v4(module["next_module"])
				check_default_v6(module["next_module"])
			check_interfaces_neighbor_v4()
			check_interfaces_neighbor_v6()
		elif module["type"] == "decap":
			if module["next_module"].endswith(":tunnel"):
				check_rib("ipv4 unicast")
				check_rib("ipv6 unicast")
				check_default_v4(module["next_module"][:-7])
				check_default_v6(module["next_module"][:-7])
				check_interfaces_neighbor_v4()
				check_interfaces_neighbor_v6()
			else:
				check_rib("ipv4 unicast")
				check_default_v4(module["next_module"])
				check_interfaces_neighbor_v4()
		elif module["type"] == "nat64stateless":
			check_rib("ipv4 unicast")
			check_rib("ipv6 unicast")
			if module["next_module"].endswith(":tunnel"):
				check_default_v4(module["next_module"][:-7])
				check_default_v6(module["next_module"][:-7])
			else:
				check_default_v4(module["next_module"])
				check_default_v6(module["next_module"])
			check_interfaces_neighbor_v4()
			check_interfaces_neighbor_v6()
		elif module["type"] == "dregress":
			check_rib("ipv4 unicast")
			check_rib("ipv6 unicast")
			check_default_v4(module["next_module"])
			check_default_v6(module["next_module"])
			check_interfaces_neighbor_v4()
			check_interfaces_neighbor_v6()
		elif module["type"] == "balancer":
			check_rib("ipv6 unicast")
			check_default_v6(module["next_module"])
			check_interfaces_neighbor_v6()
		elif module["type"] == "firewall":
			check_rib("ipv6 unicast")
			check_default_v6(module["next_module"])
			check_interfaces_neighbor_v6()
	except Exception as error:
		if testing:
			print(f"fail: {error}")
		return False

	return True


def signal_handler(signum, frame):
	global stop
	stop = True

def main():
	global tables
	global stop
	global testing
	global announcer_config
	global is_fw

	if len(sys.argv) != 2:
		print_usage()
		sys.exit(1)

	if sys.argv[1] == "--run":
		testing = False
		signal.signal(signal.SIGTERM, signal_handler)

	current_prefixes = []
	report_counter = 0
	is_fw = False

	try:
		with open(machine_target_path, 'r', encoding='UTF-8') as file:
			line = file.readline().rstrip()
			if "firewall" in line:
				is_fw = True
			file.close()
	except Exception as error:
		print(f"failed to read target file: {error}")

	while True:
		prefixes = []
		tables = {}

		try:
			with open(announcer_config_path) as f:
				announcer_config = json.load(f)
		except Exception as error:
			if (report_counter % 25 == 0):
				print(f"fail: {error}")
			report_counter += 1
			time.sleep(1)
			continue

		try:
			for module in get_announces(["decap", "nat64stateless", "dregress", "balancer", "tun64", "nat64stateful"]):
				if testing:
					print(module)

				if check_module(module):
					prefixes.extend(module["announces"])

				if testing:
					print()
		except:
			pass

		if is_fw:
			if check_module({
				"module": "firewall",
				"type": "firewall",
				"next_module": "route0"}):
				prefixes.extend(["firewall::/128"])

		for prefix in list(set(prefixes) - set(current_prefixes)):
			try:
				bgp_update(prefix)
			except:
				pass

		for prefix in list(set(current_prefixes) - set(prefixes)):
			try:
				bgp_remove(prefix)
			except:
				pass

		if testing:
			sys.exit(0)

		current_prefixes = prefixes

		if stop:
			for prefix in current_prefixes:
				try:
					bgp_remove(prefix)
				except:
					pass

			sys.exit(0)

		sys.stdout.flush()
		time.sleep(1)


tables = {}
stop = False
testing = True
announcer_config = None


if __name__ == '__main__':
	main()
