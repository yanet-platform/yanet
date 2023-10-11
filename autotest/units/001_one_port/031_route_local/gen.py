#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.contrib.mpls import MPLS


def write_pcap(filename, *packetsList):
	if len(packetsList) == 0:
		PcapWriter(filename)._write_header(Ether())
		return

	PcapWriter(filename)

	for packets in packetsList:
		if type(packets) == list:
			for packet in packets:
				packet.time = 0
				wrpcap(filename, [p for p in packet], append=True)
		else:
			packets.time = 0
			wrpcap(filename, [p for p in packets], append=True)


local_addresses_v4 = ["200.0.0.2", "200.0.0.4", "200.0.0.6", "200.0.0.21", "200.0.0.32", "200.0.0.127", "200.0.0.128", "200.0.0.130"]
local_addresses_v6 = ["::200.0.0.2", "::200.0.0.3", "::200.0.0.5", "::200.0.0.20", "::200.0.0.31", "::200.0.0.128", "::200.0.0.129", "::200.0.0.131"]

expect_v4 = []
expect_v4_local = []
send_v4 = []
send_v4_local = []

expect_v6 = []
expect_v6_local = []
send_v6 = []
send_v6_local = []
for ip_i in range(256):
	ip_v4 = f"200.0.0.{ip_i}"
	if not ip_v4 in local_addresses_v4:
		expect_v4.append(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst=f"{ip_v4}", src="222.222.222.222", ttl=63)/TCP())
		expect_v4.append(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst=f"{ip_v4}", src="222.222.222.222", ttl=63)/TCP())
		send_v4.append(Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst=f"{ip_v4}", src="222.222.222.222", ttl=64)/TCP())
		send_v4.append(Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(dst=f"{ip_v4}", src="222.222.222.222", ttl=64)/TCP())
	else:
		expect_v4_local.append(Ether(dst="71:71:71:71:71:71", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst=f"{ip_v4}", src="222.222.222.222", ttl=64)/TCP())
		expect_v4_local.append(Ether(dst="71:71:71:71:71:71", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(dst=f"{ip_v4}", src="222.222.222.222", ttl=64)/TCP())
		send_v4_local.append(Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst=f"{ip_v4}", src="222.222.222.222", ttl=64)/TCP())
		send_v4_local.append(Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(dst=f"{ip_v4}", src="222.222.222.222", ttl=64)/TCP())


	ip_v6 = f"::200.0.0.{ip_i}"
	if not ip_v6 in local_addresses_v6:
		expect_v6.append(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst=f"{ip_v6}", src="::222.222.222.222", hlim=63)/TCP())
		expect_v6.append(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst=f"{ip_v6}", src="::222.222.222.222", hlim=63)/TCP())
		send_v6.append(Ether(dst="00:11:22:33:44:55", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst=f"{ip_v6}", src="::222.222.222.222", hlim=64)/TCP())
		send_v6.append(Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst=f"{ip_v6}", src="::222.222.222.222", hlim=64)/TCP())
	else:
		expect_v6_local.append(Ether(dst="71:71:71:71:71:71", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst=f"{ip_v6}", src="::222.222.222.222", hlim=64)/TCP())
		expect_v6_local.append(Ether(dst="71:71:71:71:71:71", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst=f"{ip_v6}", src="::222.222.222.222", hlim=64)/TCP())
		send_v6_local.append(Ether(dst="00:11:22:33:44:55", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst=f"{ip_v6}", src="::222.222.222.222", hlim=64)/TCP())
		send_v6_local.append(Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst=f"{ip_v6}", src="::222.222.222.222", hlim=64)/TCP())


write_pcap("001-send.pcap",
           send_v4)

write_pcap("001-expect.pcap",
           expect_v4)

write_pcap("002-send.pcap",
           send_v4_local)

write_pcap("002-expect.pcap",
           expect_v4_local)


write_pcap("003-send.pcap",
           send_v6)

write_pcap("003-expect.pcap",
           expect_v6)

write_pcap("004-send.pcap",
           send_v6_local)

write_pcap("004-expect.pcap",
           expect_v6_local)
