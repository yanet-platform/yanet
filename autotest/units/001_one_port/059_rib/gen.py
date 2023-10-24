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

# two routes with same local preference - equal possibility to be sent with either label
write_pcap("001-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="111.222.111.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="111.2.111.1", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="222.1.222.1", ttl=64)/TCP())

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="111.222.111.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
	       Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="111.2.111.1", ttl=63)/TCP(),
	       Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="222.1.222.1", ttl=63)/TCP())

# only one best route left in fib - always label 1200
write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="111.222.111.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="111.2.111.1", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="222.1.222.1", ttl=64)/TCP())

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="111.222.111.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
	       Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="111.2.111.1", ttl=63)/TCP(),
	       Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="222.1.222.1", ttl=63)/TCP())
