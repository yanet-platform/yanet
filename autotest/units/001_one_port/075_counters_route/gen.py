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

load_contrib("mpls")

write_pcap("send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="111.222.111.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.2", src="111.222.111.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.3", src="111.222.111.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="2.0.0.4", src="111.222.111.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="2.0.0.5", src="111.222.111.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="3.0.0.6", src="111.222.111.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="4.0.0.7", src="111.222.111.222", ttl=64)/TCP())

write_pcap("expect.pcap",
           Ether(dst="00:00:00:11:11:22", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/MPLS(label=1100, ttl=0xff)/IP(dst="1.0.0.1", src="111.222.111.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:22", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/MPLS(label=1100, ttl=0xff)/IP(dst="1.0.0.2", src="111.222.111.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:22", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/MPLS(label=1100, ttl=0xff)/IP(dst="1.0.0.3", src="111.222.111.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:33", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/MPLS(label=1100, ttl=0xff)/IP(dst="2.0.0.4", src="111.222.111.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:33", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/MPLS(label=1100, ttl=0xff)/IP(dst="2.0.0.5", src="111.222.111.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:55", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/MPLS(label=1100, ttl=0xff)/IP(dst="3.0.0.6", src="111.222.111.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="4.0.0.7", src="111.222.111.222", ttl=63)/TCP())
