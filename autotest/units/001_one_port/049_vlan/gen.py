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

write_pcap("001-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/IP(dst="1.0.0.0", src="222.222.222.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/IP(dst="1.1.0.0", src="222.222.222.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/IP(dst="1.2.0.0", src="222.222.222.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/IP(dst="1.3.0.0", src="222.222.222.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/IP(dst="1.4.0.0", src="222.222.222.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/IP(dst="1.5.0.0", src="222.222.222.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/IP(dst="1.6.0.0", src="222.222.222.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/IP(dst="1.7.0.0", src="222.222.222.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/IP(dst="1.8.0.0", src="222.222.222.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/IP(dst="1.9.0.0", src="222.222.222.222", ttl=64)/TCP())


write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.4.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.6.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.7.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.8.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.9.0.0", src="222.222.222.222", ttl=63)/TCP())
