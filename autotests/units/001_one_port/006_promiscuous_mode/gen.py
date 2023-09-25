#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *


def write_pcap(filename, *packetsList):
	PcapWriter(filename)
	for packets in packetsList:
		packets.time = 0
		wrpcap(filename, [p for p in packets], append=True)


write_pcap("send.pcap",
           Ether(dst="00:99:99:99:99:99", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.2.3.0", src="0.0.0.0", ttl=64, tos=0)/ICMP(),
           Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.2.3.2", src="0.0.0.0", ttl=64, tos=0)/ICMP(),
           Ether(dst="00:99:99:99:99:99", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IP(dst="1.2.3.1", src="0.0.0.0", ttl=64, tos=0)/ICMP(),
           Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IP(dst="1.2.3.3", src="0.0.0.0", ttl=64, tos=0)/ICMP())

write_pcap("expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.1", src="0.0.0.0", ttl=63, tos=0)/ICMP())
