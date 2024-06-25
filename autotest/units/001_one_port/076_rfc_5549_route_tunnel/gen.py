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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64, tos=17)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IP(dst="2.0.0.1", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11")/UDP(dport=6635, sport=0xaa6c | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", tc=17)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63, tos=17)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11")/UDP(dport=6635, sport=0x1072 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="2.0.0.1", src="0.0.0.0", ttl=63)/ICMP())
