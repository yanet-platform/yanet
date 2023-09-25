#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *


def write_pcap(filename, *packetsList):
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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:1:2:3:1.1.0.1", src="2000::", tc=0, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:1:2:3:1.1.0.1", src="2000::", tc=0x4, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:1:2:3:1.1.0.1", src="2000::", tc=0x80, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:1:2:3:1.1.0.1", src="2000::", tc=0xfc, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:1:2:3:1.1.0.1", src="2000::", tc=0xff, hlim=64)/UDP(dport=2048, sport=443),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IPv6(dst="1:2:3:1:2:3:1.2.0.2", src="2000::", tc=0, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IPv6(dst="1:2:3:1:2:3:1.2.0.2", src="2000::", tc=0x4, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IPv6(dst="1:2:3:1:2:3:1.2.0.2", src="2000::", tc=0x80, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IPv6(dst="1:2:3:1:2:3:1.2.0.2", src="2000::", tc=0xfc, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IPv6(dst="1:2:3:1:2:3:1.2.0.2", src="2000::", tc=0xff, hlim=64)/UDP(dport=2048, sport=443),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=300)/IPv6(dst="1:2:3:1:2:3:1.3.0.3", src="2000::", tc=0, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=300)/IPv6(dst="1:2:3:1:2:3:1.3.0.3", src="2000::", tc=0x4, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=300)/IPv6(dst="1:2:3:1:2:3:1.3.0.3", src="2000::", tc=0x80, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=300)/IPv6(dst="1:2:3:1:2:3:1.3.0.3", src="2000::", tc=0xfc, hlim=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=300)/IPv6(dst="1:2:3:1:2:3:1.3.0.3", src="2000::", tc=0xff, hlim=64)/UDP(dport=2048, sport=443))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.1.0.1", src="0.0.0.0", ttl=63, tos=0x28, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.1.0.1", src="0.0.0.0", ttl=63, tos=0x4, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.1.0.1", src="0.0.0.0", ttl=63, tos=0x80, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.1.0.1", src="0.0.0.0", ttl=63, tos=0xfc, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.1.0.1", src="0.0.0.0", ttl=63, tos=0xff, id=0)/UDP(dport=2048, sport=443),

           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.2", src="10.0.0.0", ttl=63, tos=0x50, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.2", src="10.0.0.0", ttl=63, tos=0x50, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.2", src="10.0.0.0", ttl=63, tos=0x50, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.2", src="10.0.0.0", ttl=63, tos=0x50, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.2", src="10.0.0.0", ttl=63, tos=0x53, id=0)/UDP(dport=2048, sport=443),

           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IP(dst="1.3.0.3", src="100.0.0.0", ttl=63, tos=0, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IP(dst="1.3.0.3", src="100.0.0.0", ttl=63, tos=0x4, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IP(dst="1.3.0.3", src="100.0.0.0", ttl=63, tos=0x80, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IP(dst="1.3.0.3", src="100.0.0.0", ttl=63, tos=0xfc, id=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IP(dst="1.3.0.3", src="100.0.0.0", ttl=63, tos=0xff, id=0)/UDP(dport=2048, sport=443))
