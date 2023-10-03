#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *


def write_pcap(filename, *packetsList):
	PcapWriter(filename)
	for packets in packetsList:
		packets.time = 0
		wrpcap(filename, [p for p in packets], append=True)


write_pcap("send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE()/IP(dst="1.2.3.0", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(chksum_present=1)/IP(dst="1.2.3.1", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(key_present=1)/IP(dst="1.2.3.2", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(seqnum_present=1)/IP(dst="1.2.3.3", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(chksum_present=1, key_present=1, seqnum_present=1)/IP(dst="1.2.3.4", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(version=1)/IP(dst="1.2.3.5", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(version=4)/IP(dst="1.2.3.6", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(flags=1)/IP(dst="1.2.3.7", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(flags=16)/IP(dst="1.2.3.8", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(recursion_control=1)/IP(dst="1.2.3.9", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(recursion_control=4)/IP(dst="1.2.3.10", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(strict_route_source=1)/IP(dst="1.2.3.11", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::", nh=47)/GRE(routing_present=1)/IP(dst="1.2.3.12", src="0.0.0.0")/ICMP())

write_pcap("expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.0", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.2", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.3", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63)/ICMP())
