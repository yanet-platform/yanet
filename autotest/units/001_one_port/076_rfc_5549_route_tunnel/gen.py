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


# Check decapsulator for IpIp tunnel
write_pcap("001-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:0c:00")/Dot1Q(vlan=300)/IPv6(dst="3333::1", src="4444::1")/IP(dst="10.0.1.2", src="10.10.0.10", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:0c:00")/Dot1Q(vlan=300)/IPv6(dst="3333::1", src="4444::1")/IP(dst="10.0.2.2", src="10.10.0.10", ttl=64)/ICMP())

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="10.0.1.2", src="10.10.0.10", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.2.2", src="10.10.0.10", ttl=63)/ICMP())

# Check route tunnel mpls over udp + tunnel ipip
write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="10.0.1.2", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="2.0.0.1", src="10.0.1.2", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="1.0.0.1", src="10.0.2.2", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="2.0.0.1", src="10.0.2.2", ttl=64)/ICMP())

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:00:00:03", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IPv6(dst="4444::1", src="3333::1")/UDP(dport=6635, sport=0xca71, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="10.0.1.2", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:03", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IPv6(dst="5555::1", src="3333::1")/UDP(dport=6635, sport=0xf06f, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="2.0.0.1", src="10.0.1.2", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:03", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IPv6(dst="4444::1", src="3333::1")/IP(dst="1.0.0.1", src="10.0.2.2", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:03", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IPv6(dst="5555::1", src="3333::1")/IP(dst="2.0.0.1", src="10.0.2.2", ttl=63)/ICMP())
