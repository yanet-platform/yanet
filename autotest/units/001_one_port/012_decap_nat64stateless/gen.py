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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="2000::", hlim=64)/IP(dst="1.1.0.1", src="0.0.0.0", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.1.0.0", src="2000::", hlim=64)/TCP(dport=80, sport=2048))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.1", src="0.0.0.0", ttl=63)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0", src="10.0.0.0", ttl=63, id=0)/TCP(dport=80, sport=2048))


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="1.1.0.0", ttl=64)/TCP(dport=2048, sport=80))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="64:ff9b::1.1.0.0", hlim=63, fl=0)/TCP(dport=2048, sport=80))
