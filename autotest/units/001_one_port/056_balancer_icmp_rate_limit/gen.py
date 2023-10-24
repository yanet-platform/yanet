#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *


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


# real is NOT found, packet should be cloned and distributed among neighbor balancers (according to unrdup config) - all of them have ipv4 addresses
# icmp dest unreach
write_pcap("001-send.pcap",
		   # network unreachable
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="10.0.0.34", src="1.101.9.9", ttl=64)/ICMP(type=3, code=0)/IP(src="10.0.0.34", dst="1.1.0.99", ttl=50)/TCP(dport=(1,10500), sport=80)
		  )

write_pcap("001-expect.pcap",
		   # network unreachable
		   Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="123.1.231.151", src="102.0.0.22", ttl=63)/IP(dst="10.0.0.34", src="1.101.9.9", ttl=64)/ICMP(type=3, code=0)/IP(src="10.0.0.34", dst="1.1.0.99", ttl=50)/TCP(dport=(1,10500), sport=80),
		  )
