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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.0.0.127", src="0.0.0.1")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.0.0.63", src="0.0.0.1")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.0.0.15", src="0.0.0.1")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.0.0.3", src="0.0.0.1")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.0.0.4", src="0.0.0.1")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="0.0.0.1")/ICMP(),
)

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/
                 IP(dst="18.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xc2de, chksum=0)/
                 MPLS(label=1100, ttl=255)/IP(dst="1.0.0.127", src="0.0.0.1", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/
                 IP(dst="18.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xc5a4, chksum=0)/
                 MPLS(label=1100, ttl=255)/IP(dst="1.0.0.63", src="0.0.0.1", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/
                 IP(dst="38.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xfcbf, chksum=0)/
                 MPLS(label=1102, ttl=255)/IP(dst="1.0.0.15", src="0.0.0.1", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/
                 IP(dst="38.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xc43d, chksum=0)/
                 MPLS(label=1102, ttl=255)/IP(dst="1.0.0.3", src="0.0.0.1", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/
                 IP(dst="38.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xf4b4, chksum=0)/
                 MPLS(label=1102, ttl=255)/IP(dst="1.0.0.4", src="0.0.0.1", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/
                 IP(dst="68.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xddad, chksum=0)/
                 MPLS(label=1105, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.1", ttl=63)/ICMP(),
)


