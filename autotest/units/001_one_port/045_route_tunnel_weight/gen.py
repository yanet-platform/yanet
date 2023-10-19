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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/UDP(dport=443, sport=(10001,20000)))


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e57::1", src="::", hlim=64)/UDP(dport=443, sport=(10001,20000)))


write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IP(dst="1.0.0.251", src="0.0.0.0", ttl=64)/UDP(dport=443, sport=(10001,20000)))


write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IP(dst="1.0.0.250", src="0.0.0.0", ttl=64)/UDP(dport=443, sport=(10001,20000)))


write_pcap("005-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e57::fffb", src="::", hlim=64)/UDP(dport=443, sport=(10001,20000)))


write_pcap("006-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e57::fffa", src="::", hlim=64)/UDP(dport=443, sport=(10001,20000)))
