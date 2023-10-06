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


write_pcap("001-send.pcap",
           fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64)/ICMP()/("ABCDEFGH123CCCCCCCCC"*120)/"QWERTY123", fragsize=1208))

write_pcap("001-expect.pcap",
           fragment(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63)/ICMP()/("ABCDEFGH123CCCCCCCCC"*120)/"QWERTY123", fragsize=1208))


write_pcap("002-send.pcap",
           fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::")/IPv6ExtHdrFragment(id=0x31337)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64)/ICMP()/("ABCDEFGH123CCCCCCCCC"*120)/"QWERTY123", fragSize=1280))

write_pcap("002-expect.pcap")
