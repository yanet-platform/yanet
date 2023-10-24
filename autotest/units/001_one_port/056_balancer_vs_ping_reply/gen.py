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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="10.0.0.20", src="1.1.0.1", ttl=64)/ICMP(type=8, code=0, id=1, seq=0x0001)/"",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="10.0.0.20", src="1.1.0.1", ttl=64)/ICMP(type=8, code=0, id=2, seq=0x0002)/"abcdefghijklmnopqrstuvwxyz0123456789")

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.1", src="10.0.0.20", ttl=64)/ICMP(type=0, code=0, id=1, seq=0x0001)/"",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.1", src="10.0.0.20", ttl=64)/ICMP(type=0, code=0, id=2, seq=0x0002)/"abcdefghijklmnopqrstuvwxyz0123456789")

write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2005:dead:beef::1", src="2000:51b::1", hlim=64)/ICMPv6EchoRequest(id=1, seq=0x0001)/"",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2005:dead:beef::1", src="2000:51b::1", hlim=64)/ICMPv6EchoRequest(id=2, seq=0x0002)/"0123456789abcdefghijklmnopqrstuvwxyz")

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="2000:51b::1", src="2005:dead:beef::1", hlim=64)/ICMPv6EchoReply(id=1, seq=0x0001)/"",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="2000:51b::1", src="2005:dead:beef::1", hlim=64)/ICMPv6EchoReply(id=2, seq=0x0002)/"0123456789abcdefghijklmnopqrstuvwxyz")

write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="10.0.0.21", src="1.1.0.2", ttl=64)/ICMP(type=8, code=0, id=1, seq=0x0001)/"abcdefghijklmnopqrstuvwxyz0123456789")

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.2", src="10.0.0.21", ttl=64)/ICMP(type=0, code=0, id=1, seq=0x0001)/"abcdefghijklmnopqrstuvwxyz0123456789")
