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


# ipv4 (first packet. resolve mac)
write_pcap("001-send.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="10.0.0.1", ttl=64)/TCP(dport=2048, sport=8080))

write_pcap("001-expect.pcap")


# ipv4
write_pcap("002-send.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="10.0.0.1", ttl=64)/TCP(dport=2048, sport=8080))

write_pcap("002-expect.pcap",
           Ether(dst="2C:2C:3D:76:29:FD", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="10.0.0.1", ttl=63)/TCP(dport=2048, sport=8080))


# ipv6 (first packet. resolve mac)
write_pcap("003-send.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/TCP(dport=8080, sport=2048))

write_pcap("003-expect.pcap")


# ipv6
write_pcap("004-send.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/TCP(dport=8080, sport=2048))

write_pcap("004-expect.pcap",
           Ether(dst="42:42:A4:59:BE:A5", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=63)/TCP(dport=8080, sport=2048))
