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


# lan (ipv4 -> ipv6)
write_pcap("001-send.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="10.0.0.1", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="10.0.0.1", ttl=64)/TCP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="20.0.0.1", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="20.0.0.1", ttl=64)/TCP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="10.0.0.1", ttl=64)/TCP(dport=5548, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="10.0.0.1", ttl=64)/TCP(dport=5548, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="20.0.0.1", ttl=64)/TCP(dport=5548, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="20.0.0.1", ttl=64)/TCP(dport=5548, sport=443))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/TCP(dport=2048, sport=443),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/TCP(dport=2048, sport=443),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/TCP(dport=5548, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/TCP(dport=5548, sport=443),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/TCP(dport=5548, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/TCP(dport=5548, sport=443))


# wan (ipv6 -> ipv4)
write_pcap("002-send.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/TCP(dport=80, sport=5548),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/TCP(dport=443, sport=5548),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/TCP(dport=80, sport=5548),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/TCP(dport=443, sport=5548))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="4.4.4.4", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="4.4.4.4", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="4.4.4.4", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="4.4.4.4", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="88.88.4.4", ttl=63, id=0)/TCP(dport=80, sport=5548),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="88.88.4.4", ttl=63, id=0)/TCP(dport=443, sport=5548),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="88.88.4.4", ttl=63, id=0)/TCP(dport=80, sport=5548),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="88.88.4.4", ttl=63, id=0)/TCP(dport=443, sport=5548))
