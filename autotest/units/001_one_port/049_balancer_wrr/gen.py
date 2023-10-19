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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.1", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.2", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.3", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.4", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.5", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.6", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.7", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.8", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.1", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.2", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.3", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.4", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.5", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.6", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.7", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.0.8", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.1", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.2", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.3", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.4", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.5", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.6", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.7", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.8", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.1", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.2", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.3", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.4", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.5", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.6", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.7", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.2", src="1.1.1.8", ttl=64)/TCP(dport=443, sport=12444))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.1", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0002:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.2", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0003:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.3", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0004:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.4", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0005:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.5", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0006:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.6", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0007:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.7", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0008:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.8", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.1", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0002:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.2", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0003:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.3", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0004:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.4", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0005:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.5", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0006:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.6", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0007:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.7", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0008:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.0.8", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0101:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.1", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0102:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.2", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0103:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.3", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0104:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.4", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0105:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.5", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0106:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.6", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0107:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.7", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0108:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.8", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0101:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.1", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0102:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.2", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0103:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.3", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0104:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.4", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0105:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.5", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0106:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.6", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0107:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.7", ttl=64)/TCP(dport=443, sport=12444),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0108:0:1", hlim=63, fl=0)/IP(dst="10.1.0.2", src="1.1.1.8", ttl=64)/TCP(dport=443, sport=12444))

