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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=81, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=81, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=81, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=81, sport=12380))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::3", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::3", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::3", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=81, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=81, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=81, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.3", src="1.1.0.1", ttl=64)/UDP(dport=81, sport=12380))
