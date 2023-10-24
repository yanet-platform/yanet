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


# check lan (ipv6 -> ipv4). create state, check source ip
write_pcap("001-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::102.102.0.0/120", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="61:2345::102.102.0.0/120", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="61:2345:6::102.102.0.6", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/TCP(dport=80, sport=2048)) # dropped

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.0.0/24", src="153.153.154.102", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.0.0/24", src="153.153.154.102", ttl=63, id=0)/TCP(dport=80, sport=3923))


# check wan (ipv4 -> ipv6)
write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="153.153.154.102", src="102.102.0.0/24", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="153.153.154.102", src="102.102.0.0/24", ttl=64)/TCP(dport=3923, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="153.153.154.103", src="102.102.0.0/24", ttl=64)/TCP(dport=2048, sport=80), # dropped
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="153.153.154.103", src="102.102.0.0/24", ttl=64)/TCP(dport=3923, sport=80)) # dropped

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="64:ff9b::102.102.0.0/120", hlim=63, fl=0)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="61:2345::102.102.0.0/120", hlim=63, fl=0)/TCP(dport=2048, sport=80))


# check lan (ipv6 -> ipv4). create state, check source ip, check source port (1024 .. 65535)
write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::102.199.99.99", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa/118", hlim=64)/TCP(dport=80, sport=4444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="61:2345::102.199.99.99", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa/118", hlim=64)/TCP(dport=80, sport=4444))

# 003-expect.pcap - dumped


# check source port
write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::102.234.123.45", src="aaaa:aaaa:aaaa:aaaa:bbbb:bbbb:bbbb:bbbb", hlim=64)/TCP(dport=80, sport=[80, 1023, 0, 1, 2, 3, 4, 5]))

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.234.123.45", src="153.153.154.64", ttl=63, id=0)/TCP(dport=80, sport=[80 + 1024, 1023 + 1024, 0 + 1024, 1 + 1024, 2 + 1024, 3 + 1024, 4 + 1024, 5 + 1024]))


# check wan (ipv4 -> ipv6)
write_pcap("005-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="153.153.154.64", src="102.234.123.45", ttl=64)/TCP(dport=[80 + 1024, 1023 + 1024, 0 + 1024, 1 + 1024, 2 + 1024, 3 + 1024, 4 + 1024, 5 + 1024], sport=80))

write_pcap("005-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:bbbb:bbbb:bbbb:bbbb", src="64:ff9b::102.234.123.45", hlim=63, fl=0)/TCP(dport=[80, 1023, 0, 1, 2, 3, 4, 5], sport=80))
