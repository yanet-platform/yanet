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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:9999::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:9999::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0x4, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:9999::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0x80, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:9999::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0xfc, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:9999::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0xff, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:2345::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:2345::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0x4, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:2345::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0x80, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:2345::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0xfc, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:2345::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0xff, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:abcd::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:abcd::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0x4, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:abcd::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0x80, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:abcd::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0xfc, hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:abcd::102.124.0.0/120", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", tc=0xff, hlim=64)/TCP(dport=443, sport=2048))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.122.122", ttl=63, id=0, tos=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.122.122", ttl=63, id=0, tos=0x4)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.122.122", ttl=63, id=0, tos=0x80)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.122.122", ttl=63, id=0, tos=0xfc)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.122.122", ttl=63, id=0, tos=0xff)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.154.171", ttl=63, id=0, tos=0x28)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.154.171", ttl=63, id=0, tos=0x4)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.154.171", ttl=63, id=0, tos=0x80)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.154.171", ttl=63, id=0, tos=0xfc)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.154.171", ttl=63, id=0, tos=0xff)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.155.43", ttl=63, id=0, tos=0x50)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.155.43", ttl=63, id=0, tos=0x50)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.155.43", ttl=63, id=0, tos=0x50)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.155.43", ttl=63, id=0, tos=0x50)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.124.0.0/24", src="122.122.155.43", ttl=63, id=0, tos=0x53)/TCP(dport=443, sport=2048))


# check wan (ipv4 -> ipv6)
write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="122.122.122.122", src="102.124.0.0/24", ttl=64)/TCP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="122.122.154.171", src="102.124.0.0/24", ttl=64)/TCP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="122.122.155.43", src="102.124.0.0/24", ttl=64)/TCP(dport=2048, sport=443))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", src="2000:9999::102.124.0.0/120", hlim=63, fl=0)/TCP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", src="2000:2345::102.124.0.0/120", hlim=63, fl=0)/TCP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb", src="2000:abcd::102.124.0.0/120", hlim=63, fl=0)/TCP(dport=2048, sport=443))


# check lan (ipv6 -> ipv4). create state, check source ip, check source port (1024 .. 65535)
write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:9999::142.199.99.99", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb/118", tc=0x50, hlim=64)/TCP(dport=443, sport=4444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:2345::142.199.99.99", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb/118", tc=0x50, hlim=64)/TCP(dport=443, sport=4444),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:abcd::142.199.99.99", src="bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb/118", tc=0x50, hlim=64)/TCP(dport=443, sport=4444))

# 003-expect.pcap - dumped
