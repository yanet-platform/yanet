#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *


def write_pcap(filename, *packetsList):
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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::/126", hlim=64)/TCP(dport=80, sport=(2000,2009)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0001::11.11.11.0", src="2000::/126", hlim=64)/TCP(dport=80, sport=(2000,2009)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::/126", hlim=64)/UDP(dport=80, sport=(2000,2009)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0001::11.11.11.0", src="2000::/126", hlim=64)/UDP(dport=80, sport=(2000,2009)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::/126", hlim=64)/ICMPv6EchoRequest(id=(2000,2009)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0001::11.11.11.0", src="2000::/126", hlim=64)/ICMPv6EchoRequest(id=(2000,2009)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::/126", hlim=64)/ICMPv6EchoReply(id=(2000,2009)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0001::11.11.11.0", src="2000::/126", hlim=64)/ICMPv6EchoReply(id=(2000,2009)))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/TCP(dport=80, sport=(12001,12004)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/TCP(dport=80, sport=(12013,12016)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/TCP(dport=80, sport=(12005,12008)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/TCP(dport=80, sport=(12017,12020)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/TCP(dport=80, sport=(12009,12012)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/TCP(dport=80, sport=(12021,12024)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/TCP(dport=80, sport=(12001,12004)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/TCP(dport=80, sport=(12013,12016)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/TCP(dport=80, sport=(12005,12008)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/TCP(dport=80, sport=(12017,12020)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/TCP(dport=80, sport=(12009,12012)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/TCP(dport=80, sport=(12021,12024)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/UDP(dport=80, sport=(12001,12004)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/UDP(dport=80, sport=(12013,12016)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/UDP(dport=80, sport=(12005,12008)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/UDP(dport=80, sport=(12017,12020)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/UDP(dport=80, sport=(12009,12012)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/UDP(dport=80, sport=(12021,12024)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/UDP(dport=80, sport=(12001,12004)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/UDP(dport=80, sport=(12013,12016)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/UDP(dport=80, sport=(12005,12008)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/UDP(dport=80, sport=(12017,12020)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/UDP(dport=80, sport=(12009,12012)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/UDP(dport=80, sport=(12021,12024)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/ICMP(type=8, id=(12001,12004)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/ICMP(type=8, id=(12013,12016)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/ICMP(type=8, id=(12005,12008)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/ICMP(type=8, id=(12017,12020)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/ICMP(type=8, id=(12009,12012)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/ICMP(type=8, id=(12021,12024)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/ICMP(type=8, id=(12001,12004)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/ICMP(type=8, id=(12013,12016)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/ICMP(type=8, id=(12005,12008)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/ICMP(type=8, id=(12017,12020)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/ICMP(type=8, id=(12009,12012)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.1", ttl=63, id=0)/ICMP(type=8, id=(12021,12024)))


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/TCP(dport=(12000,12004), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/TCP(dport=(12013,12016), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/TCP(dport=(12005,12008), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/TCP(dport=(12017,12020), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/TCP(dport=(12009,12012), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/TCP(dport=(12021,12025), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/TCP(dport=(12000,12004), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/TCP(dport=(12013,12016), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/TCP(dport=(12005,12008), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/TCP(dport=(12017,12020), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/TCP(dport=(12009,12012), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/TCP(dport=(12021,12025), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/UDP(dport=(12000,12004), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/UDP(dport=(12013,12016), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/UDP(dport=(12005,12008), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/UDP(dport=(12017,12020), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/UDP(dport=(12009,12012), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/UDP(dport=(12021,12025), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/UDP(dport=(12000,12004), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/UDP(dport=(12013,12016), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/UDP(dport=(12005,12008), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/UDP(dport=(12017,12020), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/UDP(dport=(12009,12012), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/UDP(dport=(12021,12025), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12000,12004)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12013,12016)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12005,12008)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12017,12020)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12009,12012)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12021,12025)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12000,12004)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12013,12016)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12005,12008)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12017,12020)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12009,12012)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=8, id=(12021,12025)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12000,12004)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12013,12016)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12005,12008)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12017,12020)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12009,12012)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12021,12025)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12000,12004)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12013,12016)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12005,12008)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12017,12020)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12009,12012)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="11.11.11.0", ttl=64)/ICMP(type=0, id=(12021,12025)))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/TCP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/TCP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/TCP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0001::11.11.11.0", hlim=63, fl=0)/TCP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2222:987:0a00:0001::11.11.11.0", hlim=63, fl=0)/TCP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2222:987:0a00:0001::11.11.11.0", hlim=63, fl=0)/TCP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/UDP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/UDP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/UDP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0001::11.11.11.0", hlim=63, fl=0)/UDP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2222:987:0a00:0001::11.11.11.0", hlim=63, fl=0)/UDP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2222:987:0a00:0001::11.11.11.0", hlim=63, fl=0)/UDP(dport=(2001,2008), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/ICMPv6EchoReply(id=(2001,2008)),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/ICMPv6EchoReply(id=(2001,2008)),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/ICMPv6EchoReply(id=(2001,2008)),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0001::11.11.11.0", hlim=63, fl=0)/ICMPv6EchoReply(id=(2001,2008)),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2222:987:0a00:0001::11.11.11.0", hlim=63, fl=0)/ICMPv6EchoReply(id=(2001,2008)),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2222:987:0a00:0001::11.11.11.0", hlim=63, fl=0)/ICMPv6EchoReply(id=(2001,2008)))


write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::", hlim=64)/TCP(dport=80, sport=2001),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::", hlim=64)/IPv6ExtHdrDestOpt()/TCP(dport=81, sport=2001),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::", hlim=64)/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/TCP(dport=82, sport=2001),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::", hlim=64, plen=800)/TCP(dport=80, sport=2001),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::", hlim=64, plen=0)/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/TCP(dport=83, sport=2001),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::", hlim=64, plen=1)/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/TCP(dport=84, sport=2001),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::", hlim=64, plen=20)/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/TCP(dport=85, sport=2001),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::", hlim=64, plen=64)/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/TCP(dport=86, sport=2001),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::", hlim=64, plen=65)/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/TCP(dport=87, sport=2001),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:987:0a00:0000::11.11.11.0", src="2000::", hlim=64, plen=83)/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/TCP(dport=88, sport=2001))

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/TCP(dport=80, sport=12001),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/TCP(dport=81, sport=12001),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0)/TCP(dport=82, sport=12001))


write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64)/TCP(dport=12001, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, options=("\x02"*4))/TCP(dport=12001, sport=81),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, options=("\x02"*16))/TCP(dport=12001, sport=82),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, options=("\x02"*20))/TCP(dport=12001, sport=83),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, options=("\x02"*24))/TCP(dport=12001, sport=84),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, options=("\x02"*36))/TCP(dport=12001, sport=85),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, options=("\x02"*40))/TCP(dport=12001, sport=86),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, len=800)/TCP(dport=12001, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, len=0)/TCP(dport=12001, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, len=39)/TCP(dport=12001, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, len=43, options=("\x02"*4))/TCP(dport=12001, sport=81),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, len=55, options=("\x02"*16))/TCP(dport=12001, sport=82),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, len=59, options=("\x02"*20))/TCP(dport=12001, sport=83),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, len=63, options=("\x02"*24))/TCP(dport=12001, sport=84),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, len=75, options=("\x02"*36))/TCP(dport=12001, sport=85),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, len=79, options=("\x02"*40))/TCP(dport=12001, sport=86))

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/TCP(dport=2001, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/TCP(dport=2001, sport=81),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/TCP(dport=2001, sport=82),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/TCP(dport=2001, sport=83),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/TCP(dport=2001, sport=84),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/TCP(dport=2001, sport=85),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.0", hlim=63, fl=0)/TCP(dport=2001, sport=86))
