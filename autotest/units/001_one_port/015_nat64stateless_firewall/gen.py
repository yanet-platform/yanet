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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(flags="S"),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(flags="FPU"),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(flags=""),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/UDP(dport=4430, sport=50),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/UDP(dport=4430, sport=53),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=0),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=8),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(flags="SA"),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(flags="A"),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/GRE())

write_pcap("001-expect.pcap",
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/UDP(dport=4430, sport=53),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/ICMPv6EchoReply(),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/ICMPv6EchoRequest(),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/TCP(flags="SA"),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/TCP(flags="A"))


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=3)/IP(dst="10.99.99.99", src="10.88.88.88")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=4),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=5),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=9),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=10),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=11)/IP(dst="10.99.99.99", src="10.88.88.88")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=12, ptr=13)/IP(dst="10.99.99.99", src="10.88.88.88")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=13),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=14),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=15),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=16),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=17),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=18),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=30))

write_pcap("002-expect.pcap",
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/ICMPv6DestUnreach()/IPv6(dst="5555:5555:5555:5555:5555:5555:10.99.99.99", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")/TCP(),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/ICMPv6TimeExceeded()/IPv6(dst="5555:5555:5555:5555:5555:5555:10.99.99.99", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")/TCP(),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/ICMPv6ParamProblem(ptr=8)/IPv6(dst="5555:5555:5555:5555:5555:5555:10.99.99.99", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")/TCP())


write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/UDP(dport=50, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/UDP(dport=53, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/GRE())

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="10.88.88.88", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="10.88.88.88", ttl=63, id=0)/UDP(dport=50, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="10.88.88.88", ttl=63, id=0)/UDP(dport=53, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="10.88.88.88", ttl=63, id=0)/GRE())
