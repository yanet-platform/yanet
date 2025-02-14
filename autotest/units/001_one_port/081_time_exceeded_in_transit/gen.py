#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.contrib.mpls import MPLS


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


def ipv6_send(_src, _dst):
	return Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(src=_src, dst=_dst, hlim=64, fl=0)

def ipv6_recv(_src, _dst):
	return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src=_src, dst=_dst, hlim=63, fl=0)

write_pcap("001-send.pcap",
		# Checking the operation of the main flow
		# ttl=63
        Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IP(src="10.0.0.3", dst="10.0.0.55", ttl=64)/TCP(dport=80, sport=1024, flags=""),
		Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(src="2000::1:b", dst="2000::1:bc", hlim=64, fl=0)/UDP(dport=53, sport=1024),
		# ttl=2
		Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IP(src="10.0.0.3", dst="10.0.0.55", ttl=2)/TCP(dport=80, sport=1024, flags=""),
		Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(src="2000::1:b", dst="2000::1:bc", hlim=2, fl=0)/UDP(dport=53, sport=1024),
		#Checking the creation of an icmp response
		# ttl=0
		Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IP(src="10.0.0.3", dst="10.0.0.55", ttl=0)/TCP(dport=80, sport=1024, flags=""),
		Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(src="3456::a", dst="3456::b", hlim=0, fl=0)/TCP(dport=80, sport=1024, flags=""),
		# ttl=1
		Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IP(src="10.0.0.3", dst="10.0.0.55", ttl=1)/TCP(dport=80, sport=1024, flags=""),
		Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(src="3456::a", dst="3456::b", hlim=1, fl=0)/TCP(dport=80, sport=1024, flags=""),
		# Checking the response limitation for ipv6 (max size of ipv6 package by RFC 4443 - 1280 byte )
		Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(src="3456::a", dst="3456::b", hlim=1, fl=0)/TCP(dport=80, sport=1024, flags="")/("X"*1500))

write_pcap("001-expect.pcap",
        Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(src="10.0.0.3", dst="10.0.0.55", ttl=63)/TCP(dport=80, sport=1024, flags=""),
		Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src="2000::1:b", dst="2000::1:bc", hlim=63, fl=0)/UDP(dport=53, sport=1024),
		Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(src="10.0.0.3", dst="10.0.0.55", ttl=1)/TCP(dport=80, sport=1024, flags=""),
		Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src="2000::1:b", dst="2000::1:bc", hlim=1, fl=0)/UDP(dport=53, sport=1024),
		Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(src="10.0.0.55", dst="10.0.0.3", ttl=127)/ICMP(type = 11, code =0)/raw(IP(src="10.0.0.3", dst="10.0.0.55", ttl=0)/TCP(dport=80, sport=1024))[:28],
		Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src="3456::b", dst="3456::a", hlim=127, fl=0)/ICMPv6TimeExceeded()/raw(IPv6(src="3456::a", dst="3456::b", hlim=0, fl=0)/TCP(dport=80, sport=1024, flags="")),
		Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(src="10.0.0.55", dst="10.0.0.3", ttl=127)/ICMP(type = 11, code =0)/raw(IP(src="10.0.0.3", dst="10.0.0.55", ttl=1)/TCP(dport=80, sport=1024))[:28],
		Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src="3456::b", dst="3456::a", hlim=127, fl=0)/ICMPv6TimeExceeded()/raw(IPv6(src="3456::a", dst="3456::b", hlim=1, fl=0)/TCP(dport=80, sport=1024, flags="")),
		Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src="3456::b", dst="3456::a", hlim=127, fl=0)/ICMPv6TimeExceeded()/raw(IPv6(src="3456::a", dst="3456::b", hlim=1, fl=0)/TCP(dport=80, sport=1024, flags="")/("X"*1500))[:1232])


write_pcap("002-send.pcap",
		# Checking show real ip
		Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IP(src="10.0.0.3", dst="10.0.0.55", ttl=1)/TCP(dport=80, sport=1024, flags=""),
		Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(src="3456::a", dst="3456::b", hlim=1, fl=0)/TCP(dport=80, sport=1024, flags=""))

write_pcap("002-expect.pcap",
		Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(src="10.0.0.10", dst="10.0.0.3", ttl=127)/ICMP(type = 11, code =0)/raw(IP(src="10.0.0.3", dst="10.0.0.55", ttl=1)/TCP(dport=80, sport=1024))[:28],
		Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src="3456::c", dst="3456::a", hlim=127, fl=0)/ICMPv6TimeExceeded()/raw(IPv6(src="3456::a", dst="3456::b", hlim=1, fl=0)/TCP(dport=80, sport=1024, flags="")))
