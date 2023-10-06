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

def ipv4_send(_src, _dst):
	return Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(src=_src, dst=_dst, ttl=64)

def ipv4_recv(_src, _dst):
	return Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(src=_src, dst=_dst, ttl=63)

def ipv6_send(_src, _dst):
	return Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(src=_src, dst=_dst, hlim=64, fl=0)

def ipv6_recv(_src, _dst):
	return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src=_src, dst=_dst, hlim=63, fl=0)

write_pcap("001-send.pcap",
           ipv4_send("10.0.0.3", "10.0.0.55")/TCP(dport=80, sport=(1024,1040), flags="S"),
           ipv4_send("10.1.0.5", "21.0.0.18")/TCP(dport=80, sport=1024, flags="S"),
           fragment(ipv4_send("10.1.0.5", "21.0.0.18")/TCP(dport=80, sport=1024, flags="S")/("QQQ"*400), fragsize=256),
           ipv4_send("10.1.0.5", "10.0.0.18")/ICMP(type=10),
           fragment(ipv4_send("10.2.0.5", "10.0.0.18")/ICMP(type=10)/("."*192), fragsize=128),
           ipv4_send("33.33.33.33", "33.33.33.34")/TCP(flags="A"),
           ipv4_send("33.33.33.33", "33.33.33.34")/TCP(flags="R"))

write_pcap("001-expect.pcap",
           ipv4_recv("10.0.0.3", "10.0.0.55")/TCP(dport=80, sport=(1024,1040), flags="S"),
           ipv4_recv("10.1.0.5", "21.0.0.18")/TCP(dport=80, sport=1024, flags="S"),
           fragment(ipv4_recv("10.1.0.5", "21.0.0.18")/TCP(dport=80, sport=1024, flags="S")/("QQQ"*400), fragsize=256)[0],
           ipv4_recv("10.1.0.5", "10.0.0.18")/ICMP(type=10),
           fragment(ipv4_recv("10.2.0.5", "10.0.0.18")/ICMP(type=10)/("."*192), fragsize=128)[1],
           ipv4_recv("33.33.33.33", "33.33.33.34")/TCP(flags="A"),
           ipv4_recv("33.33.33.33", "33.33.33.34")/TCP(flags="R"))

write_pcap("002-send.pcap",
           ipv4_send("10.0.0.3", "10.0.0.55")/TCP(dport=81, sport=(1024,1040)),
           ipv4_send("10.1.0.5", "21.0.0.18")/TCP(dport=(80,85), sport=5024),
           ipv4_send("10.2.0.5", "10.0.0.18")/ICMP(type=10),
           ipv4_send("20.0.0.1", "21.0.0.18")/TCP(flags="S"),
           ipv4_recv("33.33.33.33", "33.33.33.34")/TCP(flags="S"))

write_pcap("002-expect.pcap")

write_pcap("003-send.pcap",
           ipv6_send("2000::1:b", "2000::1:bc")/UDP(dport=53, sport=(1024,1040)),
           ipv6_send("2000::b", "2200::1:bc")/UDP(dport=53, sport=53),
           fragment6(ipv6_send("2000::b", "2200::1:bc")/IPv6ExtHdrFragment(id=0x12345678)/UDP(dport=53, sport=53)/("ABCD"*1000), fragSize=1280),
           ipv6_send("2222::a", "2000::1")/ICMPv6DestUnreach(code=0),
           ipv6_send("3456::a", "3456::b")/TCP(flags="A"),
           ipv6_send("3456::a", "3456::b")/TCP(flags="R"),
           ipv6_send("2300::1", "2300::b")/TCP(flags="S"),
           ipv6_send("2301::1", "2301::b")/TCP(flags="FR"))

write_pcap("003-expect.pcap",
           ipv6_recv("2000::1:b", "2000::1:bc")/UDP(dport=53, sport=(1024,1040)),
           ipv6_recv("2000::b", "2200::1:bc")/UDP(dport=53, sport=53),
           fragment6(ipv6_recv("2000::b", "2200::1:bc")/IPv6ExtHdrFragment(id=0x12345678)/UDP(dport=53, sport=53)/("ABCD"*1000), fragSize=1280)[0],
           ipv6_recv("2222::a", "2000::1")/ICMPv6DestUnreach(code=0),
           ipv6_recv("3456::a", "3456::b")/TCP(flags="A"),
           ipv6_recv("3456::a", "3456::b")/TCP(flags="R"),
           ipv6_recv("2300::1", "2300::b")/TCP(flags="S"),
           ipv6_recv("2301::1", "2301::b")/TCP(flags="FR"))

write_pcap("004-send.pcap",
           ipv6_send("2000::1:b", "2000::1:bc")/UDP(dport=55, sport=(1024,1040)),
           ipv6_send("2000::b", "2200::1:bc")/UDP(dport=53, sport=55),
           ipv6_send("2200::a", "2000::1")/ICMPv6DestUnreach(code=0),
           ipv6_send("2300::1", "2300::b")/TCP(flags="RPU"),
           ipv6_send("2301::1", "2301::b")/TCP(flags="UF"))

write_pcap("004-expect.pcap")
