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
	return Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=100)/IP(src=_src, dst=_dst, ttl=64)

def ipv4_recv(_src, _dst):
	return Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(src=_src, dst=_dst, ttl=63)

def ipv6_send(_src, _dst):
	return Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IPv6(src=_src, dst=_dst, hlim=64, fl=0)

def ipv6_recv(_src, _dst):
	return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src=_src, dst=_dst, hlim=63, fl=0)

write_pcap("001-send.pcap",
           ipv4_send("10.0.0.3", "10.0.0.5")/TCP(dport=80, sport=(1024,1030), flags="S"),
           ipv4_send("10.1.0.5", "21.0.0.18")/TCP(dport=80, sport=1024, flags="S"),
           fragment(ipv4_send("10.0.0.5", "21.0.0.18")/TCP(dport=80, sport=1024, flags="S")/("QQQ"*400), fragsize=256),
           ipv6_send("2000::1:b", "1234::5")/UDP(dport=53, sport=(1024,1030)),
           ipv6_send("2000::cafe", "2200::beef")/TCP(dport=443, sport=1024, flags="S"),
           ipv4_send("33.33.33.33", "33.33.33.34")/TCP(flags="R"))

write_pcap("001-expect.pcap",
           ipv4_recv("10.0.0.3", "10.0.0.5")/TCP(dport=80, sport=(1024,1030), flags="S"),
           fragment(ipv4_recv("10.0.0.5", "21.0.0.18")/TCP(dport=80, sport=1024, flags="S")/("QQQ"*400), fragsize=256),
           ipv6_recv("2000::1:b", "1234::5")/UDP(dport=53, sport=(1024,1030)))
