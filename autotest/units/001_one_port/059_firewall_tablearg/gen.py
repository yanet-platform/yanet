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


def ipv4_send(_src, _dst):
	return Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(src=_src, dst=_dst, ttl=64)

def ipv4_recv(_src, _dst):
	return Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(src=_src, dst=_dst, ttl=63)

write_pcap("001-send.pcap",
           # :TUN64_SKP1
           ipv4_send("10.0.0.3", "213.180.192.1")/TCP(dport=443, sport=(1024,1030), flags="S"), # drop by rule 6
           ipv4_send("10.1.0.5", "213.180.223.1")/TCP(dport=80, sport=1024, flags="A"), # allow by rule 8
           # :TUN64_SKP2
           ipv4_send("10.1.1.1", "77.88.46.1")/UDP(dport=123, sport=1024), # drop by rule 18
           # :TUN64_SKP3
           ipv4_send("10.1.1.1", "213.180.207.65")/UDP(dport=(1024,1030), sport=4500), # allow by rule 26
           ipv4_send("10.0.0.3", "213.180.207.65")/TCP(dport=443, sport=1024, flags="S"), # drop by rule 30
           # :TUN64_SKP4
           ipv4_send("33.33.33.33", "213.180.207.113")/TCP(dport=8080, sport=1024, flags="R")) # allow by rule 20

write_pcap("001-expect.pcap",
           ipv4_recv("10.1.0.5", "213.180.223.1")/TCP(dport=80, sport=1024, flags="A"),
           ipv4_recv("10.1.1.1", "213.180.207.65")/UDP(dport=(1024,1030), sport=4500),
           ipv4_recv("33.33.33.33", "213.180.207.113")/TCP(dport=8080, sport=1024, flags="R"))
