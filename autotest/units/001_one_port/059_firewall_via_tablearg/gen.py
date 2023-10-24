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

def fill_ether(vlan) -> str:
    if vlan == 100:
        return "00:00:00:11:11:11"
    if vlan == 200:
        return "00:00:00:22:22:22"
    if vlan == 300:
        return "00:00:00:33:33:33"
    if vlan == 400:
        return "00:00:00:44:44:44"


def ipv4_send(_vlan, _src, _dst):
	return Ether(dst="00:11:22:33:44:55", src=fill_ether(_vlan))/Dot1Q(vlan=_vlan)/IP(src=_src, dst=_dst, ttl=64)

def ipv4_recv(_vlan, _src, _dst):
	return Ether(dst=fill_ether(_vlan), src="00:11:22:33:44:55")/Dot1Q(vlan=_vlan)/IP(src=_src, dst=_dst, ttl=63)

write_pcap("001-send.pcap",
           ipv4_send(100, "10.0.0.3", "200.0.20.123")/TCP(dport=443, sport=(1024,1030), flags="S"), # allow by rule 8
           ipv4_send(200, "10.1.0.5", "200.0.40.123")/ICMP(type=8, code=0, id=1, seq=0x0001), # allow by rule 12
           ipv4_send(100, "10.0.0.5", "200.0.20.123")/ICMP(type=8, code=0, id=1, seq=0x0001), # drop by rule 10
           ipv4_send(300, "10.1.1.1", "200.0.10.123")/UDP(dport=123, sport=1024), # allow by rule 16
           ipv4_send(400, "10.0.0.3", "200.0.30.123")/TCP(dport=443, sport=1024, flags="S"), # drop by rule 18
           ipv4_send(400, "10.1.1.1", "200.0.30.123")/UDP(dport=(1024,1030), sport=4500)) # allow by rule 20

write_pcap("001-expect.pcap",
           ipv4_recv(200, "10.0.0.3", "200.0.20.123")/TCP(dport=443, sport=(1024,1030), flags="S"),
           ipv4_recv(400, "10.1.0.5", "200.0.40.123")/ICMP(type=8, code=0, id=1, seq=0x0001),
           ipv4_recv(100, "10.1.1.1", "200.0.10.123")/UDP(dport=123, sport=1024),
           ipv4_recv(300, "10.1.1.1", "200.0.30.123")/UDP(dport=(1024,1030), sport=4500))
