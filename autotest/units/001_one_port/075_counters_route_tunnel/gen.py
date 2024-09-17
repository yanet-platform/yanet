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


write_pcap("001-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::2", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::3", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::4", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::5", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::6", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::7", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::8", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::9", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::10", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::11", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::12", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::13", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::14", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::15", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::16", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP())

write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=2)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=3)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=4)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=5)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=6)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=7)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=8)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=9)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=10)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=11)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=12)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=13)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=14)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=15)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=16)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x89ed | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x2355 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x9b9f | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x3127 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xb81e | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x12a6 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xc98a | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x6332 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xea0b | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x40b3 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xf879 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x52c1 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xdbf8 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x7140 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x1b51 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP())


