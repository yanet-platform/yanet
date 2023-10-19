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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::aaaa", src="::1")/IP(dst="4.4.4.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::aaaa", src="::2")/IP(dst="4.4.4.2", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::aaaa", src="::3")/IP(dst="4.4.4.3", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::aaaa", src="::4")/IP(dst="4.4.4.4", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::aaaa", src="::1", fl=1)/IP(dst="4.4.4.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::aaaa", src="::2", fl=2)/IP(dst="4.4.4.2", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::aaaa", src="::3", fl=3)/IP(dst="4.4.4.3", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::aaaa", src="::4", fl=4)/IP(dst="4.4.4.4", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="4.4.4.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.2", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.3", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="4.4.4.4", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="4.4.4.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.2", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.3", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="4.4.4.4", src="0.0.0.0", ttl=63)/ICMP())


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IP(dst="4.4.4.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::2")/IP(dst="4.4.4.2", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::3")/IP(dst="4.4.4.3", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::4")/IP(dst="4.4.4.4", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="4.4.4.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::2", fl=2)/IP(dst="4.4.4.2", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::3", fl=3)/IP(dst="4.4.4.3", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::4", fl=4)/IP(dst="4.4.4.4", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.2", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.3", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="4.4.4.4", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="4.4.4.2", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="4.4.4.3", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="0.0.0.0", ttl=63)/ICMP())


write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::2")/IP(dst="1.0.0.2", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::3")/IP(dst="1.0.0.3", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::4")/IP(dst="1.0.0.4", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::2", fl=2)/IP(dst="1.0.0.2", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::3", fl=3)/IP(dst="1.0.0.3", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::4", fl=4)/IP(dst="1.0.0.4", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::5", fl=5)/IP(dst="1.0.0.5", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::6", fl=6)/IP(dst="1.0.0.6", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::7", fl=7)/IP(dst="1.0.0.7", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::8", fl=8)/IP(dst="1.0.0.8", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xaa6c | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xdf34 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.2", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xf3fc | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.3", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x4375 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.4", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xfcb5 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.2", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x7ac5 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.3", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x7286 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.4", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xf4f6 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.5", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x0897 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.6", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x8ee7 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.7", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x1811 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.8", src="0.0.0.0", ttl=63)/ICMP())


write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::11")/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::12")/IP(dst="1.0.0.2", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::13")/IP(dst="1.0.0.3", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::14")/IP(dst="1.0.0.4", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::11", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::12", fl=2)/IP(dst="1.0.0.2", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::13", fl=3)/IP(dst="1.0.0.3", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::14", fl=4)/IP(dst="1.0.0.4", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::15", fl=5)/IP(dst="1.0.0.5", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::16", fl=6)/IP(dst="1.0.0.6", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::17", fl=7)/IP(dst="1.0.0.7", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::18", fl=8)/IP(dst="1.0.0.8", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xaa6c | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xdf34 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.2", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xf3fc | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.3", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x4375 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.4", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xfcb5 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.2", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x7ac5 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.3", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x7286 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.4", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xf4f6 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.5", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x0897 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.6", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x8ee7 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.7", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x1811 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.8", src="0.0.0.0", ttl=63)/ICMP())


write_pcap("005-send.pcap",
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

write_pcap("005-expect.pcap",
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


write_pcap("006-send.pcap",
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

write_pcap("006-expect.pcap",
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


write_pcap("007-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.2", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.3", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.4", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.5", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.6", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.7", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.8", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.9", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.10", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.11", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.12", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.13", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.14", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.15", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.16", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("007-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x00d4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x758c | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.2", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x5944 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.3", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xe9cd | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.4", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xc505 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.5", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xb05d | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.6", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x9c95 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.7", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xd14f | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.8", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xfd87 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.9", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x88df | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.10", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xa417 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.11", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x149e | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.12", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x3856 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.13", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x4d0e | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.14", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x61c6 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.15", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xd6ba | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.16", src="0.0.0.0", ttl=63)/ICMP())


# IPv6

write_pcap("008-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="de::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::2")/IPv6(dst="de::2", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::3")/IPv6(dst="de::3", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::4")/IPv6(dst="de::4", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="de::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::2", fl=2)/IPv6(dst="de::2", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::3", fl=3)/IPv6(dst="de::3", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::4", fl=4)/IPv6(dst="de::4", src="::", hlim=64, fl=100)/ICMP())

write_pcap("008-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="de::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="de::2", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="de::3", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="de::4", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="de::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="de::2", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="de::3", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="de::4", src="::", hlim=63, fl=100)/ICMP())


write_pcap("009-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=101)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::2", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=102)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::3", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=103)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::4", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=104)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::5", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=105)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::6", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=106)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::7", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=107)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::8", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=108)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::9", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=109)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::10", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=110)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::11", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=111)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::12", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=112)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::13", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=113)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::14", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=114)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::15", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=115)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::16", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=116)/ICMP())

write_pcap("009-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=101)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=102)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=103)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=104)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=105)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=106)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=107)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=108)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=109)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=110)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=111)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=112)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=113)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=114)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=115)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=116)/ICMP())


write_pcap("010-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=2)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=3)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=4)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=5)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=6)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=7)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=8)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=9)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=10)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=11)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=12)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=13)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=14)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=15)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=16)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP())

write_pcap("010-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xf3a1 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x5919 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xe1d3 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x4b6b | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xc252 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x68ea | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xb3c6 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x197e | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x9047 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x3aff | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x8235 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x288d | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xa1b4 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x0b0c | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x611d | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP())


write_pcap("011-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::1", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::2", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::3", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::4", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::5", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::6", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::7", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::8", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::9", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::10", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::11", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::12", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::13", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::14", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::15", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::16", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::18", src="::", hlim=64, fl=100)/ICMP())

write_pcap("011-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7a98 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::1", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xca6c | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::2", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xa5c0 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::3", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xab84 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::4", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xc428 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::5", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x74dc | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::6", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x1b70 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::7", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x1ea5 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::8", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::1", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7109 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e57::9", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x74e7 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::10", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x1b4b | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::11", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xabbf | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::12", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xc413 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::13", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xca57 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::14", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xa5fb | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::15", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x150f | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::16", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0x7f76 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::18", src="::", hlim=63, fl=100)/ICMP())


# local prefixes

write_pcap("012-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.255", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=2)/IP(dst="1.0.0.255", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("012-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.255", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.0.0.255", src="0.0.0.0", ttl=63)/ICMP())


write_pcap("013-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::ffff", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=2)/IPv6(dst="7e57::ffff", src="::", hlim=64, fl=100)/ICMP())

write_pcap("013-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="7e57::ffff", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e57::ffff", src="::", hlim=63, fl=100)/ICMP())


# peer_id < 1000

write_pcap("014-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.254", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=2)/IP(dst="1.0.0.254", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("014-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xfd9b, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.254", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xf4a2, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.254", src="0.0.0.0", ttl=63)/ICMP())


write_pcap("015-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::fffe", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=2)/IPv6(dst="7e57::fffe", src="::", hlim=64, fl=100)/ICMP())

write_pcap("015-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xfa07, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::fffe", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xf33e, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::fffe", src="::", hlim=63, fl=100)/ICMP())


# weight == 0

write_pcap("016-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.253", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=2)/IP(dst="1.0.0.253", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("016-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xc8c3, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.253", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xc1fa, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.253", src="0.0.0.0", ttl=63)/ICMP())


write_pcap("017-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::fffd", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=2)/IPv6(dst="7e57::fffd", src="::", hlim=64, fl=100)/ICMP())

write_pcap("017-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xcaf3, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::fffd", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xc3ca, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::fffd", src="::", hlim=63, fl=100)/ICMP())


# large_community not set

write_pcap("018-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IP(dst="1.0.0.252", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=2)/IP(dst="1.0.0.252", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("018-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xe40b, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.252", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0xed32, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.252", src="0.0.0.0", ttl=63)/ICMP())


write_pcap("019-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=1)/IPv6(dst="7e57::fffc", src="::", hlim=64, fl=100)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1", fl=2)/IPv6(dst="7e57::fffc", src="::", hlim=64, fl=100)/ICMP())

write_pcap("019-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xe55f, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::fffc", src="::", hlim=63, fl=100)/ICMP(),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::2", src="2222:1111:0:1234:5678:0101:ca11:ca11", hlim=64)/UDP(dport=6635, sport=0xec66, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e57::fffc", src="::", hlim=63, fl=100)/ICMP())
