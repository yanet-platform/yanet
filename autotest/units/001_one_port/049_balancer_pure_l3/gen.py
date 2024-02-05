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


write_pcap("001-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.1", ttl=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.2", ttl=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.1", ttl=64)/UDP(dport=0, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.2", ttl=64)/UDP(dport=0, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.3", ttl=64)/UDP(dport=0, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.4", ttl=64)/UDP(dport=0, sport=12380),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64)/UDP(dport=80, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64)/UDP(dport=80, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64)/UDP(dport=80, sport=12380))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.1", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.1", ttl=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.1", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.2", ttl=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.2", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.1", ttl=64)/UDP(dport=0, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.3", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.2", ttl=64)/UDP(dport=0, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.4", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.3", ttl=64)/UDP(dport=0, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.1", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.4", ttl=64)/UDP(dport=0, sport=12380),

           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::10:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::11:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::2", src="2000:51b::10:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64)/UDP(dport=80, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::11:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64)/UDP(dport=80, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::4", src="2000:51b::12:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64)/UDP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::3", src="2000:51b::13:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64)/UDP(dport=80, sport=12380))

write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.1", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.2", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.3", ttl=64)/TCP(dport=21, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.4", ttl=64)/TCP(dport=21, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.5", ttl=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.6", ttl=64)/TCP(dport=21, sport=12380),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64)/TCP(dport=21, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64)/TCP(dport=21, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::14", hlim=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::15", hlim=64)/TCP(dport=21, sport=12380))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.1", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.1", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.1", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.2", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.2", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.3", ttl=64)/TCP(dport=21, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.4", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.4", ttl=64)/TCP(dport=21, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.4", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.5", ttl=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.3", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.6", ttl=64)/TCP(dport=21, sport=12380),

           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::10:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::11:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::2", src="2000:51b::12:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64)/TCP(dport=21, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::13:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64)/TCP(dport=21, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::4", src="2000:51b::14:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::14", hlim=64)/TCP(dport=21, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::3", src="2000:51b::15:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::15", hlim=64)/TCP(dport=21, sport=12380))


write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.1", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.2", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.3", ttl=64)/TCP(dport=19996, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.4", ttl=64)/TCP(dport=19997, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.5", ttl=64)/TCP(dport=19998, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.6", ttl=64)/TCP(dport=19999, sport=12380),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64)/TCP(dport=19996, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64)/TCP(dport=19997, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::14", hlim=64)/TCP(dport=19998, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::15", hlim=64)/TCP(dport=19999, sport=12380))

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.1", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.1", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.1", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.2", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.2", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.3", ttl=64)/TCP(dport=19996, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.4", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.4", ttl=64)/TCP(dport=19997, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.4", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.5", ttl=64)/TCP(dport=19998, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.3", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.6", ttl=64)/TCP(dport=19999, sport=12380),

           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::10:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::11:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::2", src="2000:51b::12:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64)/TCP(dport=19996, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::13:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64)/TCP(dport=19997, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::4", src="2000:51b::14:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::14", hlim=64)/TCP(dport=19998, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::3", src="2000:51b::15:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::15", hlim=64)/TCP(dport=19999, sport=12380))

write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.1", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.2", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.3", ttl=64)/TCP(dport=29996, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.4", ttl=64)/TCP(dport=29997, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.5", ttl=64)/TCP(dport=29998, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.16", src="1.1.0.6", ttl=64)/TCP(dport=29999, sport=12380),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64)/TCP(dport=29996, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64)/TCP(dport=29997, sport=12381),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::14", hlim=64)/TCP(dport=29998, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2004:dead:beef::1", src="2002::15", hlim=64)/TCP(dport=29999, sport=12380))

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.1", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.1", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.1", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.2", ttl=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.2", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.3", ttl=64)/TCP(dport=29996, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.4", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.4", ttl=64)/TCP(dport=29997, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.4", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.5", ttl=64)/TCP(dport=29998, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.3", src="100.0.0.22", ttl=63)/IP(dst="10.0.0.16", src="1.1.0.6", ttl=64)/TCP(dport=29999, sport=12380),

           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::10:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::11:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64)/TCP(dport=20, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::2", src="2000:51b::12:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64)/TCP(dport=29996, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::1", src="2000:51b::13:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64)/TCP(dport=29997, sport=12381),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::4", src="2000:51b::14:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::14", hlim=64)/TCP(dport=29998, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2006::3", src="2000:51b::15:0:1", hlim=63, fl=0)/IPv6(dst="2004:dead:beef::1", src="2002::15", hlim=64)/TCP(dport=29999, sport=12380))