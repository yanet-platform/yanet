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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x4)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x80)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xfc)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xff)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab01", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab01", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x4)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab01", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x80)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab01", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xfc)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab01", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xff)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab02", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab02", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x4)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab02", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x80)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab02", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xfc)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab02", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xff)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab03", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab03", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x4)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab03", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x80)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab03", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xfc)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab03", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xff)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab04", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0)/ICMP())

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x4)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x80)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0xfc)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0xff)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x28)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x4)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x80)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0xfc)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0xff)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x53)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x53)/ICMP())


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE()/IP(dst="1.2.3.0", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(chksum_present=1)/IP(dst="1.2.3.1", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(key_present=1)/IP(dst="1.2.3.2", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(seqnum_present=1)/IP(dst="1.2.3.3", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(chksum_present=1, key_present=1, seqnum_present=1)/IP(dst="1.2.3.4", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(version=1)/IP(dst="1.2.3.5", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(version=4)/IP(dst="1.2.3.6", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(flags=1)/IP(dst="1.2.3.7", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(flags=16)/IP(dst="1.2.3.8", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(recursion_control=1)/IP(dst="1.2.3.9", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(recursion_control=4)/IP(dst="1.2.3.10", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(strict_route_source=1)/IP(dst="1.2.3.11", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::", nh=47)/GRE(routing_present=1)/IP(dst="1.2.3.12", src="0.0.0.0")/ICMP())

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.0", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.2", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.3", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63)/ICMP())


write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="2000::", hlim=64)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::ab00", src="2000::", hlim=64)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=164)/TCP(dport=80, sport=2048))

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=63)/TCP(dport=80, sport=2048))


write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="2000::", hlim=64)/IP(dst="90.90.90.4", src="5.5.5.4", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="2000::", hlim=64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="2000::", hlim=64, nh=47)/GRE())

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="90.90.90.4", src="5.5.5.4", ttl=63)/TCP(dport=80, sport=2048))


write_pcap("005-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IP(dst="1.2.3.0/25", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6ExtHdrFragment(offset=0, m=0)/IP(dst="1.2.3.255", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6ExtHdrDestOpt()/IP(dst="1.2.3.254", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6ExtHdrHopByHop()/IP(dst="1.2.3.253", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6ExtHdrRouting()/IP(dst="1.2.3.252", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IP(dst="1.2.3.251", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting(nh=47)/GRE()/IP(dst="1.2.3.250", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrFragment(offset=0, m=0)/IPv6ExtHdrRouting(nh=47)/GRE()/IP(dst="1.2.3.249", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrFragment(offset=0, m=0, nh=47)/GRE()/IP(dst="1.2.3.249", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IP(dst="1.2.3.248", src="0.0.0.0", ttl=[2, 255])/ICMP())

write_pcap("005-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.0/25", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.255", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.254", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.253", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.252", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.251", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.250", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.249", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.249", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.248", src="0.0.0.0", ttl=[1, 254])/ICMP())


write_pcap("006-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IP(dst="1.1.1.1", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6ExtHdrFragment(offset=1, m=0)/IP(dst="1.1.1.1", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6ExtHdrFragment(offset=[0, 1], m=1)/IP(dst="1.1.1.1", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6()/IP(dst="1.1.1.1", src="0.0.0.0")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::ab00", src="::")/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IPv6ExtHdrDestOpt()/IPv6ExtHdrHopByHop()/IPv6ExtHdrRouting()/IP(dst="1.1.1.1", src="0.0.0.0")/ICMP())

write_pcap("006-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.1.1", src="0.0.0.0", ttl=63)/ICMP())


write_pcap("007-send.pcap",
           [Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst=f"1234::fa{ip:02x}", src="::")/IP(dst=f"1.2.3.{ip}", src="0.0.0.0", ttl=64, tos=0)/ICMP() for ip in range(256)])

write_pcap("007-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.0", src="0.0.0.0", ttl=63, tos=0)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.1", src="0.0.0.0", ttl=63, tos=0)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.2", src="0.0.0.0", ttl=63, tos=0)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.3", src="0.0.0.0", ttl=63, tos=0)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.5", src="0.0.0.0", ttl=63, tos=0)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.16/30", src="0.0.0.0", ttl=63, tos=0)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.32/30", src="0.0.0.0", ttl=63, tos=0)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.48/30", src="0.0.0.0", ttl=63, tos=0)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.64/30", src="0.0.0.0", ttl=63, tos=0)/ICMP())
