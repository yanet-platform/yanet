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
           fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2121:bbbc:0a00:0000::11.11.11.0", src="2000::", hlim=64)/IPv6ExtHdrFragment(id=0x12345670)/TCP(dport=80, sport=2001)/("ABCDEFGH1234AAAAAAAA"*128), fragSize=1280))

write_pcap("001-expect.pcap",
           fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="2.2.2.2", ttl=63, id=0x8282)/TCP(dport=80, sport=12001)/("ABCDEFGH1234AAAAAAAA"*128), fragsize=1208))

write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="2.2.2.2", src="11.11.11.0", ttl=64, id=0xAAA0, flags="MF", frag=0)/UDP(dport=12002, sport=80, len=1536, chksum=0xe3fb)/("DEADBEAF"*63),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="2.2.2.2", src="11.11.11.0", ttl=64, id=0xAAA1, flags="MF", frag=64, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="2.2.2.2", src="11.11.11.0", ttl=64, id=0xAAA2, frag=64+64, proto=17)/("DEADBEAF"*64))


write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2121:bbbc::202:202", src="64:ff9b:1::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0xAAA00000, m=1)/UDP(dport=12002, sport=80, len=1536, chksum=0xe3fb)/("DEADBEAF"*63),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2121:bbbc::202:202", src="64:ff9b:1::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0xAAA10000, m=1, offset=64, nh=17)/("DEADBEAF"*64),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2121:bbbc::202:202", src="64:ff9b:1::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0xAAA20000, m=0, offset=64+64, nh=17)/("DEADBEAF"*64))
 
