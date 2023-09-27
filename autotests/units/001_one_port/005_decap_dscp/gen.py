#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *


def write_pcap(filename, *packetsList):
	PcapWriter(filename)
	for packets in packetsList:
		packets.time = 0
		wrpcap(filename, [p for p in packets], append=True)


write_pcap("send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x4)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x80)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xfc)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xff)/ICMP(),

           # MarkType = onlyDefault: replace initial first six bits of TOS with value from config if packet was not marked, otherwise keep the original mark
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x4)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x80)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xfc)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xff)/ICMP(),

           # MarkType = always: replace initial first six bits of TOS with value from config
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=102)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=102)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x4)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=102)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0x80)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=102)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xfc)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=102)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="1.2.3.4", src="0.0.0.0", ttl=64, tos=0xff)/ICMP(),

           # MarkType = always: correct checksum evaluation, correct old TOS subtraction
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=103)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="250.250.108.139", src="251.251.21.180", ttl=64, tos=0x0, id=0xc0bd, flags="DF", frag=0)/TCP(dport=4612, sport=443)/("0123456789"*141),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=103)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="250.250.108.139", src="251.251.21.180", ttl=64, tos=0x4, id=0xc0bd, flags="DF", frag=0)/TCP(dport=4712, sport=443)/("0123456789"*141),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=103)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="252.252.222.185", src="253.253.204.158", ttl=64, tos=0x8, id=0xc57a)/TCP(dport=58062, sport=443)/("0123456789"*141),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=103)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="254.254.206.37", src="253.253.204.179", ttl=64, tos=0x80, id=0x9f41)/TCP(dport=37058, sport=443)/("0123"*37),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=103)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="249.249.101.1", src="248.248.247.182", ttl=64, tos=0xfc, id=0x517e)/TCP(dport=6320, sport=443)/("123456789"*128),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=103)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="247.247.30.210", src="248.248.247.182", ttl=64, tos=0xff, id=0x264a)/TCP(dport=43010, sport=443)/("123456789"*128),

           # inverted_original_checksum < (inverted_original_checksum - original_tos), (inverted_original_checksum - original_tos) < (inverted_original_checksum - original_tos + new tos)
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=102)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="254.254.206.37", src="253.253.204.179", ttl=64, tos=0xf0, id=0x9fcc)/TCP(dport=37068, sport=443)/("01234567"*3),
           # inverted_original_checksum > (inverted_original_checksum - original_tos), (inverted_original_checksum - original_tos) > (inverted_original_checksum - original_tos + new tos)
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=103)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="254.254.206.37", src="253.253.204.179", ttl=64, tos=0x04, id=0xa050)/TCP(dport=39068, sport=443)/("01234567"*3),
           # inverted_original_checksum < (inverted_original_checksum - original_tos), (inverted_original_checksum - original_tos) > (inverted_original_checksum - original_tos + new tos)
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=103)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="254.254.206.37", src="253.253.204.179", ttl=64, tos=0xc0, id=0xa000)/TCP(dport=41068, sport=443)/("01234567"*3),
           # new tos is the same - nothing happens
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=103)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="254.254.206.37", src="253.253.204.179", ttl=64, tos=0xa0, id=0xa0bc)/TCP(dport=49068, sport=443)/("01234567"*3),

           # MarkType = onlyDefault: correct checksum evaluation, no need to subtract old DSCP (first six bits of TOS): mark packet only if it was initially unmarked
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=104)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="250.250.108.139", src="251.251.21.180", ttl=64, tos=0x0, id=0xc0bd, flags="DF", frag=0)/TCP(dport=5613, sport=443)/("0123456789"*141),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=104)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="254.254.206.37", src="253.253.204.179", ttl=64, tos=0x03, id=0x9f41)/TCP(dport=38068, sport=443)/("0123"*37))

write_pcap("expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x4)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x80)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0xfc)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0xff)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x28)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x4)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x80)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0xfc)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0xff)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x50)/ICMP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.3.4", src="0.0.0.0", ttl=63, tos=0x53)/ICMP(),

           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="250.250.108.139", src="251.251.21.180", ttl=63, tos=0xa0, id=0xc0bd, flags="DF", frag=0)/TCP(dport=4612, sport=443)/("0123456789"*141),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="250.250.108.139", src="251.251.21.180", ttl=63, tos=0xa0, id=0xc0bd, flags="DF", frag=0)/TCP(dport=4712, sport=443)/("0123456789"*141),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="252.252.222.185", src="253.253.204.158", ttl=63, tos=0xa0, id=0xc57a)/TCP(dport=58062, sport=443)/("0123456789"*141),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="254.254.206.37", src="253.253.204.179", ttl=63, tos=0xa0, id=0x9f41)/TCP(dport=37058, sport=443)/("0123"*37),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="249.249.101.1", src="248.248.247.182", ttl=63, tos=0xa0, id=0x517e)/TCP(dport=6320, sport=443)/("123456789"*128),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="247.247.30.210", src="248.248.247.182", ttl=63, tos=0xa3, id=0x264a)/TCP(dport=43010, sport=443)/("123456789"*128),

           # overflow when subtracting original tos
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="254.254.206.37", src="253.253.204.179", ttl=63, tos=0x50, id=0x9fcc)/TCP(dport=37068, sport=443)/("01234567"*3),
           # overflow when adding new tos
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="254.254.206.37", src="253.253.204.179", ttl=63, tos=0xa0, id=0xa050)/TCP(dport=39068, sport=443)/("01234567"*3),
           # overflow when subtracting original tos and when adding new tos
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="254.254.206.37", src="253.253.204.179", ttl=63, tos=0xa0, id=0xa000)/TCP(dport=41068, sport=443)/("01234567"*3),
           # new tos is the same - nothing happens
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="254.254.206.37", src="253.253.204.179", ttl=63, tos=0xa0, id=0xa0bc)/TCP(dport=49068, sport=443)/("01234567"*3),

           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="250.250.108.139", src="251.251.21.180", ttl=63, tos=0xa0, id=0xc0bd, flags="DF", frag=0)/TCP(dport=5613, sport=443)/("0123456789"*141),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="254.254.206.37", src="253.253.204.179", ttl=63, tos=0xa3, id=0x9f41)/TCP(dport=38068, sport=443)/("0123"*37))

# trying to catch incorrect checksums
# PcapWriter("send_many.pcap")
# dscp = 0x04
# for i in range(0, 65536):
#         packet = Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=103)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="250.250.108.139", src="251.251.21.180", ttl=64, tos=dscp, id=i, flags="DF", frag=0)/TCP(dport=i, sport=440+dscp)/("0123456789"*141)
#         packet.time = 0
#         wrpcap("send_many.pcap", packet, append=True)

#         packet = Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=102)/IPv6(dst="1:2:3:4::abcd", src="::")/IP(dst="250.250.108.139", src="251.251.21.180", ttl=64, tos=0xf0, id=i, flags="DF", frag=0)/TCP(dport=i, sport=430)/("0123456789"*141)
#         packet.time = 0
#         wrpcap("send_many.pcap", packet, append=True)

# PcapWriter("expect_many.pcap")
# for i in range(0, 65536):
#         packet = Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="250.250.108.139", src="251.251.21.180", ttl=63, tos=0xa0, id=i, flags="DF", frag=0)/TCP(dport=i, sport=440+dscp)/("0123456789"*141)
#         packet.time = 0
#         wrpcap("expect_many.pcap", packet, append=True)

#         packet = Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="250.250.108.139", src="251.251.21.180", ttl=63, tos=0x50, id=i, flags="DF", frag=0)/TCP(dport=i, sport=430)/("0123456789"*141)
#         packet.time = 0
#         wrpcap("expect_many.pcap", packet, append=True)
