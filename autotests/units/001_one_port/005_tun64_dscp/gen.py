#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *


def write_pcap(filename, *packetsList):
	PcapWriter(filename)
	for packets in packetsList:
		packets.time = 0
		wrpcap(filename, [p for p in packets], append=True)

write_pcap("decap.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="8.8.8.8", src="55.55.205.4", ttl=64, tos=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="8.8.8.8", src="55.55.205.4", ttl=64, tos=0x4)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="8.8.8.8", src="55.55.205.4", ttl=64, tos=0x80)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="8.8.8.8", src="55.55.205.4", ttl=64, tos=0xfc)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="8.8.8.8", src="55.55.205.4", ttl=64, tos=0xff)/UDP(dport=2048, sport=443),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=300)/IPv6(dst="2000:123:b2b2:b0ff::2", src="2000:123:b3b3:1:2:3:4:5")/IP(dst="8.8.8.8", src="55.66.206.4", ttl=64, tos=0)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=300)/IPv6(dst="2000:123:b2b2:b0ff::2", src="2000:123:b3b3:1:2:3:4:5")/IP(dst="8.8.8.8", src="55.66.206.4", ttl=64, tos=0x4)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=300)/IPv6(dst="2000:123:b2b2:b0ff::2", src="2000:123:b3b3:1:2:3:4:5")/IP(dst="8.8.8.8", src="55.66.206.4", ttl=64, tos=0x80)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=300)/IPv6(dst="2000:123:b2b2:b0ff::2", src="2000:123:b3b3:1:2:3:4:5")/IP(dst="8.8.8.8", src="55.66.206.4", ttl=64, tos=0xfc)/UDP(dport=2048, sport=443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=300)/IPv6(dst="2000:123:b2b2:b0ff::2", src="2000:123:b3b3:1:2:3:4:5")/IP(dst="8.8.8.8", src="55.66.206.4", ttl=64, tos=0xff)/UDP(dport=2048, sport=443),

           # MarkType = always: correct checksum evaluation, correct old TOS subtraction
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="108.108.108.139", src="55.55.205.4", ttl=64, tos=0x0, id=0x5598, flags="DF", frag=0)/TCP(dport=4612, sport=443)/("0123456789"*141),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="108.108.108.139", src="55.55.205.4", ttl=64, tos=0x4, id=0x5598, flags="DF", frag=0)/TCP(dport=4712, sport=443)/("0123456789"*141),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="109.109.222.185", src="55.55.205.4", ttl=64, tos=0x8, id=0x999c)/TCP(dport=58062, sport=443)/("0123456789"*141),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="110.110.206.37", src="55.55.205.4", ttl=64, tos=0x80, id=0x7378)/TCP(dport=37058, sport=443)/("0123"*37),

           # MarkType = onlyDefault: correct checksum evaluation, no need to subtract old DSCP (first six bits of TOS): mark packet only if it was initially unmarked
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=301)/IPv6(dst="2000:123:b2b2:b0ff::2", src="2000:123:b3b3:1:2:3:4:5")/IP(dst="108.108.108.139", src="55.66.206.4", ttl=64, tos=0x0, id=0x4b98, flags="DF", frag=0)/TCP(dport=5613, sport=443)/("0123456789"*141),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=301)/IPv6(dst="2000:123:b2b2:b0ff::2", src="2000:123:b3b3:1:2:3:4:5")/IP(dst="110.110.206.37", src="55.66.206.4", ttl=64, tos=0x03, id=0x6975)/TCP(dport=38068, sport=443)/("0123"*37),

           # inverted_original_checksum < (inverted_original_checksum - original_tos), (inverted_original_checksum - original_tos) < (inverted_original_checksum - original_tos + new tos)
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="110.110.206.37", src="55.55.205.4", ttl=64, tos=0xf0, id=0x7403)/TCP(dport=37068, sport=443)/("01234567"*3),
           # inverted_original_checksum > (inverted_original_checksum - original_tos), (inverted_original_checksum - original_tos) > (inverted_original_checksum - original_tos + new tos)
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="110.110.206.37", src="55.55.205.4", ttl=64, tos=0x04, id=0x7487)/TCP(dport=39068, sport=443)/("01234567"*3),
           # inverted_original_checksum < (inverted_original_checksum - original_tos), (inverted_original_checksum - original_tos) > (inverted_original_checksum - original_tos + new tos)
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="110.110.206.37", src="55.55.205.4", ttl=64, tos=0xc0, id=0x7437)/TCP(dport=41068, sport=443)/("01234567"*3),
           # new tos is the same - nothing happens
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=101)/IPv6(dst="2000:123:b0b0:a0ff::1", src="2000:123:b1b:4:10:11:0:661c")/IP(dst="110.110.206.37", src="55.55.205.4", ttl=64, tos=0xa0, id=0x74f3)/TCP(dport=49068, sport=443)/("01234567"*3))

write_pcap("decap_expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="55.55.205.4", ttl=63, tos=0x50)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="55.55.205.4", ttl=63, tos=0x50)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="55.55.205.4", ttl=63, tos=0x50)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="55.55.205.4", ttl=63, tos=0x50)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="55.55.205.4", ttl=63, tos=0x53)/UDP(dport=2048, sport=443),
           
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="55.66.206.4", ttl=63, tos=0x28)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="55.66.206.4", ttl=63, tos=0x4)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="55.66.206.4", ttl=63, tos=0x80)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="55.66.206.4", ttl=63, tos=0xfc)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="55.66.206.4", ttl=63, tos=0xff)/UDP(dport=2048, sport=443),

           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="108.108.108.139", src="55.55.205.4", ttl=63, tos=0xa0, id=0x5598, flags="DF", frag=0)/TCP(dport=4612, sport=443)/("0123456789"*141),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="108.108.108.139", src="55.55.205.4", ttl=63, tos=0xa0, id=0x5598, flags="DF", frag=0)/TCP(dport=4712, sport=443)/("0123456789"*141),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="109.109.222.185", src="55.55.205.4", ttl=63, tos=0xa0, id=0x999c)/TCP(dport=58062, sport=443)/("0123456789"*141),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="110.110.206.37", src="55.55.205.4", ttl=63, tos=0xa0, id=0x7378)/TCP(dport=37058, sport=443)/("0123"*37),

           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="108.108.108.139", src="55.66.206.4", ttl=63, tos=0xa0, id=0x4b98, flags="DF", frag=0)/TCP(dport=5613, sport=443)/("0123456789"*141),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="110.110.206.37", src="55.66.206.4", ttl=63, tos=0xa3, id=0x6975)/TCP(dport=38068, sport=443)/("0123"*37),

           # overflow when subtracting original tos
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="110.110.206.37", src="55.55.205.4", ttl=63, tos=0x50, id=0x7403)/TCP(dport=37068, sport=443)/("01234567"*3),
           # overflow when adding new tos
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="110.110.206.37", src="55.55.205.4", ttl=63, tos=0xa0, id=0x7487)/TCP(dport=39068, sport=443)/("01234567"*3),
           # overflow when subtracting original tos and when adding new tos
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="110.110.206.37", src="55.55.205.4", ttl=63, tos=0xa0, id=0x7437)/TCP(dport=41068, sport=443)/("01234567"*3),
           # new tos is the same - nothing happens
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="110.110.206.37", src="55.55.205.4", ttl=63, tos=0xa0, id=0x74f3)/TCP(dport=49068, sport=443)/("01234567"*3))
