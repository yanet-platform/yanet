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
           fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::", hlim=64)/IPv6ExtHdrFragment(id=0x12345670)/TCP(dport=80, sport=2001)/("ABCDEFGH1234AAAAAAAA"*128), fragSize=1280),
           list(reversed(fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::", hlim=64)/IPv6ExtHdrFragment(id=0x12345671)/TCP(dport=80, sport=2005)/("ABCDEFGH1234DDDDDDDD"*128), fragSize=1280))),

           fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::1", hlim=64)/IPv6ExtHdrFragment(id=0x12345672)/UDP(dport=80, sport=2002)/("ABCDEFGH1234BBBBBBBB"*128), fragSize=1280),
           list(reversed(fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::1", hlim=64)/IPv6ExtHdrFragment(id=0x12345673)/UDP(dport=80, sport=2006)/("ABCDEFGH1234EEEEEEEE"*128), fragSize=1280))),

           fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x12345674)/ICMPv6EchoRequest(id=2003)/("ABCDEFGH123CCCCCCCCC"*128), fragSize=1280),
           list(reversed(fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x12345675)/ICMPv6EchoRequest(id=2007)/("ABCDEFGH1234FFFFFFFF"*128), fragSize=1280))))

write_pcap("001-expect.pcap",
           fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0x8282)/TCP(dport=80, sport=12001)/("ABCDEFGH1234AAAAAAAA"*128), fragsize=1208),
           list(reversed(fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0x8101)/TCP(dport=80, sport=12013)/("ABCDEFGH1234DDDDDDDD"*128), fragsize=1208))),

           fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0x75f2)/UDP(dport=80, sport=12006)/("ABCDEFGH1234BBBBBBBB"*128), fragsize=1208),
           list(reversed(fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0x7671)/UDP(dport=80, sport=12018)/("ABCDEFGH1234EEEEEEEE"*128), fragsize=1208))),

           fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0x9d15)/ICMP(type=8, id=12011)/("ABCDEFGH123CCCCCCCCC"*128), fragsize=1208),
           fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0x9e96)/ICMP(type=8, id=12023)/("ABCDEFGH1234FFFFFFFF"*128), fragsize=1208))


write_pcap("002-send.pcap",
           fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0x1111)/TCP(dport=12002, sport=80)/("ABCDEFGH1234AAAAAAAA"*128), fragsize=1208),
           list(reversed(fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0x2222)/TCP(dport=12014, sport=80)/("ABCDEFGH1234DDDDDDDD"*128), fragsize=1208))),

           fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0x3333)/UDP(dport=12007, sport=80)/("ABCDEFGH1234BBBBBBBB"*128), fragsize=1208),
           list(reversed(fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0x4444)/UDP(dport=12019, sport=80)/("ABCDEFGH1234EEEEEEEE"*128), fragsize=1208))),

           fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0x5555)/ICMP(type=0, id=12012)/("ABCDEFGH123CCCCCCCCC"*128), fragsize=1208),
           list(reversed(fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0x6666)/ICMP(type=0, id=12024)/("ABCDEFGH1234FFFFFFFF"*128), fragsize=1208))))

write_pcap("002-expect.pcap",
           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0x11110000)/TCP(dport=2002, sport=80)/("ABCDEFGH1234AAAAAAAA"*128), fragSize=1280),
           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0x22220000)/TCP(dport=2006, sport=80)/("ABCDEFGH1234DDDDDDDD"*128), fragSize=1280),

           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0x33330000)/UDP(dport=2003, sport=80)/("ABCDEFGH1234BBBBBBBB"*128), fragSize=1280),
           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0x44440000)/UDP(dport=2007, sport=80)/("ABCDEFGH1234EEEEEEEE"*128), fragSize=1280),

           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0x55550000)/ICMPv6EchoReply(id=2004)/("ABCDEFGH123CCCCCCCCC"*128), fragSize=1280),
           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0x66660000)/ICMPv6EchoReply(id=2008)/("ABCDEFGH1234FFFFFFFF"*128), fragSize=1280))


write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA0, m=1)/ICMPv6EchoRequest(id=2001, cksum=0x2cc6)/("1BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA0, m=1, offset=84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA0, m=0, offset=84+84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA1, m=1)/ICMPv6EchoRequest(id=2002)/("2BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA1, m=1, offset=84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA1, m=1, offset=84+84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA2, m=1)/ICMPv6EchoRequest(id=2003)/("3BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA2, m=1, offset=83, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*40),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA2, m=0, offset=84+84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA3, m=1)/ICMPv6EchoRequest(id=2004)/("4BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA3, m=1, offset=85, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*40),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA3, m=0, offset=84+84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA4, m=1)/ICMPv6EchoRequest(id=2001)/("5BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA4, m=1, offset=84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA4, m=0, offset=84+83, nh=58)/("ABCDEFGH1234AAAAAAAA"*32),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA5, m=1)/ICMPv6EchoRequest(id=2002)/("6BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA5, m=1, offset=84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA5, m=0, offset=84+85, nh=58)/("ABCDEFGH1234AAAAAAAA"*32),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA6, m=1)/ICMPv6EchoRequest(id=2003, cksum=0x6cc3)/("7BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA6, m=1, offset=84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA6, m=1, offset=84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA6, m=0, offset=84+84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA7, m=1)/ICMPv6EchoRequest(id=2004, cksum=0x4cc2)/("8BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA7, m=1, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA7, m=1, offset=84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA7, m=0, offset=84+84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA8, m=1)/ICMPv6EchoRequest(id=2001)/("9BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA8, m=1, offset=84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234AAA9, m=0, offset=84+84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234FFF0, m=1)/ICMPv6EchoRequest(id=2002, cksum=0x4cc5)/("0BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234FFF0, m=1, offset=84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::2", hlim=64)/IPv6ExtHdrFragment(id=0x1234FFF0, m=0, offset=84+84, nh=58)/("ABCDEFGH1234AAAAAAAA"*32))

write_pcap("003-expect.pcap",
           fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0x33ef)/ICMP(type=8, id=12009)/("1BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III"/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32)/("ABCDEFGH1234AAAAAAAA"*32), fragsize=672),
           fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0xdb08)/ICMP(type=8, id=12011)/("7BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III"/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32)/("ABCDEFGH1234AAAAAAAA"*32), fragsize=672),
           fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0xd88b)/ICMP(type=8, id=12012)/("8BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III"/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32)/("ABCDEFGH1234AAAAAAAA"*32), fragsize=672),
           fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0xcefb)/ICMP(type=8, id=12010)/("0BCDEFGH1234AAAAAAAA"*32)/"   voevat'-masterit' III"/("ABCDEFGH1234AAAAAAAA"*32)/(" "*32)/("ABCDEFGH1234AAAAAAAA"*32), fragsize=672))


write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA0, flags="MF", frag=0)/UDP(dport=12002, sport=80, len=1536, chksum=0xddff)/("DEADBEAF"*63),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA0, flags="MF", frag=64, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA0, flags="", frag=64+64, proto=17)/("DEADBEAF"*64),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA1, flags="MF", frag=0)/UDP(dport=12002, sport=80, len=1536, chksum=0xddff)/("DEADBEAF"*63),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA1, flags="MF", frag=64, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA1, flags="MF", frag=64+64, proto=17)/("DEADBEAF"*64),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA2, flags="MF", frag=0)/UDP(dport=12002, sport=80, len=1536, chksum=0xddff)/("DEADBEAF"*63),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA2, flags="MF", frag=63, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA2, flags="", frag=64+64, proto=17)/("DEADBEAF"*64),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA3, flags="MF", frag=0)/UDP(dport=12002, sport=80, len=1536, chksum=0xddff)/("DEADBEAF"*63),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA3, flags="MF", frag=65, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA3, flags="", frag=64+64, proto=17)/("DEADBEAF"*64),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA4, flags="MF", frag=0)/UDP(dport=12002, sport=80, len=1536, chksum=0xddff)/("DEADBEAF"*63),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA4, flags="MF", frag=64, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA4, flags="", frag=64+63, proto=17)/("DEADBEAF"*64),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA5, flags="MF", frag=0)/UDP(dport=12002, sport=80, len=1536, chksum=0xddff)/("DEADBEAF"*63),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA5, flags="MF", frag=64, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA5, flags="", frag=64+65, proto=17)/("DEADBEAF"*64),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA6, flags="MF", frag=0)/UDP(dport=12002, sport=80, len=1536, chksum=0xddff)/("DEADBEAF"*63),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA6, flags="MF", frag=64, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA6, flags="MF", frag=64, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA6, flags="", frag=64+64, proto=17)/("DEADBEAF"*64),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA7, flags="MF", frag=0)/UDP(dport=12002, sport=80, len=1536, chksum=0xddff)/("DEADBEAF"*63),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA7, flags="MF", frag=0, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA7, flags="MF", frag=64, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA7, flags="", frag=64+64, proto=17)/("DEADBEAF"*64),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA8, flags="MF", frag=0)/UDP(dport=12002, sport=80, len=1536, chksum=0xddff)/("DEADBEAF"*63),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA8, flags="MF", frag=64, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xAAA9, flags="", frag=64+64, proto=17)/("DEADBEAF"*64),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xFFF0, flags="MF", frag=0)/UDP(dport=12002, sport=80, len=1536, chksum=0xddff)/("DEADBEAF"*63),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xFFF0, flags="MF", frag=64, proto=17)/("DEADBEAF"*64),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xFFF0, flags="", frag=64+64, proto=17)/("DEADBEAF"*64))

write_pcap("004-expect.pcap",
           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0xAAA00000)/UDP(dport=2002, sport=80)/("DEADBEAF"*(63+64+64)), fragSize=584),
           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0xAAA60000)/UDP(dport=2002, sport=80)/("DEADBEAF"*(63+64+64)), fragSize=584),
           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0xAAA70000)/UDP(dport=2002, sport=80)/("DEADBEAF"*(63+64+64)), fragSize=584),
           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0xFFF00000)/UDP(dport=2002, sport=80)/("DEADBEAF"*(63+64+64)), fragSize=584))


write_pcap("005-send.pcap",
           fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::1", hlim=64)/IPv6ExtHdrDestOpt()/IPv6ExtHdrFragment(id=0x12CDCDC0)/UDP(dport=80, sport=2002)/("ABCDEFGH1234BBBBBBBB"*128), fragSize=1280),
# last extension?    fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::1", hlim=64)/IPv6ExtHdrFragment(id=0x12CDCDC1)/IPv6ExtHdrDestOpt()/UDP(dport=81, sport=2002)/("ABCDEFGH1234BBBBBBBB"*128), fragSize=1280),
# last extension?    fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::1", hlim=64)/IPv6ExtHdrDestOpt()/IPv6ExtHdrFragment(id=0x12CDCDC2)/IPv6ExtHdrDestOpt()/UDP(dport=82, sport=2002)/("ABCDEFGH1234BBBBBBBB"*128), fragSize=1280),
           fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:123:0a00:0000::11.11.11.0", src="2000::1", hlim=64)/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrDestOpt()/IPv6ExtHdrFragment(id=0x12CDCDC3)/UDP(dport=83, sport=2002)/("ABCDEFGH1234BBBBBBBB"*128), fragSize=1280))

write_pcap("005-expect.pcap",
           fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0xad4d)/UDP(dport=80, sport=12006)/("ABCDEFGH1234BBBBBBBB"*128), fragsize=1200),
# last extension?   fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0x75f2)/UDP(dport=81, sport=12006)/("ABCDEFGH1234BBBBBBBB"*128), fragsize=1208),
# last extension?   fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0x75f2)/UDP(dport=82, sport=12006)/("ABCDEFGH1234BBBBBBBB"*128), fragsize=1208),
           fragment(Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="11.11.11.0", src="10.0.0.0", ttl=63, id=0x59be)/UDP(dport=83, sport=12006)/("ABCDEFGH1234BBBBBBBB"*128), fragsize=1152))


write_pcap("006-send.pcap",
           fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xc1c0, options=("\x02"*4))/UDP(dport=12007, sport=80)/("ABCDEFGH1234BBBBBBBB"*128), fragsize=1208),
           fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xc1c1, options=("\x02"*20))/UDP(dport=12007, sport=80)/("ABCDEFGH1234BBBBBBBB"*128), fragsize=1208),
           fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0", src="11.11.11.0", ttl=64, id=0xc1c2, options=("\x02"*40))/UDP(dport=12007, sport=80)/("ABCDEFGH1234BBBBBBBB"*128), fragsize=1208))

write_pcap("006-expect.pcap",
           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0xc1c00000)/UDP(dport=2003, sport=80)/("ABCDEFGH1234BBBBBBBB"*128), fragSize=1280),
           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0xc1c10000)/UDP(dport=2003, sport=80)/("ABCDEFGH1234BBBBBBBB"*128), fragSize=1280),
           fragment6(Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2222:123:0a00:0000::11.11.11.0", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0xc1c20000)/UDP(dport=2003, sport=80)/("ABCDEFGH1234BBBBBBBB"*128), fragSize=1280))
