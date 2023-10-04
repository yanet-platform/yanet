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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99c:0a00:0000::1.1.0.0", src="2000::/127", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99c:0a00:0001::1.1.0.0", src="2000::/127", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99c:0a00:0002::1.1.0.0", src="2000::/127", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99c:0a00:0003::1.1.0.0", src="2000::/127", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99c:0a00:0000:0000:0000:1.1.0.0", src="2000::", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99c:0a00:0000:1234:5678:1.1.0.0", src="2000::", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99c:0a00:0000:0000:0001:1.1.0.0", src="2000::", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99c:0a00:0000:8000:0000:1.1.0.0", src="2000::", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99e:fffe::1.2.0.0", src="2001::/126", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99e:ffff::1.2.0.0", src="2001::/126", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99d::1.3.0.0", src="2002::/127", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99d:1::1.3.0.0", src="2002::/127", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99d::0001:1.3.0.0", src="2002::/127", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99f::1.4.0.0", src="2003::/126", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:99f:ffff:ffff:ffff:ffff:1.4.0.0", src="2003::/126", hlim=64)/TCP(dport=80, sport=2048))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0", src="10.0.0.0/32", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0", src="10.0.0.1/32", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0", src="10.0.0.2/32", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0", src="10.0.0.0/32", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.0", src="10.1.0.0/31", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.0", src="10.1.1.0/31", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.3.0.0", src="10.2.0.0/32", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.3.0.0", src="10.2.1.0/32", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.4.0.0", src="10.3.0.0/31", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.4.0.0", src="10.3.1.0/31", ttl=63, id=0)/TCP(dport=80, sport=2048))


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.0/32", src="1.1.0.0", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1/32", src="1.1.0.0", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2/32", src="1.1.0.0", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.3/32", src="1.1.0.0", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.0/30", src="1.2.0.0", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.1.0/30", src="1.2.0.0", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.2.0.0/31", src="1.3.0.0", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.2.1.0/31", src="1.3.0.0", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.3.0.0/30", src="1.4.0.0", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.3.1.0/30", src="1.4.0.0", ttl=64)/TCP(dport=2048, sport=80))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:99c:0a00:0000::1.1.0.0", hlim=63, fl=0)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:99c:0a00:0001::1.1.0.0", hlim=63, fl=0)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::", src="2222:99c:0a00:0002::1.1.0.0", hlim=63, fl=0)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2001::/127", src="2222:99e:fffe::1.2.0.0", hlim=63, fl=0)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2001::/127", src="2222:99e:ffff::1.2.0.0", hlim=63, fl=0)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2002::", src="2222:99d::1.3.0.0", hlim=63, fl=0)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2002::", src="2222:99d:1::1.3.0.0", hlim=63, fl=0)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2003::/127", src="2222:99f::1.4.0.0", hlim=63, fl=0)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2003::/127", src="2222:99f:ffff:ffff:ffff:ffff:1.4.0.0", hlim=63, fl=0)/TCP(dport=2048, sport=80))
