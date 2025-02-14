#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.contrib.mpls import MPLS


def write_pcap(filename, *packetsList):
	if len(packetsList) == 0:
		writer=PcapWriter(filename)
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


'''
At the first stage, the routing table should be as follows:
	route 0.0.0.0/0 via 10.10.10.1;
	route 1.0.0.0/8 via 10.10.10.2;
	route 2.0.0.0/8 via 10.10.10.3;
	route ::/0 via 10::1;
	route 1::/64 via 10::2;
	route 2::/64 via 10::3;
'''

write_pcap("001-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.0.0.127", src="11.0.0.1")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.1.0.127", src="11.0.0.1")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="2.0.0.127", src="11.0.0.1")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="3.0.0.127", src="11.0.0.1")/ICMP(),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1::1", src="11::1")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1::1:1", src="11::1")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2::1", src="11::1")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="3::1", src="11::1")/ICMP(),
)

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IP(dst="1.0.0.127", src="11.0.0.1", ttl=63)/ICMP(),
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IP(dst="1.1.0.127", src="11.0.0.1", ttl=63)/ICMP(),
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IP(dst="2.0.0.127", src="11.0.0.1", ttl=63)/ICMP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="3.0.0.127", src="11.0.0.1", ttl=63)/ICMP(),

           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IPv6(dst="1::1", src="11::1", hlim=63)/ICMP(),
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IPv6(dst="1::1:1", src="11::1", hlim=63)/ICMP(),
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IPv6(dst="2::1", src="11::1", hlim=63)/ICMP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="3::1", src="11::1", hlim=63)/ICMP(),
)

'''
At the second stage, the following changes occur:
	del route 2.0.0.0/8 via 10.10.10.3;
	add route 1.0.0.0/16 via 10.10.10.3;

The routing table should be as follows:
	route 0.0.0.0/0 via 10.10.10.1;
	route 1.0.0.0/8 via 10.10.10.2;
	route 1.0.0.0/16 via 10.10.10.3;
	route ::/0 via 10::1;
	route 1::/64 via 10::2;
	route 1::/120 via 10::3;

'''


write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IP(dst="1.0.0.127", src="11.0.0.1", ttl=63)/ICMP(),
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IP(dst="1.1.0.127", src="11.0.0.1", ttl=63)/ICMP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="2.0.0.127", src="11.0.0.1", ttl=63)/ICMP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="3.0.0.127", src="11.0.0.1", ttl=63)/ICMP(),

           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IPv6(dst="1::1", src="11::1", hlim=63)/ICMP(),
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IPv6(dst="1::1:1", src="11::1", hlim=63)/ICMP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="2::1", src="11::1", hlim=63)/ICMP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="3::1", src="11::1", hlim=63)/ICMP(),
)

'''
At the third stage, all routes are deleted and the routing table should be empty.
'''
