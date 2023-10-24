#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *


def write_pcap(filename, *packetsList):
	PcapWriter(filename)
	for packets in packetsList:
		packets.time = 0
		wrpcap(filename, [p for p in packets], append=True)


# First packet will be accounted by one mapping
# Second packet will be accounted by the decap_unknown counter
write_pcap("decap.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2020:ddd:b010:a0ff::1", src="2020:ddd:ccc:4444:111:111:0:2222")/IP(dst="8.8.8.8", src="1.23.111.4")/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=100)/IPv6(dst="2020:ddd:b010:a0ff::1", src="fe80::cafe")/IP(dst="8.8.8.8", src="10.0.0.1")/ICMP())

write_pcap("decap_expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="1.23.111.4", ttl=63)/ICMP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="8.8.8.8", src="10.0.0.1", ttl=63)/ICMP())

# First packet will be accounted by one mapping
# Second packet will be accounted by the encap_dropped counter
write_pcap("encap.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(dst="1.23.111.4", src="8.8.8.8", ttl=59)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(dst="11.220.222.65", src="8.8.8.8")/ICMP())

write_pcap("encap_expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2020:ddd:ccc:4444:111:111:0:2222", src="2020:ddd:b010:a0ff::1",hlim=63)/IP(dst="1.23.111.4", src="8.8.8.8", ttl=59)/ICMP())


# Both packets will be accounted by some mapping
write_pcap("encap_rnd.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(dst="1.23.123.134", src="8.8.8.8", ttl=59)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(dst="123.0.250.66", src="1.1.1.1", ttl=59)/ICMP())

write_pcap("encap_rnd_expect.pcap",
        Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2020:ddd:ccc:bbb:0:4444:cccc:3737", src="2020:ddd:abcd::808:808:0:0",hlim=63)/IP(dst="1.23.123.134", src="8.8.8.8", ttl=59)/ICMP(),
        Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2020:ddd:ccc:111:0:567:5555:8888", src="2020:ddd:abcd::101:101:0:0",hlim=63)/IP(dst="123.0.250.66", src="1.1.1.1", ttl=59)/ICMP())

