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

# IPv4

def write_pcap_ipv4(filename):
   write_pcap(filename,
            # vlan 100, 200 - default vrf
            #
            # 0.0.0.0/0  -> 200.0.10.1
            # 1.0.0.0/24 -> 200.0.20.1    ! only in 001
            # 2.0.0.0/24 -> 200.0.40.1
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="2.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="3.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IP(dst="2.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IP(dst="3.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
            
            # vlan 300 - vrf "red"
            #
            # 0.0.0.0/0  -> 200.0.30.1    ! only in 001
            # 1.0.0.0/24 -> 200.0.10.1
            # 2.0.0.0/24 -> 200.0.20.1
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=300)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=300)/IP(dst="2.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=300)/IP(dst="3.0.0.1", src="222.222.222.222", ttl=64)/TCP(),

            # vlan 400 - vrf "white"
            #
            # 1.0.0.0/24  -> 200.0.40.1
            # 1.0.0.16/28 -> 200.0.10.1   ! only in 001
            # 1.0.0.16/30 -> 200.0.20.2
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=400)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=400)/IP(dst="1.0.0.17", src="222.222.222.222", ttl=64)/TCP(),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=400)/IP(dst="1.0.0.21", src="222.222.222.222", ttl=64)/TCP(),
            # no route for these 2 packets:
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=400)/IP(dst="2.0.0.1", src="222.222.222.222", ttl=64)/TCP(),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=400)/IP(dst="3.0.0.1", src="222.222.222.222", ttl=64)/TCP())

write_pcap_ipv4("001-send.pcap")
write_pcap("001-expect.pcap",
           # vlan 100, 200 - default vrf
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IP(dst="2.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="3.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IP(dst="2.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="3.0.0.1", src="222.222.222.222", ttl=63)/TCP(),

           # vlan 300 - vrf "red"
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="2.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IP(dst="3.0.0.1", src="222.222.222.222", ttl=63)/TCP(),

           # vlan 400 - vrf "white"
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.17", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.0.0.21", src="222.222.222.222", ttl=63)/TCP())

write_pcap_ipv4("003-send.pcap")
write_pcap("003-expect.pcap",
           # vlan 100, 200 - default vrf
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IP(dst="2.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="3.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IP(dst="2.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="3.0.0.1", src="222.222.222.222", ttl=63)/TCP(),

           # vlan 300 - vrf "red"
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="2.0.0.1", src="222.222.222.222", ttl=63)/TCP(),

           # vlan 400 - vrf "white"
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IP(dst="1.0.0.1", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.0.0.17", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="1.0.0.21", src="222.222.222.222", ttl=63)/TCP())

# IPv6

def write_pcap_ipv6(filename):
   write_pcap(filename,
           # vlan 100, 200 - default vrf
           #
           # ::/0      -> c0de::10:1
           # 7e01::/64 -> c0de::20:1   ! only in 001
           # 7e02::/64 -> c0de::40:1
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="7e01::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="7e02::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="7e03::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IPv6(dst="7e01::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IPv6(dst="7e02::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IPv6(dst="7e03::1", src="2222::2222")/TCP(),
           
           # vlan 300 - vrf "red"
           #
           # ::/0      -> c0de::30:1   ! only in 001
           # 7e01::/64 -> c0de::10:1
           # 7e02::/64 -> c0de::20:1
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=300)/IPv6(dst="7e01::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=300)/IPv6(dst="7e02::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=300)/IPv6(dst="7e03::1", src="2222::2222")/TCP(),

           # vlan 400 - vrf "white"
           #
           # 7e01::/64  -> c0de::40:1
           # 7e01::/96  -> c0de::10:1
           # 7e01::/128 -> c0de::20:1   ! only in 001
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=400)/IPv6(dst="7e01:0::1:0:0:1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=400)/IPv6(dst="7e01::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=400)/IPv6(dst="7e01::0", src="2222::2222")/TCP(),
           # no route for these 2 packets:
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=400)/IPv6(dst="7e02::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=400)/IPv6(dst="7e03::1", src="2222::2222")/TCP())

write_pcap_ipv6("002-send.pcap")
write_pcap("002-expect.pcap",
           # vlan 100, 200 - default vrf
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="7e01::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IPv6(dst="7e02::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e03::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="7e01::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IPv6(dst="7e02::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e03::1", src="2222::2222", hlim=63)/TCP(),

           # vlan 300 - vrf "red"
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e01::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="7e02::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=300)/IPv6(dst="7e03::1", src="2222::2222", hlim=63)/TCP(),

           # vlan 400 - vrf "white"
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IPv6(dst="7e01:0::1:0:0:1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e01::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="7e01::0", src="2222::2222", hlim=63)/TCP())

write_pcap_ipv6("004-send.pcap")
write_pcap("004-expect.pcap",
           # vlan 100, 200 - default vrf
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e01::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IPv6(dst="7e02::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e03::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e01::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IPv6(dst="7e02::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e03::1", src="2222::2222", hlim=63)/TCP(),

           # vlan 300 - vrf "red"
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e01::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="7e02::1", src="2222::2222", hlim=63)/TCP(),

           # vlan 400 - vrf "white"
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=400)/IPv6(dst="7e01:0::1:0:0:1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e01::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="7e01::0", src="2222::2222", hlim=63)/TCP())
