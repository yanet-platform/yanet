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


# 10.10.0.0/24 -> kni0.100
write_pcap("001-send.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="10.10.0.2", src="222.222.222.222")/UDP(),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="10.10.0.111", src="222.222.222.222")/UDP(), # neighbor mac invalid
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="10.10.0.250", src="222.222.222.222")/UDP(),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IP(dst="10.10.0.2", src="222.222.222.222")/UDP(),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IP(dst="10.10.0.111", src="222.222.222.222")/UDP(), # neighbor mac invalid
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IP(dst="10.10.0.250", src="222.222.222.222")/UDP())

write_pcap("001-expect.pcap",
           Ether(dst="00:00:EE:10:44:02", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.10.0.2", src="222.222.222.222", ttl=63)/UDP(),
           Ether(dst="00:00:EE:10:44:FA", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.10.0.250", src="222.222.222.222", ttl=63)/UDP(),
           Ether(dst="00:00:EE:10:44:02", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.10.0.2", src="222.222.222.222", ttl=63)/UDP(),
           Ether(dst="00:00:EE:10:44:FA", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.10.0.250", src="222.222.222.222", ttl=63)/UDP())


# 2000:100::/96 -> kni0.100
write_pcap("002-send.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IPv6(dst="2000:100::2", src="2222::2222")/UDP(),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IPv6(dst="2000:100::6F", src="2222::2222")/UDP(), # neighbor mac invalid
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IPv6(dst="2000:100::FA", src="2222::2222")/UDP(),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:100::2", src="2222::2222")/UDP(),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:100::6F", src="2222::2222")/UDP(), # neighbor mac invalid
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:100::FA", src="2222::2222")/UDP())

write_pcap("002-expect.pcap",
           Ether(dst="00:00:EE:10:66:02", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="2000:100::2", src="2222::2222", hlim=63)/UDP(),
           Ether(dst="00:00:EE:10:66:FA", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="2000:100::FA", src="2222::2222", hlim=63)/UDP(),
           Ether(dst="00:00:EE:10:66:02", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="2000:100::2", src="2222::2222", hlim=63)/UDP(),
           Ether(dst="00:00:EE:10:66:FA", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="2000:100::FA", src="2222::2222", hlim=63)/UDP())


# 10.20.0.0/24 -> kni0.200
write_pcap("003-send.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="10.20.0.2", src="222.222.222.222")/UDP(),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="10.20.0.111", src="222.222.222.222")/UDP(), # neighbor mac invalid
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="10.20.0.250", src="222.222.222.222")/UDP(),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IP(dst="10.20.0.2", src="222.222.222.222")/UDP(),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IP(dst="10.20.0.111", src="222.222.222.222")/UDP(), # neighbor mac invalid
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IP(dst="10.20.0.250", src="222.222.222.222")/UDP())

write_pcap("003-expect.pcap",
           Ether(dst="00:00:EE:20:44:02", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(dst="10.20.0.2", src="222.222.222.222", ttl=63)/UDP(),
           Ether(dst="00:00:EE:20:44:FA", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(dst="10.20.0.250", src="222.222.222.222", ttl=63)/UDP(),
           Ether(dst="00:00:EE:20:44:02", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(dst="10.20.0.2", src="222.222.222.222", ttl=63)/UDP(),
           Ether(dst="00:00:EE:20:44:FA", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(dst="10.20.0.250", src="222.222.222.222", ttl=63)/UDP())


# 2000:200::/96 -> kni0.200
write_pcap("004-send.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IPv6(dst="2000:200::2", src="2222::2222")/UDP(),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IPv6(dst="2000:200::6F", src="2222::2222")/UDP(), # neighbor mac invalid
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IPv6(dst="2000:200::FA", src="2222::2222")/UDP(),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:200::2", src="2222::2222")/UDP(),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:200::6F", src="2222::2222")/UDP(), # neighbor mac invalid
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:200::FA", src="2222::2222")/UDP())

write_pcap("004-expect.pcap",
           Ether(dst="00:00:EE:20:66:02", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="2000:200::2", src="2222::2222", hlim=63)/UDP(),
           Ether(dst="00:00:EE:20:66:FA", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="2000:200::FA", src="2222::2222", hlim=63)/UDP(),
           Ether(dst="00:00:EE:20:66:02", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="2000:200::2", src="2222::2222", hlim=63)/UDP(),
           Ether(dst="00:00:EE:20:66:FA", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="2000:200::FA", src="2222::2222", hlim=63)/UDP())
