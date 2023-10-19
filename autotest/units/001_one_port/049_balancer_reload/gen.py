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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.1", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.2", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.3", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.4", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.1", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0002:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.2", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0003:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.3", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0004:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.4", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.5", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.6", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.7", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.8", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0005:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.5", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0006:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.6", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0007:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.7", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0008:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.8", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.9", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.10", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.11", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.12", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.13", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.14", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.15", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.16", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0009:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.9", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:000a:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.10", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:000b:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.11", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:000c:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.12", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:000d:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.13", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:000e:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.14", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:000f:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.15", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0010:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.16", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.17", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.18", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.19", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.20", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.21", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.22", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.23", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.24", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0011:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.17", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0012:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.18", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0013:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.19", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0014:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.20", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0015:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.21", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0016:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.22", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0017:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.23", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0018:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.24", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("005-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.25", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.26", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.27", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.28", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.29", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.30", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.31", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.32", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.33", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.34", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.35", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.36", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.37", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.38", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.39", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.40", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("005-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:0019:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.25", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:001a:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.26", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:001b:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.27", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:001c:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.28", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:001d:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.29", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:001e:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.30", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:001f:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.31", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:0020:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.32", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0021:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.33", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:0022:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.34", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0023:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.35", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:0024:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.36", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0025:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.37", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:0026:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.38", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:0027:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.39", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0028:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.40", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("006-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.41", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.42", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.43", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.44", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.45", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.46", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.47", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.48", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.49", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.50", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.51", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.52", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.53", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.54", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.55", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.56", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("006-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0029:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.41", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:002a:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.42", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::6", src="2000:51b::0101:002b:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.43", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:002c:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.44", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:002d:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.45", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:002e:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.46", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:002f:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.47", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0030:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.48", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0031:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.49", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:0032:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.50", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0033:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.51", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0034:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.52", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0035:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.53", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::6", src="2000:51b::0101:0036:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.54", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:0037:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.55", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::5", src="2000:51b::0101:0038:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.56", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("007-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.57", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.58", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.59", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.60", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.61", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.62", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.63", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.64", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.65", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.66", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.67", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.68", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.69", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.70", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.71", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="20.1.0.2", src="1.1.0.72", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("007-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::6", src="2000:51b::0101:0039:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.57", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:003a:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.58", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::6", src="2000:51b::0101:003b:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.59", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:003c:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.60", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:003d:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.61", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:003e:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.62", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:003f:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.63", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0040:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.64", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0041:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.65", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0042:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.66", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0043:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.67", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0044:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.68", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0045:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.69", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0046:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.70", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0047:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.71", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0048:0:1", hlim=63, fl=0)/IP(dst="20.1.0.2", src="1.1.0.72", ttl=64)/TCP(dport=443, sport=12443))


