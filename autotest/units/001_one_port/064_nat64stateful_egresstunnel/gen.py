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


# check lan (ipv6 -> ipv4). local prefixes
write_pcap("001-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::4.4.4.1", src="::100", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::4.4.4.2", src="::100", hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::4.4.4.3", src="::100", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::4.4.4.4", src="::100", hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::4.4.4.1", src="::100", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::4.4.4.2", src="::100", hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::4.4.4.3", src="::100", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::4.4.4.4", src="::100", hlim=64)/TCP(dport=443, sport=2048))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.1", src="153.153.153.200", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.2", src="153.153.153.200", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="4.4.4.3", src="153.153.153.200", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="153.153.153.200", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.1", src="153.153.153.200", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.2", src="153.153.153.200", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="4.4.4.3", src="153.153.153.200", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="153.153.153.200", ttl=63, id=0)/TCP(dport=443, sport=2048))


# check lan (ipv6 -> ipv4). tunnel
write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.1", src="::1", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.2", src="::2", hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.3", src="::3", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.4", src="::4", hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.1", src="::1", hlim=64, fl=1)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.2", src="::2", hlim=64, fl=1)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.3", src="::3", hlim=64, fl=1)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.4", src="::4", hlim=64, fl=1)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.5", src="::5", hlim=64, fl=1)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.6", src="::6", hlim=64, fl=1)/TCP(dport=443, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.7", src="::7", hlim=64, fl=1)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="64:ff9b::1.0.0.8", src="::8", hlim=64, fl=1)/TCP(dport=443, sport=2048))


write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xd9bb | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="153.153.153.200", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xcf4b | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.2", src="153.153.153.200", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xc3da | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.3", src="153.153.153.200", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xd719 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.4", src="153.153.153.200", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xd9bb | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="153.153.153.200", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xcf4b | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.2", src="153.153.153.200", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xc3da | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.3", src="153.153.153.200", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xd719 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.4", src="153.153.153.200", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xdb88 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.5", src="153.153.153.200", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xcd78 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.6", src="153.153.153.200", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xc1e9 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.7", src="153.153.153.200", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="88.88.88.1", src="10.50.0.1", ttl=64, id=0)/UDP(dport=6635, sport=0xe7bd | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.8", src="153.153.153.200", ttl=63, id=0)/TCP(dport=443, sport=2048))
