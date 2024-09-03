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

write_pcap("001-send.pcap",
           # vlan 100 - default vrf
		   #
           # 1.0.0.0/24 -> 88.88.88.1
           # 2.0.0.0/24 -> 88.88.88.2
           # 3.0.0.0/24 -> 88.88.88.3
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IP(dst="2.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IP(dst="3.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           
           # vlan 200 - red vrf
		   #
           # 1.0.0.0/24 -> 88.88.88.2
           # 2.0.0.0/24 -> 88.88.88.3
           # 3.0.0.0/24 -> 88.88.88.1
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IPv6(dst="2222::cccc", src="::1")/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IPv6(dst="2222::cccc", src="::1")/IP(dst="2.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IPv6(dst="2222::cccc", src="::1")/IP(dst="3.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),

           # vlan 300 - white vrf
		   #
           # 1.0.0.0/24 -> 88.88.88.3
           # 2.0.0.0/24 -> 88.88.88.1
           # 3.0.0.0/24 -> 88.88.88.2
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=300)/IPv6(dst="2222::cccc", src="::1")/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=300)/IPv6(dst="2222::cccc", src="::1")/IP(dst="2.0.0.1", src="0.0.0.0", ttl=64)/ICMP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=300)/IPv6(dst="2222::cccc", src="::1")/IP(dst="3.0.0.1", src="0.0.0.0", ttl=64)/ICMP())

write_pcap("001-expect.pcap",
           # vlan 100 - default vrf
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1")/UDP(dport=6635, sport=0xaa6c | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1")/UDP(dport=6635, sport=0x1072 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="2.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.3", src="10.50.0.1")/UDP(dport=6635, sport=0x2bd7 | 0xc000, chksum=0)/MPLS(label=1300, ttl=255)/IP(dst="3.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),

           # vlan 200 - red vrf
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1")/UDP(dport=6635, sport=0xaa6c | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.3", src="10.50.0.1")/UDP(dport=6635, sport=0x1072 | 0xc000, chksum=0)/MPLS(label=1300, ttl=255)/IP(dst="2.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1")/UDP(dport=6635, sport=0x2bd7 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="3.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),

           # vlan 300 - white vrf
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.3", src="10.50.0.1")/UDP(dport=6635, sport=0xaa6c | 0xc000, chksum=0)/MPLS(label=1300, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.1", src="10.50.0.1")/UDP(dport=6635, sport=0x1072 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="2.0.0.1", src="0.0.0.0", ttl=63)/ICMP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="88.88.88.2", src="10.50.0.1")/UDP(dport=6635, sport=0x2bd7 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IP(dst="3.0.0.1", src="0.0.0.0", ttl=63)/ICMP())

# IPv6

write_pcap("002-send.pcap",
           # vlan 100 - default vrf
           #
           # 7e01::/64 -> 8888::1
           # 7e02::/64 -> 8888::2
           # 7e03::/64 -> 8888::3
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e01::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e02::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e03::1", src="2222::2222")/TCP(),
           
           # vlan 100 - red vrf
           #
           # 7e01::/64 -> 8888::2
           # 7e02::/64 -> 8888::3
           # 7e03::/64 -> 8888::1
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e01::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e02::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=200)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e03::1", src="2222::2222")/TCP(),

           # vlan 100 - white vrf
           #
           # 7e01::/64 -> 8888::3
           # 7e02::/64 -> 8888::1
           # 7e03::/64 -> 8888::2
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=300)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e01::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=300)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e02::1", src="2222::2222")/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=300)/IPv6(dst="2222::cccc", src="::1")/IPv6(dst="7e03::1", src="2222::2222")/TCP())


write_pcap("002-expect.pcap",
           # vlan 100 - default vrf
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="c0de::1")/UDP(dport=6635, sport=0x1f99 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e01::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::2", src="c0de::1")/UDP(dport=6635, sport=0x0fd1 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e02::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::3", src="c0de::1")/UDP(dport=6635, sport=0x3fe9 | 0xc000, chksum=0)/MPLS(label=1300, ttl=255)/IPv6(dst="7e03::1", src="2222::2222", hlim=63)/TCP(),

           # vlan 100 - red vrf
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::2", src="c0de::1")/UDP(dport=6635, sport=0x1f99 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e01::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::3", src="c0de::1")/UDP(dport=6635, sport=0x0fd1 | 0xc000, chksum=0)/MPLS(label=1300, ttl=255)/IPv6(dst="7e02::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="c0de::1")/UDP(dport=6635, sport=0x3fe9 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e03::1", src="2222::2222", hlim=63)/TCP(),

           # vlan 100 - white vrf
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::3", src="c0de::1")/UDP(dport=6635, sport=0x1f99 | 0xc000, chksum=0)/MPLS(label=1300, ttl=255)/IPv6(dst="7e01::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::1", src="c0de::1")/UDP(dport=6635, sport=0x0fd1 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IPv6(dst="7e02::1", src="2222::2222", hlim=63)/TCP(),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="8888::2", src="c0de::1")/UDP(dport=6635, sport=0x3fe9 | 0xc000, chksum=0)/MPLS(label=1200, ttl=255)/IPv6(dst="7e03::1", src="2222::2222", hlim=63)/TCP())
