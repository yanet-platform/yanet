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

# default vrf
write_pcap("001-send.pcap",
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=64)/TCP())

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP())

# vrf1
write_pcap("002-send.pcap",
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=101)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=101)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=64)/TCP())

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP())

# vrf2
write_pcap("003-send.pcap",
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=102)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=64)/TCP(),
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=102)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=64)/TCP())

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
		   Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP())

write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=102)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=102)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=64)/TCP())

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP())

# new route in default vrf - now packets will be routed through different logical ports (in comparison to 001-expected.pcap) 
write_pcap("005-send.pcap",
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=64)/TCP())

write_pcap("005-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP())

# packets received through lp.103 (with vlan 103) - vrf is not explicitly set in controlplane.conf, using default vrf
write_pcap("005-send.pcap",
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=103)/IP(dst="5.5.5.5", src="222.222.222.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=103)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=64)/TCP())

write_pcap("005-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="5.5.5.5", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP())

# after controlplane.2.conf was loaded, lp.103 uses vrf1
write_pcap("006-send.pcap",
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=103)/IP(dst="5.5.5.5", src="222.222.222.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=103)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=64)/TCP())

write_pcap("006-expect.pcap",
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="5.5.5.5", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP())

# vrf1 was cleared and only 1.1.0.0/16 prefix was added
write_pcap("007-send.pcap",
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=103)/IP(dst="5.5.5.5", src="222.222.222.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=103)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=64)/TCP())

write_pcap("007-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP())

# vrf1 changed nexthop for 1.1.0.0/16 prefix
write_pcap("008-send.pcap",
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=103)/IP(dst="5.5.5.5", src="222.222.222.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=103)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=64)/TCP())

write_pcap("008-expect.pcap",
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP())

# new routes were added for vrf4 which does not yet correpond to any logical interface
write_pcap("009-send.pcap",
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="7.7.7.0", src="222.222.222.222", ttl=64)/TCP(),
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=104)/IP(dst="7.7.7.0", src="222.222.222.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=104)/IP(dst="7.7.7.7", src="222.222.222.222", ttl=64)/TCP(),
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=104)/IP(dst="7.7.7.8", src="222.222.222.222", ttl=64)/TCP())

write_pcap("009-expect.pcap",
		   Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="7.7.7.0", src="222.222.222.222", ttl=63)/TCP())

# vrf4 now correponds to logical interface with vlan 104
# TODO: flaps: packet 4 may be missed for some reason
write_pcap("010-send.pcap",
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="7.7.7.0", src="222.222.222.222", ttl=64)/TCP(),
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=104)/IP(dst="7.7.7.0", src="222.222.222.222", ttl=64)/TCP(),
	       Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=104)/IP(dst="7.7.7.7", src="222.222.222.222", ttl=64)/TCP(),
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=104)/IP(dst="7.7.7.8", src="222.222.222.222", ttl=64)/TCP())

write_pcap("010-expect.pcap",
		   Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="7.7.7.0", src="222.222.222.222", ttl=63)/TCP(),
		   Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="7.7.7.0", src="222.222.222.222", ttl=63)/TCP(),
		   Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="7.7.7.7", src="222.222.222.222", ttl=63)/TCP(),
		   Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=202)/IP(dst="7.7.7.8", src="222.222.222.222", ttl=63)/TCP())

# route tunnel vrf1
write_pcap("011-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=102)/IPv6(dst="2222::cccc", src="::11")/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=102)/IPv6(dst="2222::cccc", src="::12")/IP(dst="1.0.0.2", src="0.0.0.0", ttl=64)/TCP())

write_pcap("011-expect.pcap",
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=202)/IP(dst="200.0.2.3", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x0941 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/TCP(),
           Ether(dst="00:00:00:44:44:44", src="00:11:22:33:44:55")/Dot1Q(vlan=202)/IP(dst="200.0.2.3", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x0568 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.2", src="0.0.0.0", ttl=63)/TCP())

# route tunnel vrf4
write_pcap("012-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=104)/IPv6(dst="2222::cccc", src="::11")/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=104)/IPv6(dst="2222::cccc", src="::12")/IP(dst="1.0.0.2", src="0.0.0.0", ttl=64)/TCP())

write_pcap("012-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.2.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x0941 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.2.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x0568 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.2", src="0.0.0.0", ttl=63)/TCP())

# more specific prefix 1.0.0.1/32
write_pcap("013-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=104)/IPv6(dst="2222::cccc", src="::11")/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/TCP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=104)/IPv6(dst="2222::cccc", src="::12")/IP(dst="1.0.0.2", src="0.0.0.0", ttl=64)/TCP(),
		   Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=104)/IPv6(dst="2222::cccc", src="::11")/IP(dst="1.0.0.1", src="0.0.0.0", ttl=64)/TCP())

write_pcap("013-expect.pcap",
           Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="200.0.2.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x0941 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.2.1", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x0568 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.2", src="0.0.0.0", ttl=63)/TCP(),
		   Ether(dst="00:00:00:33:33:33", src="00:11:22:33:44:55")/Dot1Q(vlan=201)/IP(dst="200.0.2.2", src="10.50.0.1", ttl=64)/UDP(dport=6635, sport=0x0941 | 0xc000, chksum=0)/MPLS(label=1100, ttl=255)/IP(dst="1.0.0.1", src="0.0.0.0", ttl=63)/TCP())