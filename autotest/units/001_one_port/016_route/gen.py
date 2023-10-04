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

def write_pcap_step1(filename):
	write_pcap(filename,
	           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=64)/TCP(),
	           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=64)/TCP(),
	           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.2.0.0", src="222.222.222.222", ttl=64)/TCP(),
	           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=64)/TCP(),
	           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.4.0.0", src="222.222.222.222", ttl=64)/TCP(),
	           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=64)/TCP(),
	           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.6.0.0", src="222.222.222.222", ttl=64)/TCP(),
	           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.7.0.0", src="222.222.222.222", ttl=64)/TCP(),
	           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.8.0.0", src="222.222.222.222", ttl=64)/TCP(),
	           Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="1.9.0.0", src="222.222.222.222", ttl=64)/TCP())


write_pcap_step1("001-send.pcap")
write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.4.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.6.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.7.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.8.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.9.0.0", src="222.222.222.222", ttl=63)/TCP())


write_pcap_step1("002-send.pcap")
write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.4.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.6.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.7.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.8.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.9.0.0", src="222.222.222.222", ttl=63)/TCP())


write_pcap_step1("003-send.pcap")
write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.2.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.4.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.6.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.7.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.8.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.9.0.0", src="222.222.222.222", ttl=63)/TCP())


write_pcap_step1("004-send.pcap")
write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=113, ttl=255)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.2.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.4.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.6.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.7.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.8.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=113, ttl=255)/IP(dst="1.9.0.0", src="222.222.222.222", ttl=63)/TCP())


write_pcap_step1("005-send.pcap")
write_pcap("005-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=113, ttl=255)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=113, ttl=255)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.2.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.4.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=113, ttl=255)/IP(dst="1.6.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=113, ttl=255)/IP(dst="1.7.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.8.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=113, ttl=255)/IP(dst="1.9.0.0", src="222.222.222.222", ttl=63)/TCP())


write_pcap_step1("006-send.pcap")
write_pcap("006-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=113, ttl=255)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.2.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.4.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=111, ttl=255)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.6.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.7.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=112, ttl=255)/IP(dst="1.8.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.9.0.0", src="222.222.222.222", ttl=63)/TCP())


write_pcap_step1("007-send.pcap")
write_pcap("007-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=113, ttl=255)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=121, ttl=255)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.4.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=121, ttl=255)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.6.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.7.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.8.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.9.0.0", src="222.222.222.222", ttl=63)/TCP())


write_pcap_step1("008-send.pcap")
write_pcap("008-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=113, ttl=255)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=121, ttl=255)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=121, ttl=255)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP())


write_pcap_step1("009-send.pcap")
write_pcap("009-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=121, ttl=255)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=121, ttl=255)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP())


write_pcap_step1("010-send.pcap")
write_pcap("010-expect.pcap")


write_pcap_step1("011-send.pcap")
write_pcap("011-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=122, ttl=255)/IP(dst="1.2.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=122, ttl=255)/IP(dst="1.4.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=122, ttl=255)/IP(dst="1.6.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/MPLS(label=122, ttl=255)/IP(dst="1.7.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.8.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.9.0.0", src="222.222.222.222", ttl=63)/TCP())


write_pcap_step1("012-send.pcap")
write_pcap("012-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.0.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.2.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.3.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.4.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.5.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.6.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.7.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.8.0.0", src="222.222.222.222", ttl=63)/TCP(),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.9.0.0", src="222.222.222.222", ttl=63)/TCP())


write_pcap_step1("013-send.pcap")
write_pcap("013-expect.pcap")
