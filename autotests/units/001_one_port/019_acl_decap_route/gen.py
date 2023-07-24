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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=164)/TCP(dport=80, sport=2048),
)

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=63)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=163)/TCP(dport=80, sport=2048))


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::abce", src="2000::", hlim=64)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abce", src="2000::", hlim=64)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=164)/TCP(dport=80, sport=2048))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="1234::abce", src="2000::", hlim=63)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="1234::abce", src="2000::", hlim=63)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=164)/TCP(dport=80, sport=2048))


write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::abcd", src="2000::", hlim=64)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="2000::", hlim=64)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=164)/TCP(dport=80, sport=2048))

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=63)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=163)/TCP(dport=80, sport=2048))


write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2000::/124", src="dead:beaf::8:800:555:3535", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2000::/124", src="dead:beaf::8:800:555:3535", hlim=64)/TCP(dport=80, sport=2048))

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::/124", src="dead:beaf::8:800:555:3535", hlim=63)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::/124", src="dead:beaf::8:800:555:3535", hlim=63)/TCP(dport=80, sport=2048))


write_pcap("005-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/ARP(),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/ARP())

write_pcap("005-expect.pcap")
