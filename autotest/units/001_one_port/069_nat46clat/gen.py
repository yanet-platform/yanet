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


# lan (ipv4 -> ipv6) TCP/UDP
write_pcap("001-send.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="10.0.0.1", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="10.0.0.1", ttl=64)/TCP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="20.0.0.1", ttl=64)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="20.0.0.1", ttl=64)/TCP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="10.0.0.1", ttl=64)/TCP(dport=5548, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="10.0.0.1", ttl=64)/TCP(dport=5548, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="20.0.0.1", ttl=64)/TCP(dport=5548, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="20.0.0.1", ttl=64)/TCP(dport=5548, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="10.0.0.1", ttl=64)/UDP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="10.0.0.1", ttl=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="20.0.0.1", ttl=64)/UDP(dport=2048, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="4.4.4.4", src="20.0.0.1", ttl=64)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="10.0.0.1", ttl=64)/UDP(dport=5548, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="10.0.0.1", ttl=64)/UDP(dport=5548, sport=443),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="20.0.0.1", ttl=64)/UDP(dport=5548, sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="88.88.4.4", src="20.0.0.1", ttl=64)/UDP(dport=5548, sport=443))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/TCP(dport=2048, sport=443),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/TCP(dport=2048, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/TCP(dport=2048, sport=443),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/TCP(dport=5548, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/TCP(dport=5548, sport=443),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/TCP(dport=5548, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/TCP(dport=5548, sport=443),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/UDP(dport=2048, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/UDP(dport=2048, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:0404:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/UDP(dport=2048, sport=443),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/UDP(dport=5548, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", hlim=63)/UDP(dport=5548, sport=443),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/UDP(dport=5548, sport=80),
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:5858:0404", src="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", hlim=63)/UDP(dport=5548, sport=443))


# wan (ipv6 -> ipv4) TCP/UDP
write_pcap("002-send.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/TCP(dport=80, sport=5548),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/TCP(dport=443, sport=5548),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/TCP(dport=80, sport=5548),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/TCP(dport=443, sport=5548),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/UDP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/UDP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/UDP(dport=80, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:0404:0404", hlim=64)/UDP(dport=443, sport=2048),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/UDP(dport=80, sport=5548),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:10.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/UDP(dport=443, sport=5548),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/UDP(dport=80, sport=5548),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:20.0.0.1", src="6464:6464:6464:6464:6464:6464:5858:0404", hlim=64)/UDP(dport=443, sport=5548))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="4.4.4.4", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="4.4.4.4", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="4.4.4.4", ttl=63, id=0)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="4.4.4.4", ttl=63, id=0)/TCP(dport=443, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="88.88.4.4", ttl=63, id=0)/TCP(dport=80, sport=5548),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="88.88.4.4", ttl=63, id=0)/TCP(dport=443, sport=5548),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="88.88.4.4", ttl=63, id=0)/TCP(dport=80, sport=5548),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="88.88.4.4", ttl=63, id=0)/TCP(dport=443, sport=5548),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="4.4.4.4", ttl=63, id=0)/UDP(dport=80, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="4.4.4.4", ttl=63, id=0)/UDP(dport=443, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="4.4.4.4", ttl=63, id=0)/UDP(dport=80, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="4.4.4.4", ttl=63, id=0)/UDP(dport=443, sport=2048),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="88.88.4.4", ttl=63, id=0)/UDP(dport=80, sport=5548),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="10.0.0.1", src="88.88.4.4", ttl=63, id=0)/UDP(dport=443, sport=5548),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="88.88.4.4", ttl=63, id=0)/UDP(dport=80, sport=5548),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="20.0.0.1", src="88.88.4.4", ttl=63, id=0)/UDP(dport=443, sport=5548))


# check IPv6 -> IPv4, Fragments
write_pcap("003-send.pcap",
           fragment6(Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:102.102.102.102", src="6464:6464:6464:6464:6464:6464:153.153.153.153", hlim=64)/IPv6ExtHdrFragment(id=0x12345678)/TCP(dport=80, sport=2048)/("ABCDEFGH123456789012"*128), fragSize=1280),
           fragment6(Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:102.102.102.102", src="6464:6464:6464:6464:6464:6464:153.153.153.153", hlim=64)/IPv6ExtHdrFragment(id=0x12345678)/UDP(dport=80, sport=2048)/("ABCDEFGH123456789012"*128), fragSize=1280),
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:102.102.102.102", src="6464:6464:6464:6464:6464:6464:153.153.153.153", hlim=64)/IPv6ExtHdrFragment(id=0x87654321, m=0, offset=0)/TCP(dport=80, sport=2048),
           fragment6(Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:102.102.102.102", src="6464:6464:6464:6464:6464:6464:153.153.153.153", hlim=64)/IPv6ExtHdrFragment(id=0xABCDEF12)/ICMPv6EchoRequest(id=0x1234, seq=0x8765)/("ABCDEFGH123456789012"*128), fragSize=1280))

write_pcap("003-expect.pcap",
           fragment(Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="102.102.102.102", src="153.153.153.153", ttl=63, id=0x4dda)/TCP(dport=80, sport=2048)/("ABCDEFGH123456789012"*128), fragsize=1208),
           fragment(Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="102.102.102.102", src="153.153.153.153", ttl=63, id=0x4dda)/UDP(dport=80, sport=2048)/("ABCDEFGH123456789012"*128), fragsize=1208),
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="102.102.102.102", src="153.153.153.153", ttl=63, id=0)/TCP(dport=80, sport=2048),
           # ICMP fragments not allowed yet
           # fragment(Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="102.102.102.102", src="153.153.153.153", ttl=63, id=0xcaaa)/ICMP(type=8, id=0x1234, seq=0x8765)/("ABCDEFGH123456789012"*128), fragsize=1208),
           )


# check IPv4 -> IPv6, Fragments
write_pcap("004-send.pcap",
           fragment(Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="153.153.153.153", src="102.102.102.102", ttl=64, id=0x1234)/TCP(dport=2048, sport=80)/("ABCDEFGH123456789012"*128), fragsize=1208),
           fragment(Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="153.153.153.153", src="102.102.102.102", ttl=64, id=0x1234)/UDP(dport=2048, sport=80)/("ABCDEFGH123456789012"*128), fragsize=1208),
           fragment(Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="153.153.153.153", src="102.102.102.102", ttl=64, id=0x1234)/ICMP(type=8, id=0x1234, seq=0x8765)/("ABCDEFGH123456789012"*128), fragsize=1208))

write_pcap("004-expect.pcap",
           fragment6(Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:153.153.153.153", src="2000:abcd:fefe:b0b0:c0c0:fea6:102.102.102.102", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0x12340000)/TCP(dport=2048, sport=80)/("ABCDEFGH123456789012"*128), fragSize=1280),
           fragment6(Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:153.153.153.153", src="2000:abcd:fefe:b0b0:c0c0:fea6:102.102.102.102", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0x12340000)/UDP(dport=2048, sport=80)/("ABCDEFGH123456789012"*128), fragSize=1280),
           # ICMP fragments not allowed yet
           # fragment6(Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:153.153.153.153", src="2000:abcd:fefe:b0b0:c0c0:fea6:102.102.102.102", hlim=63, fl=0)/IPv6ExtHdrFragment(id=0x12340000)/ICMPv6EchoRequest(id=0x1234, seq=0x8765)/("ABCDEFGH123456789012"*128), fragSize=1280),
           )


# check IPv6 -> IPv4, ICMP Ping/Pong
write_pcap("005-send.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:102.102.102.102", src="6464:6464:6464:6464:6464:6464:153.153.153.153", hlim=64)/ICMPv6EchoRequest(id=0x1234, seq=0x8765)/"du hast vyacheslavich",
           Ether(dst="00:00:00:22:22:22", src="00:00:DE:AD:00:00")/Dot1Q(vlan=200)/IPv6(dst="2000:abcd:fefe:b0b0:c0c0:fea6:102.102.102.102", src="6464:6464:6464:6464:6464:6464:153.153.153.153", hlim=64)/ICMPv6EchoReply(id=0x5678, seq=0x4321)/"vitalya 2")

write_pcap("005-expect.pcap",
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="102.102.102.102", src="153.153.153.153", ttl=63, id=0)/ICMP(type=8, id=0x1234, seq=0x8765)/"du hast vyacheslavich",
           Ether(dst="00:00:EE:10:44:44", src="00:00:00:11:11:11")/Dot1Q(vlan=100)/IP(dst="102.102.102.102", src="153.153.153.153", ttl=63, id=0)/ICMP(type=0, id=0x5678, seq=0x4321)/"vitalya 2")


# check IPv4 -> IPv6, ICMP Ping/Pong
write_pcap("006-send.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="153.153.153.153", src="102.102.102.102", ttl=64)/ICMP(type=0, id=0x1234, seq=0x8765)/"du hast vyacheslavich",
           Ether(dst="00:00:00:11:11:11", src="00:00:DE:AD:00:00")/Dot1Q(vlan=100)/IP(dst="153.153.153.153", src="102.102.102.102", ttl=64)/ICMP(type=8, id=0x5678, seq=0x4321)/"vitalya 2")

write_pcap("006-expect.pcap",
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:153.153.153.153", src="2000:abcd:fefe:b0b0:c0c0:fea6:102.102.102.102", hlim=63, fl=0)/ICMPv6EchoReply(id=0x1234, seq=0x8765)/"du hast vyacheslavich",
           Ether(dst="00:00:EE:20:66:66", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(dst="6464:6464:6464:6464:6464:6464:153.153.153.153", src="2000:abcd:fefe:b0b0:c0c0:fea6:102.102.102.102", hlim=63, fl=0)/ICMPv6EchoRequest(id=0x5678, seq=0x4321)/"vitalya 2")
