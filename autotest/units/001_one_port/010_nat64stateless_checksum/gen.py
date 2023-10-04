#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *


def write_pcap(filename, *packetsList):
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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/TCP(dport=22, sport=(1,65535)))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="153.153.153.153", ttl=63, id=0)/TCP(dport=22, sport=(1,65535)))


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="153.153.153.153", src="102.102.102.102", ttl=64)/TCP(dport=(1,65535), sport=80))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:102.102.102.102", hlim=63, fl=0)/TCP(dport=(1,65535), sport=80))


write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/UDP(dport=22, sport=(1,56740)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/UDP(dport=22, sport=56741, chksum=0xffff),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/UDP(dport=22, sport=(56742,65535)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/UDP(dport=80, sport=80, chksum=0))

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="153.153.153.153", ttl=63, id=0)/UDP(dport=22, sport=(1,65478)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="153.153.153.153", ttl=63, id=0)/UDP(dport=22, sport=65479, chksum=0xffff),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="153.153.153.153", ttl=63, id=0)/UDP(dport=22, sport=(65480,65535)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="153.153.153.153", ttl=63, id=0)/UDP(dport=80, sport=80, chksum=0))


write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="153.153.153.153", src="102.102.102.102", ttl=64)/UDP(dport=(1,65421), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="153.153.153.153", src="102.102.102.102", ttl=64)/UDP(dport=65422, sport=80, chksum=0xffff),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="153.153.153.153", src="102.102.102.102", ttl=64)/UDP(dport=(65423,65535), sport=80),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="153.153.153.153", src="102.102.102.102", ttl=64)/UDP(dport=22, sport=22, chksum=0))

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:102.102.102.102", hlim=63, fl=0)/UDP(dport=(1,56683), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:102.102.102.102", hlim=63, fl=0)/UDP(dport=56684, sport=80, chksum=0xffff),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:102.102.102.102", hlim=63, fl=0)/UDP(dport=(56685,65535), sport=80),
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:102.102.102.102", hlim=63, fl=0)/UDP(dport=22, sport=22, chksum=0))


write_pcap("005-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:1.1.0.0/112", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/TCP(dport=80, sport=2048))

write_pcap("005-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.1.0.0/16", src="153.153.153.153", ttl=63, id=0)/TCP(dport=80, sport=2048))


write_pcap("006-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.102", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/ICMPv6EchoRequest(id=(0,65535), seq=0x8765)/"pelmeni boyarskie")

write_pcap("006-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.102", src="153.153.153.153", ttl=63, id=0)/ICMP(type=8, id=(0,65535), seq=0x8765)/"pelmeni boyarskie")


write_pcap("007-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="153.153.153.153", src="102.102.102.102", ttl=64)/ICMP(type=0, id=(0,65535), seq=0x8765)/"pelmeni boyarskie")

write_pcap("007-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:102.102.102.102", hlim=63, fl=0)/ICMPv6EchoReply(id=(0,65535), seq=0x8765)/"pelmeni boyarskie")

