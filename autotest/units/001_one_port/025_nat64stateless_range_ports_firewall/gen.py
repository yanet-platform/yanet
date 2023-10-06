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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(sport=443, dport=(12000,12005), flags="S"),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(sport=443, dport=(12000,12005), flags="FPU"),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(sport=443, dport=(12000,12005), flags=""),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/UDP(sport=50, dport=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/UDP(sport=53, dport=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=0, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=8, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(sport=443, dport=(12000,12005), flags="SA"),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(sport=443, dport=(12000,12005), flags="A"),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(sport=443, dport=(22000,22005), flags="S"),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(sport=443, dport=(22000,22005), flags="FPU"),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(sport=443, dport=(22000,22005), flags=""),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/UDP(sport=50, dport=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/UDP(sport=53, dport=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=0, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=8, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(sport=443, dport=(22000,22005), flags="SA"),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/TCP(sport=443, dport=(22000,22005), flags="A"),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/GRE())

write_pcap("001-expect.pcap",
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/UDP(dport=(2001,2004), sport=53),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/ICMPv6EchoReply(id=(2001,2004)),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/TCP(dport=(2001,2004), sport=443, flags="SA"),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/TCP(dport=(2001,2004), sport=443, flags="A"),

           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:bbbb", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/TCP(dport=(2001,2004), sport=443, flags="S"),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:bbbb", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/TCP(dport=(2001,2004), sport=443, flags="FPU"),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:bbbb", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/TCP(dport=(2001,2004), sport=443, flags=""),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:bbbb", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/UDP(dport=(2001,2004), sport=50),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:bbbb", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/UDP(dport=(2001,2004), sport=53),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:bbbb", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/ICMPv6EchoReply(id=(2001,2004)),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:bbbb", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/TCP(dport=(2001,2004), sport=443, flags="SA"),
           Ether(src="00:11:22:33:44:55", dst="00:00:00:11:11:11")/Dot1Q(vlan=100)/IPv6(dst="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:bbbb", src="5555:5555:5555:5555:5555:5555:10.99.99.99", hlim=63)/TCP(dport=(2001,2004), sport=443, flags="A"))


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=3, id=(12000,12005))/IP(dst="10.99.99.99", src="10.88.88.88")/TCP(), # todo: tcp ports
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=4, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=5, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=9, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=10, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=11, id=(12000,12005))/IP(dst="10.99.99.99", src="10.88.88.88")/TCP(), # todo: tcp ports
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=12, id=(12000,12005), ptr=13)/IP(dst="10.99.99.99", src="10.88.88.88")/TCP(), # todo: tcp ports
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=13, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=14, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=15, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=16, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=17, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=18, id=(12000,12005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=30, id=(12000,12005)),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=3, id=(22000,22005))/IP(dst="10.99.99.99", src="10.88.88.88")/TCP(), # todo: tcp ports
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=4, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=5, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=9, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=10, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=11, id=(22000,22005))/IP(dst="10.99.99.99", src="10.88.88.88")/TCP(), # todo: tcp ports
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=12, id=(22000,22005), ptr=13)/IP(dst="10.99.99.99", src="10.88.88.88")/TCP(), # todo: tcp ports
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=13, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=14, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=15, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=16, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=17, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=18, id=(22000,22005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=200)/IP(dst="10.88.88.88", src="10.99.99.99")/ICMP(type=30, id=(22000,22005)))

write_pcap("002-expect.pcap")


write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/TCP(dport=443, sport=(2000,2005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/UDP(dport=50, sport=(2000,2005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/UDP(dport=53, sport=(2000,2005)),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:bbbb", hlim=64)/TCP(dport=443, sport=(2000,2005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:bbbb", hlim=64)/UDP(dport=50, sport=(2000,2005)),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:bbbb", hlim=64)/UDP(dport=53, sport=(2000,2005)),

           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="5555:5555:5555:5555:5555:5555:102.102.102.103", src="aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", hlim=64)/GRE())

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="10.88.88.88", ttl=63, id=0)/TCP(dport=443, sport=(12001,12004)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="10.88.88.88", ttl=63, id=0)/UDP(dport=50, sport=(12001,12004)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="10.88.88.88", ttl=63, id=0)/UDP(dport=53, sport=(12001,12004)),

           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="10.88.88.88", ttl=63, id=0)/TCP(dport=443, sport=(22001,22004)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="10.88.88.88", ttl=63, id=0)/UDP(dport=50, sport=(22001,22004)),
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="102.102.102.103", src="10.88.88.88", ttl=63, id=0)/UDP(dport=53, sport=(22001,22004)))
