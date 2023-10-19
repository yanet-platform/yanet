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
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.3", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.4", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::2", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::3", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::4", hlim=64)/TCP(dport=80, sport=12380))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0002:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0003:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.3", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0004:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.4", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0001:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0002:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::2", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0003:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::3", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0004:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::4", hlim=64)/TCP(dport=80, sport=12380),
)


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.5", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.6", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.7", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.8", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::5", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::6", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::7", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::8", hlim=64)/TCP(dport=80, sport=12380))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0005:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.5", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0101:0006:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.6", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0007:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.7", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0008:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.8", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0005:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::5", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0006:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::6", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0007:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::7", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0008:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::8", hlim=64)/TCP(dport=80, sport=12380))


write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.3", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.4", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.5", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.6", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.7", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.8", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.1", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.2", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.3", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.4", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.5", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.6", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.7", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.8", ttl=64)/TCP(dport=443, sport=12443))

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::4", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0002:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0101:0003:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.3", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::3", src="2000:51b::0101:0004:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.4", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::4", src="2000:51b::0101:0005:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.5", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0006:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.6", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0101:0007:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.7", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::4", src="2000:51b::0101:0008:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.8", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.1", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0002:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.2", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0003:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.3", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::1", src="2000:51b::0101:0004:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.4", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0005:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.5", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::3", src="2000:51b::0101:0006:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.6", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::4", src="2000:51b::0101:0007:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.7", ttl=64)/TCP(dport=443, sport=12443),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2443::2", src="2000:51b::0101:0008:0:1", hlim=63, fl=0)/IP(dst="10.0.0.2", src="1.1.0.8", ttl=64)/TCP(dport=443, sport=12443))


write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.1", ttl=64)/TCP(dport=8080, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.2", ttl=64)/TCP(dport=8080, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.3", ttl=64)/TCP(dport=8080, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.4", ttl=64)/TCP(dport=8080, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.5", ttl=64)/TCP(dport=8080, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.6", ttl=64)/TCP(dport=8080, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.7", ttl=64)/TCP(dport=8080, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.8", ttl=64)/TCP(dport=8080, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.1", ttl=64)/TCP(dport=4443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.2", ttl=64)/TCP(dport=4443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.3", ttl=64)/TCP(dport=4443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.4", ttl=64)/TCP(dport=4443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.5", ttl=64)/TCP(dport=4443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.6", ttl=64)/TCP(dport=4443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.7", ttl=64)/TCP(dport=4443, sport=12443),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.8", ttl=64)/TCP(dport=4443, sport=12443))

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.1", ttl=63)/TCP(dport=8080, sport=12380),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.2", ttl=63)/TCP(dport=8080, sport=12380),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.3", ttl=63)/TCP(dport=8080, sport=12380),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.4", ttl=63)/TCP(dport=8080, sport=12380),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.5", ttl=63)/TCP(dport=8080, sport=12380),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.6", ttl=63)/TCP(dport=8080, sport=12380),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.7", ttl=63)/TCP(dport=8080, sport=12380),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.8", ttl=63)/TCP(dport=8080, sport=12380),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.1", ttl=63)/TCP(dport=4443, sport=12443),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.2", ttl=63)/TCP(dport=4443, sport=12443),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.3", ttl=63)/TCP(dport=4443, sport=12443),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.4", ttl=63)/TCP(dport=4443, sport=12443),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.5", ttl=63)/TCP(dport=4443, sport=12443),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.6", ttl=63)/TCP(dport=4443, sport=12443),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.7", ttl=63)/TCP(dport=4443, sport=12443),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="10.0.0.2", src="1.1.0.8", ttl=63)/TCP(dport=4443, sport=12443))


# check state
write_pcap("005-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.3", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.4", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::5", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::6", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::7", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::8", hlim=64)/TCP(dport=80, sport=12380))

write_pcap("005-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0002:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0003:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.3", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0004:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.4", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0005:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::5", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0006:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::6", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0007:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::7", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0008:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::8", hlim=64)/TCP(dport=80, sport=12380))


# check real disabled
write_pcap("006-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.3", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.4", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::5", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::6", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::7", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::8", hlim=64)/TCP(dport=80, sport=12380))

write_pcap("006-expect.pcap")


# check real enabled again
write_pcap("007-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.3", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.4", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::5", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::6", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::7", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::8", hlim=64)/TCP(dport=80, sport=12380))

write_pcap("007-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0001:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0002:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0003:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.3", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0101:0004:0:1", hlim=63, fl=0)/IP(dst="10.0.0.1", src="1.1.0.4", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0005:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::5", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2000:51b::0006:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::6", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0007:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::7", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::0008:0:1", hlim=63, fl=0)/IPv6(dst="2001:dead:beef::1", src="2002::8", hlim=64)/TCP(dport=80, sport=12380))


# check fragments
write_pcap("008-send.pcap",
           fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380)/("ABCDEFGH123CCCCCCCCC"*120)/"QWERTY123", fragsize=1208),
           fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380)/("ABCDEFGH123CCCCCCCCC"*120)/"QWERTY123", fragsize=1208),
           fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.3", ttl=64)/TCP(dport=80, sport=12380)/("ABCDEFGH123CCCCCCCCC"*120)/"QWERTY123", fragsize=1208),
           fragment(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.4", ttl=64)/TCP(dport=80, sport=12380)/("ABCDEFGH123CCCCCCCCC"*120)/"QWERTY123", fragsize=1208),
           fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::5", hlim=64)/IPv6ExtHdrFragment(id=0x31337)/TCP(dport=80, sport=12380)/("ABCDEFGH123CCCCCCCCC"*120)/"QWERTY123", fragSize=1280),
           fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::6", hlim=64)/IPv6ExtHdrFragment(id=0x31338)/TCP(dport=80, sport=12380)/("ABCDEFGH123CCCCCCCCC"*120)/"QWERTY123", fragSize=1280),
           fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::7", hlim=64)/IPv6ExtHdrFragment(id=0x31339)/TCP(dport=80, sport=12380)/("ABCDEFGH123CCCCCCCCC"*120)/"QWERTY123", fragSize=1280),
           fragment6(Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::1", src="2002::8", hlim=64)/IPv6ExtHdrFragment(id=0x31330)/TCP(dport=80, sport=12380)/("ABCDEFGH123CCCCCCCCC"*120)/"QWERTY123", fragSize=1280))

write_pcap("008-expect.pcap")
