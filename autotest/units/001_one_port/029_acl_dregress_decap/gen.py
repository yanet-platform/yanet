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


write_pcap("001-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="1234::abcd", src="2000::", fl=0x12345, hlim=64)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=64)/TCP(dport=80, sport=2048))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="90.90.90.0/30", src="5.5.5.0/30", ttl=63)/TCP(dport=80, sport=2048))


write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.0/30", src="5.5.5.55", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="daad::0", fl=0x12345, hlim=64)/IP(dst="6.7.8.0", src="5.5.5.80", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="daad::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.0", src="5.5.5.81", ttl=64)/TCP(dport=80, sport=2048))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0xbe62 | 0xc000, chksum=0)/MPLS(label=110, ttl=255)/IP(dst="6.7.8.0", src="5.5.5.55", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0x682a | 0xc000, chksum=0)/MPLS(label=111, ttl=255)/IP(dst="6.7.8.1", src="5.5.5.55", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0x6403 | 0xc000, chksum=0)/MPLS(label=112, ttl=255)/IP(dst="6.7.8.2", src="5.5.5.55", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0xb24b | 0xc000, chksum=0)/MPLS(label=113, ttl=255)/IP(dst="6.7.8.3", src="5.5.5.55", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0x58d3 | 0xc000, chksum=0)/MPLS(label=110, ttl=255)/IP(dst="6.7.8.0", src="5.5.5.80", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0x60b6 | 0xc000, chksum=0)/MPLS(label=110, ttl=255)/IP(dst="6.7.8.0", src="5.5.5.81", ttl=64)/TCP(dport=80, sport=2048))


TCP_SYNACK = TCP(sport=8800, dport=555, flags='SA', seq=3535)
TCP_ACK1_1 = TCP(sport=8800, dport=555, flags='A', seq=TCP_SYNACK.seq + 1, options=[("NOP", None), (253, "\x79\x61\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")])/"luchshe prosto pozvonit'"
TCP_ACK2_1 = TCP(sport=8800, dport=555, flags='A', seq=TCP_ACK1_1.seq + 24, options=[("NOP", None), (253, "\x79\x61\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09")])/"chem u kogo-to zanimat'"
TCP_ACK1_2 = TCP(sport=8800, dport=555, flags='A', seq=TCP_SYNACK.seq + 1, options=[("Timestamp", (0, 0)), (253, "\x79\x61\x00\x00\x00\x00\x09\x00\x00\x00\x00\x09")])/"luchshe prosto pozvonit'"
TCP_ACK2_2 = TCP(sport=8800, dport=555, flags='A', seq=TCP_ACK1_2.seq + 24, options=[("NOP", None), ("NOP", None), (253, "\x79\x61\x00\x00\x00\x00\x09\x09\x00\x00\x09\x09")])/"chem u kogo-to zanimat'"

write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.6", src="5.5.5.66", ttl=64)/TCP_SYNACK,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.6", src="5.5.5.66", ttl=64)/TCP_ACK1_1,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.6", src="5.5.5.66", ttl=64)/TCP_ACK2_1,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.6", src="5.5.5.66", ttl=64)/TCP_ACK1_2,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.6", src="5.5.5.66", ttl=64)/TCP_ACK2_2)

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0x974e | 0xc000, chksum=0)/MPLS(label=114, ttl=255)/IP(dst="6.7.8.6", src="5.5.5.66", ttl=64)/TCP_SYNACK,
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0x974e | 0xc000, chksum=0)/MPLS(label=114, ttl=255)/IP(dst="6.7.8.6", src="5.5.5.66", ttl=64)/TCP_ACK1_1,
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0x974e | 0xc000, chksum=0)/MPLS(label=114, ttl=254)/IP(dst="6.7.8.6", src="5.5.5.66", ttl=64)/TCP_ACK2_1,
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0x974e | 0xc000, chksum=0)/MPLS(label=114, ttl=253)/IP(dst="6.7.8.6", src="5.5.5.66", ttl=64)/TCP_ACK1_2,
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0x974e | 0xc000, chksum=0)/MPLS(label=114, ttl=252)/IP(dst="6.7.8.6", src="5.5.5.66", ttl=64)/TCP_ACK2_2)


write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_SYNACK,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_ACK1_1,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_ACK2_1,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_SYNACK,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_ACK1_1,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_ACK2_1)

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0xaf2b | 0xc000, chksum=0)/MPLS(label=114, ttl=255)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_SYNACK,
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0xaf2b | 0xc000, chksum=0)/MPLS(label=114, ttl=255)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_ACK1_1,
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0xaf2b | 0xc000, chksum=0)/MPLS(label=114, ttl=254)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_ACK2_1,
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0xaf2b | 0xc000, chksum=0)/MPLS(label=114, ttl=255)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_SYNACK,
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0xaf2b | 0xc000, chksum=0)/MPLS(label=114, ttl=255)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_ACK1_1,
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0xaf2b | 0xc000, chksum=0)/MPLS(label=114, ttl=254)/IP(dst="6.7.8.6", src="5.5.5.67", ttl=64)/TCP_ACK2_1)


write_pcap("005-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="7.0.0.1", src="5.5.5.55", ttl=64)/TCP(dport=80, sport=2048))

write_pcap("005-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="200.0.0.1", src="10.50.0.1", ttl=63)/UDP(dport=6635, sport=0x0b40 | 0xc000, chksum=0)/MPLS(label=115, ttl=255)/IP(dst="7.0.0.1", src="5.5.5.55", ttl=64)/TCP(dport=80, sport=2048))


# 'local' packet
write_pcap("006-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IP(dst="7.0.0.2/31", src="5.5.5.55", ttl=64)/TCP(dport=80, sport=2048))

write_pcap("006-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="7.0.0.2/31", src="5.5.5.55", ttl=63)/TCP(dport=80, sport=2048))


write_pcap("007-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="daad::2", fl=0x12345, hlim=64)/IP(dst="6.7.8.0", src="5.5.5.82", ttl=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="daad::3", fl=0x12345, hlim=64)/IP(dst="6.7.8.0", src="5.5.5.83", ttl=64)/TCP(dport=80, sport=2048))

write_pcap("007-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="6.7.8.0", src="5.5.5.82", ttl=63)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="6.7.8.0", src="5.5.5.83", ttl=63)/TCP(dport=80, sport=2048))


write_pcap("008-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="b0b0::1", src="cafe::1", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::", src="cafe::2", hlim=64)/TCP(dport=80, sport=2048))

write_pcap("008-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="b0b0::1", src="cafe::1", hlim=63)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="cccc::", src="cafe::2", hlim=63)/TCP(dport=80, sport=2048))


write_pcap("009-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::1", src="cafe::2", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="daad::0", fl=0x12345, hlim=64)/IPv6(dst="cccc::100", src="cafe::3", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="daad::1", fl=0x12345, hlim=64)/IPv6(dst="dddd::200", src="cafe::4", hlim=64)/TCP(dport=80, sport=2048))

write_pcap("009-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0xa0b8 | 0xc000, chksum=0)/MPLS(label=210, ttl=255)/IPv6(dst="cccc::1", src="cafe::2", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0xc6c8 | 0xc000, chksum=0)/MPLS(label=210, ttl=255)/IPv6(dst="cccc::100", src="cafe::3", hlim=64)/TCP(dport=80, sport=2048),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="cbcb::1", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0x3b9f | 0xc000, chksum=0)/MPLS(label=211, ttl=255)/IPv6(dst="dddd::200", src="cafe::4", hlim=64)/TCP(dport=80, sport=2048))


write_pcap("010-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::6", src="cafe::2", hlim=64)/TCP_SYNACK,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::6", src="cafe::2", hlim=64)/TCP_ACK1_1,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::6", src="cafe::2", hlim=64)/TCP_ACK2_1,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::6", src="cafe::2", hlim=64)/TCP_ACK1_2,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::6", src="cafe::2", hlim=64)/TCP_ACK2_2)

write_pcap("010-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0xd4e4 | 0xc000, chksum=0)/MPLS(label=210, ttl=255)/IPv6(dst="cccc::6", src="cafe::2", hlim=64)/TCP_SYNACK,
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0xd4e4 | 0xc000, chksum=0)/MPLS(label=210, ttl=255)/IPv6(dst="cccc::6", src="cafe::2", hlim=64)/TCP_ACK1_1,
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0xd4e4 | 0xc000, chksum=0)/MPLS(label=210, ttl=254)/IPv6(dst="cccc::6", src="cafe::2", hlim=64)/TCP_ACK2_1,
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0xd4e4 | 0xc000, chksum=0)/MPLS(label=210, ttl=253)/IPv6(dst="cccc::6", src="cafe::2", hlim=64)/TCP_ACK1_2,
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0xd4e4 | 0xc000, chksum=0)/MPLS(label=210, ttl=252)/IPv6(dst="cccc::6", src="cafe::2", hlim=64)/TCP_ACK2_2)


write_pcap("011-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_SYNACK,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_ACK1_1,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_ACK2_1,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_SYNACK,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_ACK1_1,
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="1234::abcd", src="abba::1", fl=0x12345, hlim=64)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_ACK2_1)

write_pcap("011-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0x6daa | 0xc000, chksum=0)/MPLS(label=210, ttl=255)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_SYNACK,
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0x6daa | 0xc000, chksum=0)/MPLS(label=210, ttl=255)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_ACK1_1,
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0x6daa | 0xc000, chksum=0)/MPLS(label=210, ttl=254)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_ACK2_1,
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0x6daa | 0xc000, chksum=0)/MPLS(label=210, ttl=255)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_SYNACK,
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0x6daa | 0xc000, chksum=0)/MPLS(label=210, ttl=255)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_ACK1_1,
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="caca::123", src="2222:9876:0:1234:aeae:0101:fefe:ca11", hlim=63)/UDP(dport=6635, sport=0x6daa | 0xc000, chksum=0)/MPLS(label=210, ttl=254)/IPv6(dst="cccc::6", src="cafe::4", hlim=64)/TCP_ACK2_1)

# @todo: ipv6 ext
