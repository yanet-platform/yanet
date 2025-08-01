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


# No MarkType
write_pcap(
    "001-send.pcap",
    # Outer: IPv6; Inner: IPv4
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.0.0.3", src="1.1.0.1", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.0.0.3", src="1.1.0.2", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.0.0.3", src="1.1.0.3", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.0.0.3", src="1.1.0.4", ttl=64) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv4
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.0.0.16", src="1.1.0.1", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.0.0.16", src="1.1.0.2", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.0.0.16", src="1.1.0.3", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.0.0.16", src="1.1.0.4", ttl=64) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv6
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64) / TCP(dport=80, sport=12380),
    # Outer: IPv6; Inner: IPv6
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2005:dead:beef::1", src="2002::10", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2005:dead:beef::1", src="2002::11", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2005:dead:beef::1", src="2002::12", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2005:dead:beef::1", src="2002::13", hlim=64) / TCP(dport=80, sport=12380),
)

write_pcap(
    "001-expect.pcap",
    # Outer: IPv6; Inner: IPv4
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2000:51b::0101:0001:0:1", hlim=63, fl=0) / IP(dst="10.0.0.3", src="1.1.0.1", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::1", src="2000:51b::0101:0002:0:1", hlim=63, fl=0) / IP(dst="10.0.0.3", src="1.1.0.2", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2000:51b::0101:0003:0:1", hlim=63, fl=0) / IP(dst="10.0.0.3", src="1.1.0.3", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::1", src="2000:51b::0101:0004:0:1", hlim=63, fl=0) / IP(dst="10.0.0.3", src="1.1.0.4", ttl=64) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv4
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.2", src="100.0.0.22", ttl=63) / IP(dst="10.0.0.16", src="1.1.0.1", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.1", src="100.0.0.22", ttl=63) / IP(dst="10.0.0.16", src="1.1.0.2", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.2", src="100.0.0.22", ttl=63) / IP(dst="10.0.0.16", src="1.1.0.3", ttl=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.1", src="100.0.0.22", ttl=63) / IP(dst="10.0.0.16", src="1.1.0.4", ttl=64) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv6
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.7", src="100.0.0.22", ttl=63) / IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.6", src="100.0.0.22", ttl=63) / IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.7", src="100.0.0.22", ttl=63) / IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.6", src="100.0.0.22", ttl=63) / IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64) / TCP(dport=80, sport=12380),
    # Outer: IPv6; Inner: IPv6
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::2", src="2000:51b::0000:0010:0:1", hlim=63, fl=0) / IPv6(dst="2005:dead:beef::1", src="2002::10", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::1", src="2000:51b::0000:0011:0:1", hlim=63, fl=0) / IPv6(dst="2005:dead:beef::1", src="2002::11", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::2", src="2000:51b::0000:0012:0:1", hlim=63, fl=0) / IPv6(dst="2005:dead:beef::1", src="2002::12", hlim=64) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::1", src="2000:51b::0000:0013:0:1", hlim=63, fl=0) / IPv6(dst="2005:dead:beef::1", src="2002::13", hlim=64) / TCP(dport=80, sport=12380),
)

# MarkType = always: replace initial first six bits of TOS with value from config
write_pcap(
    "002-send.pcap",
    # Outer: IPv6; Inner: IPv4
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IP(dst="10.0.0.3", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IP(dst="10.0.0.3", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IP(dst="10.0.0.3", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IP(dst="10.0.0.3", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv4
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IP(dst="10.0.0.16", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IP(dst="10.0.0.16", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IP(dst="10.0.0.16", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IP(dst="10.0.0.16", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv6
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv6; Inner: IPv6
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IPv6(dst="2005:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IPv6(dst="2005:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IPv6(dst="2005:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=201) / IPv6(dst="2005:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
)

write_pcap(
    "002-expect.pcap",
    # Outer: IPv6; Inner: IPv4
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2000:51b::0101:0001:0:1", hlim=63, fl=0, tc=0xA0) / IP(dst="10.0.0.3", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::1", src="2000:51b::0101:0002:0:1", hlim=63, fl=0, tc=0xA0) / IP(dst="10.0.0.3", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2000:51b::0101:0003:0:1", hlim=63, fl=0, tc=0xA0) / IP(dst="10.0.0.3", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::1", src="2000:51b::0101:0004:0:1", hlim=63, fl=0, tc=0xA3) / IP(dst="10.0.0.3", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv4
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.2", src="100.0.0.22", ttl=63, tos=0xA0) / IP(dst="10.0.0.16", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.1", src="100.0.0.22", ttl=63, tos=0xA0) / IP(dst="10.0.0.16", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.2", src="100.0.0.22", ttl=63, tos=0xA0) / IP(dst="10.0.0.16", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.1", src="100.0.0.22", ttl=63, tos=0xA3) / IP(dst="10.0.0.16", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv6
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.7", src="100.0.0.22", ttl=63, tos=0xA0) / IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.6", src="100.0.0.22", ttl=63, tos=0xA0) / IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.7", src="100.0.0.22", ttl=63, tos=0xA0) / IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.6", src="100.0.0.22", ttl=63, tos=0xA3) / IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv6; Inner: IPv6
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::2", src="2000:51b::0000:0010:0:1", hlim=63, fl=0, tc=0xA0) / IPv6(dst="2005:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::1", src="2000:51b::0000:0011:0:1", hlim=63, fl=0, tc=0xA0) / IPv6(dst="2005:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::2", src="2000:51b::0000:0012:0:1", hlim=63, fl=0, tc=0xA0) / IPv6(dst="2005:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::1", src="2000:51b::0000:0013:0:1", hlim=63, fl=0, tc=0xA3) / IPv6(dst="2005:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
)

# MarkType = onlyDefault: replace initial first six bits of TOS with value from config if packet was not marked, otherwise keep the original mark
write_pcap(
    "003-send.pcap",
    # Outer: IPv6; Inner: IPv4
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IP(dst="10.0.0.3", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IP(dst="10.0.0.3", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IP(dst="10.0.0.3", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IP(dst="10.0.0.3", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv4
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IP(dst="10.0.0.16", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IP(dst="10.0.0.16", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IP(dst="10.0.0.16", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IP(dst="10.0.0.16", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv6
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv6; Inner: IPv6
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IPv6(dst="2005:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IPv6(dst="2005:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IPv6(dst="2005:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=202) / IPv6(dst="2005:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
)

write_pcap(
    "003-expect.pcap",
    # Outer: IPv6; Inner: IPv4
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2000:51b::0101:0001:0:1", hlim=63, fl=0, tc=0xA0) / IP(dst="10.0.0.3", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::1", src="2000:51b::0101:0002:0:1", hlim=63, fl=0, tc=0x04) / IP(dst="10.0.0.3", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2000:51b::0101:0003:0:1", hlim=63, fl=0, tc=0xFC) / IP(dst="10.0.0.3", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::1", src="2000:51b::0101:0004:0:1", hlim=63, fl=0, tc=0xFF) / IP(dst="10.0.0.3", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv4
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.2", src="100.0.0.22", ttl=63, tos=0xA0) / IP(dst="10.0.0.16", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.1", src="100.0.0.22", ttl=63, tos=0x04) / IP(dst="10.0.0.16", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.2", src="100.0.0.22", ttl=63, tos=0xFC) / IP(dst="10.0.0.16", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.1", src="100.0.0.22", ttl=63, tos=0xFF) / IP(dst="10.0.0.16", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv6
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.7", src="100.0.0.22", ttl=63, tos=0xA0) / IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.6", src="100.0.0.22", ttl=63, tos=0x04) / IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.7", src="100.0.0.22", ttl=63, tos=0xFC) / IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.6", src="100.0.0.22", ttl=63, tos=0xFF) / IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv6; Inner: IPv6
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::2", src="2000:51b::0000:0010:0:1", hlim=63, fl=0, tc=0xA0) / IPv6(dst="2005:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::1", src="2000:51b::0000:0011:0:1", hlim=63, fl=0, tc=0x04) / IPv6(dst="2005:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::2", src="2000:51b::0000:0012:0:1", hlim=63, fl=0, tc=0xFC) / IPv6(dst="2005:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::1", src="2000:51b::0000:0013:0:1", hlim=63, fl=0, tc=0xFF) / IPv6(dst="2005:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
)

# MarkType = never
write_pcap(
    "004-send.pcap",
    # Outer: IPv6; Inner: IPv4
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IP(dst="10.0.0.3", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IP(dst="10.0.0.3", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IP(dst="10.0.0.3", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IP(dst="10.0.0.3", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv4
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IP(dst="10.0.0.16", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IP(dst="10.0.0.16", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IP(dst="10.0.0.16", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IP(dst="10.0.0.16", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv6
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv6; Inner: IPv6
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IPv6(dst="2005:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IPv6(dst="2005:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IPv6(dst="2005:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=203) / IPv6(dst="2005:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
)

write_pcap(
    "004-expect.pcap",
    # Outer: IPv6; Inner: IPv4
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2000:51b::0101:0001:0:1", hlim=63, fl=0, tc=0x0) / IP(dst="10.0.0.3", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::1", src="2000:51b::0101:0002:0:1", hlim=63, fl=0, tc=0x4) / IP(dst="10.0.0.3", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2000:51b::0101:0003:0:1", hlim=63, fl=0, tc=0xFC) / IP(dst="10.0.0.3", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::1", src="2000:51b::0101:0004:0:1", hlim=63, fl=0, tc=0xFF) / IP(dst="10.0.0.3", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv4
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.2", src="100.0.0.22", ttl=63, tos=0x0) / IP(dst="10.0.0.16", src="1.1.0.1", ttl=64, tos=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.1", src="100.0.0.22", ttl=63, tos=0x4) / IP(dst="10.0.0.16", src="1.1.0.2", ttl=64, tos=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.2", src="100.0.0.22", ttl=63, tos=0xFC) / IP(dst="10.0.0.16", src="1.1.0.3", ttl=64, tos=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.1", src="100.0.0.22", ttl=63, tos=0xFF) / IP(dst="10.0.0.16", src="1.1.0.4", ttl=64, tos=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv4; Inner: IPv6
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.7", src="100.0.0.22", ttl=63, tos=0x0) / IPv6(dst="2004:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.6", src="100.0.0.22", ttl=63, tos=0x4) / IPv6(dst="2004:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.7", src="100.0.0.22", ttl=63, tos=0xFC) / IPv6(dst="2004:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IP(dst="100.0.0.6", src="100.0.0.22", ttl=63, tos=0xFF) / IPv6(dst="2004:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
    # Outer: IPv6; Inner: IPv6
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::2", src="2000:51b::0000:0010:0:1", hlim=63, fl=0, tc=0x0) / IPv6(dst="2005:dead:beef::1", src="2002::10", hlim=64, tc=0x0) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::1", src="2000:51b::0000:0011:0:1", hlim=63, fl=0, tc=0x04) / IPv6(dst="2005:dead:beef::1", src="2002::11", hlim=64, tc=0x04) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::2", src="2000:51b::0000:0012:0:1", hlim=63, fl=0, tc=0xFC) / IPv6(dst="2005:dead:beef::1", src="2002::12", hlim=64, tc=0xFC) / TCP(dport=80, sport=12380),
    Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2010::1", src="2000:51b::0000:0013:0:1", hlim=63, fl=0, tc=0xFF) / IPv6(dst="2005:dead:beef::1", src="2002::13", hlim=64, tc=0xFF) / TCP(dport=80, sport=12380),
)
