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


packages1 = [Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.1.0.55", src=f"1.{a_h}.{a_m}.{a_l}", ttl=64) / TCP(dport=443, sport=sport)
             for sport in (12443, 12444) for a_h in range(4) for a_m in range(2) for a_l in range(4)]
packages2 = [Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.1.0.55", src=f"1.{a_h}.{a_m}.{a_l}", ttl=64) / TCP(dport=443, sport=sport)
             for sport in (11443, 11444) for a_h in range(4) for a_m in range(0, 2) for a_l in range(4)]
packages3 = [Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.1.0.55", src=f"1.{a_h}.{a_m}.{a_l}", ttl=64) / TCP(dport=443, sport=sport)
             for sport in (11443, 11444) for a_h in range(2) for a_m in range(2, 4) for a_l in range(4)]

write_pcap("001-send.pcap", *packages1)
write_pcap("002-send.pcap", *packages2)
write_pcap("003-send.pcap", *packages3)
