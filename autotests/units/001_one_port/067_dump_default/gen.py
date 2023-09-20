#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List

from scapy.layers.inet import UDP, TCP, IP, fragment
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet
from scapy.utils import PcapWriter


def write_pcap(path: str, packets: List[Packet]) -> None:
    with PcapWriter(path) as fh:
        for p in packets:
            fh.write(p)


def ipv4_send(src: str, dst: str) -> Packet:
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11") / Dot1Q(vlan=100) / IP(src=src, dst=dst, ttl=64)


def ipv4_recv(src: str, dst: str) -> Packet:
    return Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55") / Dot1Q(vlan=200) / IP(src=src, dst=dst, ttl=63)


write_pcap("001-send.pcap", [
    fragment(ipv4_send("10.0.0.1", "1.2.3.4") / UDP(sport=1024, dport=53)/("ABCDEFGH1234AAAAAAAA"*128), fragsize=1208),
    ipv4_send("10.0.0.1", "1.2.3.4") / UDP(sport=1024, dport=53),
    ipv4_send("10.0.0.1", "1.2.3.4") / TCP(sport=1024, dport=53),
])

write_pcap("001-expect.pcap", [
    ipv4_recv("10.0.0.1", "1.2.3.4") / TCP(sport=1024, dport=53),
])

write_pcap("001-expect-dump-ring1.pcap", [
    ipv4_send("10.0.0.1", "1.2.3.4") / TCP(sport=1024, dport=53),
])
