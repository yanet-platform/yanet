#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List

from scapy.layers.inet import TCP, IP
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


def ipv6_send(src: str, dst: str) -> Packet:
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22") / \
           Dot1Q(vlan=200) / \
           IPv6(src=src, dst=dst, hlim=64, fl=0)


def ipv6_recv(src: str, dst: str) -> Packet:
    return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55") / \
           Dot1Q(vlan=100) / \
           IPv6(src=src, dst=dst, hlim=63, fl=0)


write_pcap("001-send.pcap", [
    # Direct ...
    ipv6_send("1111:2222::1", "2111:aaa:ff1c:2030::1") / TCP(sport=(1024, 1025), dport=53),
    # ... and reverse.
    ipv6_send("2111:aaa:ff1c:2030::1", "1111:2222::1") / TCP(sport=53, dport=(1024, 1025)),
    # Drop: different dst port.
    ipv6_send("1111:2222::1", "2111:aaa:ff1c:2030::1") / TCP(sport=10000, dport=54),
    # Drop: different dst addr.
    ipv6_send("1111:2222::1", "2111:aaa:ff1c:2040::ff") / TCP(sport=10000, dport=53),
])

write_pcap("001-expect.pcap", [
    ipv6_recv("1111:2222::1", "2111:aaa:ff1c:2030::1") / TCP(sport=(1024, 1025), dport=53),
    ipv6_recv("2111:aaa:ff1c:2030::1", "1111:2222::1") / TCP(sport=53, dport=(1024, 1025)),
])

write_pcap("002-send.pcap", [
    # Direct ...
    ipv4_send("11.0.0.1", "1.1.1.1") / TCP(sport=(1024, 1025), dport=53),
    # ... and reverse.
    ipv4_send("1.1.1.1", "11.0.0.1") / TCP(sport=53, dport=(1024, 1025)),
    # Drop: different dst port.
    ipv4_send("11.0.0.1", "1.1.1.1") / TCP(sport=10000, dport=54),
    # Drop: different src addr.
    ipv4_send("11.0.1.1", "1.1.1.1") / TCP(sport=10000, dport=53),
])

write_pcap("002-expect.pcap", [
    ipv4_recv("11.0.0.1", "1.1.1.1") / TCP(sport=(1024, 1025), dport=53),
    ipv4_recv("1.1.1.1", "11.0.0.1") / TCP(sport=53, dport=(1024, 1025)),
])
