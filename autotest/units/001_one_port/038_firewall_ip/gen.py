#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List

from scapy.layers.inet import UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet
from scapy.utils import PcapWriter


def write_pcap(path: str, packets: List[Packet]) -> None:
    with PcapWriter(path) as fh:
        for p in packets:
            fh.write(p)


def ipv6_send(src: str, dst: str) -> Packet:
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22") / \
           Dot1Q(vlan=200) / \
           IPv6(src=src, dst=dst, hlim=64, fl=0)


def ipv6_recv(src: str, dst: str) -> Packet:
    return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55") / \
           Dot1Q(vlan=100) / \
           IPv6(src=src, dst=dst, hlim=63, fl=0)


write_pcap("001-send.pcap", [
    # Drop.
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2030::1") / UDP(sport=(1024, 1040), dport=53),
    # Allow.
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2030::1") / UDP(sport=10000, dport=54),
])

write_pcap("001-expect.pcap", [
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2030::1") / UDP(sport=10000, dport=54),
])
