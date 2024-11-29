#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List, Optional

from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet
from scapy.utils import PcapWriter


def write_pcap(path: str, packets: List[Packet], linktype: Optional[int] = None) -> None:
    with PcapWriter(path, sync=True, linktype=linktype) as fh:
        for p in packets:
            fh.write(p)


def ipv4_send(src: str, dst: str, proto: Packet, payload_size: int) -> Packet:
    payload = b"A" * payload_size
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11") / \
           Dot1Q(vlan=100) / \
           IP(src=src, dst=dst, ttl=64) / \
           proto / \
           payload


def ipv4_recv(src: str, dst: str, proto: Packet, payload_size: int) -> Packet:
    payload = b"A" * payload_size
    return Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55") / \
           Dot1Q(vlan=200) / \
           IP(src=src, dst=dst, ttl=63) / \
           proto / \
           payload


def ipv6_send(src: str, dst: str, proto: Packet, payload_size: int) -> Packet:
    payload = b"B" * payload_size
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22") / \
           Dot1Q(vlan=200) / \
           IPv6(src=src, dst=dst, hlim=64, fl=0) / \
           proto / \
           payload


def ipv6_recv(src: str, dst: str, proto: Packet, payload_size: int) -> Packet:
    payload = b"B" * payload_size
    return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55") / \
           Dot1Q(vlan=100) / \
           IPv6(src=src, dst=dst, hlim=63, fl=0) / \
           proto / \
           payload

write_pcap("001-send.pcap", [
    ipv4_send("11.0.0.1", "1.1.1.1", TCP(sport=1024, dport=53, flags="S"), payload_size=50),
    ipv4_send("1.1.1.1", "11.0.0.1", TCP(sport=53, dport=1024, flags="S"), payload_size=30),
])

write_pcap("001-expect.pcap", [
    ipv4_recv("11.0.0.1", "1.1.1.1", TCP(sport=1024, dport=53, flags="S"), payload_size=50),
    ipv4_recv("1.1.1.1", "11.0.0.1", TCP(sport=53, dport=1024, flags="S"), payload_size=30),
])

write_pcap("002-send.pcap", [
    ipv6_send("1111:2222::1", "2111:aaa:ff1c:2030::1", TCP(sport=1024, dport=53, flags="S"), payload_size=60),
    ipv6_send("2111:aaa:ff1c:2030::1", "1111:2222::1", TCP(sport=53, dport=1024, flags="S"), payload_size=40),
])

write_pcap("002-expect.pcap", [
    ipv6_recv("1111:2222::1", "2111:aaa:ff1c:2030::1", TCP(sport=1024, dport=53, flags="S"), payload_size=60),
    ipv6_recv("2111:aaa:ff1c:2030::1", "1111:2222::1", TCP(sport=53, dport=1024, flags="S"), payload_size=40),
])

write_pcap("003-send.pcap", [
    ipv4_send("2.2.2.2", "3.3.3.3", UDP(sport=1024, dport=80), payload_size=70),
])

write_pcap("003-expect.pcap", [])


