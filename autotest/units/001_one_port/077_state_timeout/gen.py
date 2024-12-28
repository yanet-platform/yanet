#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import PcapWriter

def write_pcap(path: str, packets: List[Packet]) -> None:
    with PcapWriter(path, sync=True) as fh:
        for p in packets:
            fh.write(p)

def ipv4_send(src: str, dst: str) -> Packet:
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11") / IP(src=src, dst=dst, ttl=64)

def ipv4_recv(src: str, dst: str) -> Packet:
    return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55") / IP(src=src, dst=dst, ttl=63)

# Send packet from 10.0.0.2 to 10.0.0.1
write_pcap("001-send.pcap", [
    ipv4_send("10.0.0.2", "10.0.0.1") / TCP(sport=12345, dport=80, flags="S"),
])

# Expect the packet forwarded
write_pcap("001-expect.pcap", [
    ipv4_recv("10.0.0.2", "10.0.0.1") / TCP(sport=12345, dport=80, flags="S"),
])
