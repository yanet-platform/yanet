#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import PcapWriter

def write_pcap(path: str, packets: List[Packet]) -> None:
    with PcapWriter(path, sync=True) as fh:
        for p in packets:
            fh.write(p)

def ipv4_send(src: str, dst: str, ttl: int = 64) -> Packet:
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11") / IP(src=src, dst=dst, ttl=ttl)

def ipv4_recv(src: str, dst: str, ttl: int = 63) -> Packet:
    return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55") / IP(src=src, dst=dst, ttl=ttl)

# Initial packet to create state
write_pcap("001-send.pcap", [
    ipv4_send("10.0.0.10", "10.0.0.1") / UDP(sport=1024, dport=53),
])

# Expect the packet to be forwarded
write_pcap("001-expect.pcap", [
    ipv4_recv("10.0.0.10", "10.0.0.1") / UDP(sport=1024, dport=53),
])

# Expected dump (initial packet)
write_pcap("001-expect-dump-ring1.pcap", [
    ipv4_send("10.0.0.10", "10.0.0.1") / UDP(sport=1024, dport=53),
])

# Inverted packet
write_pcap("002-send.pcap", [
    ipv4_send("10.0.0.1", "10.0.0.10") / UDP(sport=53, dport=1024),
])

# Expect the inverted packet
write_pcap("002-expect.pcap", [
    ipv4_recv("10.0.0.1", "10.0.0.10") / UDP(sport=53, dport=1024),
])
