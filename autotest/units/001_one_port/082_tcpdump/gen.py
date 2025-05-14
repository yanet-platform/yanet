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

# Create 64 packets with 16384 byte payloads
send_packets = []
expect_packets = []
expect_dump_packets = []

# Ethernet (14) + IP (20) + UDP (8) = 42 bytes header
payload_size = 100 - 42
dummy_payload = b'\x00' * payload_size

for i in range(10):
    # Create packets with incrementing source ports for variety
    send_pkt = ipv4_send("10.0.0.10", "10.0.0.1") / UDP(sport=1024+i, dport=53) / dummy_payload
    recv_pkt = ipv4_recv("10.0.0.10", "10.0.0.1") / UDP(sport=1024+i, dport=53) / dummy_payload

    send_packets.append(send_pkt)
    expect_packets.append(recv_pkt)
    expect_dump_packets.append(send_pkt)

write_pcap("001-send.pcap", send_packets)
write_pcap("001-expect.pcap", expect_packets)
write_pcap("001-expect-dump.pcap", expect_dump_packets)
