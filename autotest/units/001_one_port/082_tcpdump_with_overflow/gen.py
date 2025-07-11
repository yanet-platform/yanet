#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import PcapWriter

GENERIC_SNAPLEN = 65535

# ... (helper functions are correct) ...
def write_pcap(path: str, packets: List[Packet], snaplen: int = GENERIC_SNAPLEN, use_nano: bool = True) -> None:
    with PcapWriter(path, sync=True, snaplen=snaplen, nano=use_nano) as fh:
        for p in packets:
            fh.write(p)

def ipv4_send(src: str, dst: str, ttl: int = 64) -> Packet:
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11") / IP(src=src, dst=dst, ttl=ttl)

def ipv4_recv(src: str, dst: str, ttl: int = 63) -> Packet:
    return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55") / IP(src=src, dst=dst, ttl=ttl)

# --- Configuration ---
SMALL_RING_COUNT = 2
SMALL_RING_PKT_SIZE = 1000
UDP_PACKETS_TO_SEND_SMALL_RING = 5

REGULAR_RING_COUNT = 64
REGULAR_RING_PKT_SIZE = 16384
UDP_PACKETS_TO_SEND_BIG_RING = 70

# --- Packet Generation ---
all_send_packets = []
udp_for_big_ring = []
udp_for_small_ring = []
expect_recv_packets = []

# 1. Generate UDP packets for the BIG ring
# *** THE FIX: Use a reasonable payload size, not a jumbo frame ***
udp_payload_size_big = 1400 # Well under standard MTU of 1500
udp_payload_big = b'\xBB' * udp_payload_size_big
for i in range(UDP_PACKETS_TO_SEND_BIG_RING):
    # This traffic should be DUMPED to ring_pcap and then DENIED
    send_pkt = ipv4_send("192.168.1.1", "10.0.0.2") / UDP(sport=2000 + i, dport=12345) / udp_payload_big
    udp_for_big_ring.append(send_pkt)
    all_send_packets.append(send_pkt)

# 2. Generate UDP packets for the SMALL ring
udp_payload_size_small = 900 # Also a reasonable size
udp_payload_small = b'\xAA' * udp_payload_size_small
for i in range(UDP_PACKETS_TO_SEND_SMALL_RING):
    # This traffic should be DUMPED to small_ring_pcap and then ALLOWED
    send_pkt = ipv4_send("10.0.0.10", "8.8.8.8") / UDP(sport=1024 + i, dport=53) / udp_payload_small
    udp_for_small_ring.append(send_pkt)
    all_send_packets.append(send_pkt)
    recv_pkt = ipv4_recv("10.0.0.10", "8.8.8.8") / UDP(sport=1024 + i, dport=53) / udp_payload_small
    expect_recv_packets.append(recv_pkt)

# ... (rest of file remains the same) ...
last_packets_big_ring = udp_for_big_ring[UDP_PACKETS_TO_SEND_BIG_RING - REGULAR_RING_COUNT:]
last_packets_small_ring = udp_for_small_ring[UDP_PACKETS_TO_SEND_SMALL_RING - SMALL_RING_COUNT:]

write_pcap("001-send.pcap", all_send_packets)
write_pcap("001-expect.pcap", expect_recv_packets)
write_pcap("001-expect-dump-big-ring.pcap", last_packets_big_ring, snaplen=REGULAR_RING_PKT_SIZE)
write_pcap("001-expect-dump-small-ring.pcap", last_packets_small_ring, snaplen=SMALL_RING_PKT_SIZE)

print("Done.")

