#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ipaddress
import struct
import socket

from typing import List

from scapy.layers.inet import UDP, IP, TCP
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6ND_RS
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet, Raw
from scapy.utils import PcapWriter


def write_pcap(path: str, packets: List[Packet]) -> None:
    with PcapWriter(path) as fh:
        for p in packets:
            fh.write(p)


vlan_map = {
    100: "00:00:00:11:11:11",
    200: "00:00:00:22:22:22",
    300: "00:00:00:33:33:33",
}

def ipv6_send(src: str, dst: str, vlan: int) -> Packet:
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:88:88:88") / \
           Dot1Q(vlan=vlan) / \
           IPv6(src=src, dst=dst, hlim=64, fl=0)


def ipv6_recv(src: str, dst: str, vlan: int) -> Packet:
    return Ether(dst=vlan_map[vlan], src="00:11:22:33:44:55") / \
           Dot1Q(vlan=vlan) / \
           IPv6(src=src, dst=dst, hlim=63, fl=0)

def make_payload6(proto: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int) -> bytes:
    data = struct.pack(
        "<IIHHBBBB",
        0,  # dst_ip
        0,  # src_ip
        dst_port,
        src_port,
        0,  # fib
        proto,
        flags,  # flags
        6,  # addr_type
    )

    data += ipaddress.ip_address(dst_ip).packed
    data += ipaddress.ip_address(src_ip).packed

    data += struct.pack(
        "<II",
        0,  # flow_id6
        0,  # extra
    )

    return data

write_pcap("001-send.pcap", [
    ipv6_send("1111:2222::1", "1111:2222::2", 100) / UDP(sport=1024, dport=1234),
    ipv6_send("1111:2222::1", "1111:2222::3", 200) / UDP(sport=1024, dport=1234),
    ipv6_send("1111:2222::1", "1111:2222::4", 300) / UDP(sport=1024, dport=1234),
    
    ipv6_send("2222:898::1", "2222:898:0:1429::ad2", 100) / UDP(sport=1024, dport=53),
    
    ipv6_send("1111:2222::1", "2222:898::1", 100) / ICMPv6DestUnreach(code=0),
    ipv6_send("1111:2222::2", "2222:898::1", 200) / ICMPv6DestUnreach(code=0),
    ipv6_send("1111:2222::3", "2222:898::1", 300) / ICMPv6DestUnreach(code=0),
    
    ipv6_send("1111:2222::1", "2222:898::1", 100) / ICMPv6ND_RS(),
    ipv6_send("1111:2222::2", "2222:898::1", 200) / ICMPv6ND_RS(),
    ipv6_send("1111:2222::3", "2222:898::1", 300) / ICMPv6ND_RS(),

    ipv6_send("1111:2222::1", "2222:898::3f4", 100) / TCP(dport=80, sport=12345),
    ipv6_send("1111:2222::2", "2222:898::3f4", 100) / TCP(dport=81, sport=12345),
    ipv6_send("1111:2222::3", "2222:898::3f4", 100) / TCP(dport=443, sport=12345),
    ipv6_send("1111:2222::4", "2222:898::3f4", 300) / TCP(dport=80, sport=12345),
    ipv6_send("2222:898:bf00:400::3", "2222:898::3f4", 300) / TCP(dport=80, sport=12345),
    
    ipv6_send("1111:2222::1", "2222:898:bf00:400::1", 100) / TCP(dport=443, sport=12345),
    ipv6_send("2222:898:c00:1::f805:1:1", "2222:898:bf00:400::1", 100) / TCP(dport=443, sport=12345),
    ipv6_send("2222:898:c00:1::f805:1:2", "2222:898:bf00:400::1", 200) / TCP(dport=443, sport=12345),

    ipv6_send("2222:898:c00:1::f805:1:3", "2222:898:bf00:400::2", 100) / TCP(dport=443, sport=12345),
])

write_pcap("001-expect.pcap", [
    ipv6_recv("1111:2222::1", "1111:2222::2", 100) / UDP(sport=1024, dport=1234),

    ipv6_recv("2222:898::1", "2222:898:0:1429::ad2", 200) / UDP(sport=1024, dport=53),

    ipv6_recv("1111:2222::1", "2222:898::1", 200) / ICMPv6DestUnreach(code=0),

    ipv6_recv("1111:2222::1", "2222:898::1", 200) / ICMPv6ND_RS(),
    ipv6_recv("1111:2222::3", "2222:898::1", 200) / ICMPv6ND_RS(),

    ipv6_recv("1111:2222::1", "2222:898::3f4", 200) / TCP(dport=80, sport=12345),
    ipv6_recv("1111:2222::3", "2222:898::3f4", 200) / TCP(dport=443, sport=12345),
    ipv6_recv("2222:898:bf00:400::3", "2222:898::3f4", 200) / TCP(dport=80, sport=12345),

    ipv6_recv("2222:898:c00:1::f805:1:1", "2222:898:bf00:400::1", 300) / TCP(dport=443, sport=12345),
    ipv6_recv("2222:898:c00:1::f805:1:2", "2222:898:bf00:400::1", 300) / TCP(dport=443, sport=12345),

    ipv6_recv("2222:898:c00:1::f805:1:3", "2222:898:bf00:400::2", 300) / TCP(dport=443, sport=12345),
    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:02:10") / Dot1Q(vlan=2000) / IPv6(src="fe80::f10", dst="ff02::210", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_TCP, "2222:898:c00:1::f805:1:3", "2222:898:bf00:400::2", 12345, 443, 2)),
])
