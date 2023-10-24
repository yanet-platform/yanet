#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ipaddress
import socket
import struct
from typing import List

from scapy.layers.inet import UDP, IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet, Raw
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


def make_payload4(proto: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int) -> bytes:
    data = b''
    data += ipaddress.ip_address(dst_ip).packed
    data += ipaddress.ip_address(src_ip).packed

    data += struct.pack(
        "<HHBBBB",
        dst_port,
        src_port,
        0,  # fib
        proto,
        flags,  # flags
        4,  # addr_type
    )

    data += ipaddress.ip_address('::').packed
    data += ipaddress.ip_address('::').packed

    data += struct.pack(
        "<II",
        0,  # flow_id6
        0,  # extra
    )

    return data


write_pcap("001-send.pcap", [
    ipv6_send("1111:2222::1", "2220:ddd:ff1c:2030::1") / TCP(sport=1024, dport=12345, flags="S"),
])

write_pcap("001-expect.pcap", [
    ipv6_recv("1111:2222::1", "2220:ddd:ff1c:2030::1") / TCP(sport=1024, dport=12345, flags="S"),

    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f1", dst="ff02::1", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_TCP, "1111:2222::1", "2220:ddd:ff1c:2030::1", 1024, 12345, 2)),
    ipv6_recv("3333::4444", "2222::1111") / UDP(sport=21995, dport=21995) / Raw(make_payload6(socket.IPPROTO_TCP, "1111:2222::1", "2220:ddd:ff1c:2030::1", 1024, 12345, 2)),
])

write_pcap("002-send.pcap", [
    # Mimic external multicast sync event.
    Ether(src="00:00:00:33:33:33", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f2", dst="ff02::1", hlim=63, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_TCP, "1111:2222::10", "2220:ddd:ff1c:2030::10", 10240, 54321, 2)),
])

write_pcap("002-expect.pcap", [
])

# Sleep for 1s.

write_pcap("003-send.pcap", [
    ipv6_send("2220:ddd:ff1c:2030::10", "1111:2222::10") / TCP(sport=54321, dport=10240, flags="S"),
])

write_pcap("003-expect.pcap", [
    ipv6_recv("2220:ddd:ff1c:2030::10", "1111:2222::10") / TCP(sport=54321, dport=10240, flags="S"),
])

# FW clear state

write_pcap("004-send.pcap", [
    ipv4_send("12.0.0.1", "1.1.1.1") / TCP(sport=1000, dport=12345, flags="S"),
])

write_pcap("004-expect.pcap", [
    ipv4_recv("12.0.0.1", "1.1.1.1") / TCP(sport=1000, dport=12345, flags="S"),

    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f1", dst="ff02::1", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload4(socket.IPPROTO_TCP, "12.0.0.1", "1.1.1.1", 1000, 12345, 2)),
    ipv6_recv("3333::4444", "2222::1111") / UDP(sport=21995, dport=21995) / Raw(make_payload4(socket.IPPROTO_TCP, "12.0.0.1", "1.1.1.1", 1000, 12345, 2)),
])

write_pcap("005-send.pcap", [
    # Mimic external multicast sync event.
    Ether(src="00:00:00:33:33:33", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f2", dst="ff02::1", hlim=63, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload4(socket.IPPROTO_TCP, "12.0.0.10", "1.1.1.10", 10000, 54321, 2)),
])

write_pcap("005-expect.pcap", [
])

# Sleep for 1s.

write_pcap("006-send.pcap", [
    ipv4_send("1.1.1.10", "12.0.0.10") / TCP(sport=54321, dport=10000, flags="S"),
])

write_pcap("006-expect.pcap", [
    ipv4_recv("1.1.1.10", "12.0.0.10") / TCP(sport=54321, dport=10000, flags="S"),
])

# Sleep for 1s.

write_pcap("007-send.pcap", [
    ipv6_send("1111:2222::1", "2220:ddd:ff1c:2030::1") / TCP(sport=777, dport=12345, flags="S"),
    ipv6_send("2220:ddd:ff1c:2030::1", "1111:2222::1") / TCP(dport=777, sport=12345, flags="SA"),
    ipv6_send("1111:2222::1", "2220:ddd:ff1c:2030::1") / TCP(sport=777, dport=12345, flags="A"),
    ipv6_send("2220:ddd:ff1c:2030::1", "1111:2222::1") / TCP(dport=777, sport=12345, flags="F"),
    ipv6_send("1111:2222::1", "2220:ddd:ff1c:2030::1") / TCP(sport=777, dport=12345, flags="FA"),
    ipv6_send("2220:ddd:ff1c:2030::1", "1111:2222::1") / TCP(dport=777, sport=12345, flags="A"),
])

write_pcap("007-expect-tcp.pcap", [
    ipv6_recv("1111:2222::1", "2220:ddd:ff1c:2030::1") / TCP(sport=777, dport=12345, flags="S"),
    ipv6_recv("2220:ddd:ff1c:2030::1", "1111:2222::1") / TCP(dport=777, sport=12345, flags="SA"),
    ipv6_recv("1111:2222::1", "2220:ddd:ff1c:2030::1") / TCP(sport=777, dport=12345, flags="A"),
    ipv6_recv("2220:ddd:ff1c:2030::1", "1111:2222::1") / TCP(dport=777, sport=12345, flags="F"),
    ipv6_recv("1111:2222::1", "2220:ddd:ff1c:2030::1") / TCP(sport=777, dport=12345, flags="FA"),
    ipv6_recv("2220:ddd:ff1c:2030::1", "1111:2222::1") / TCP(dport=777, sport=12345, flags="A"),
])
write_pcap("007-expect-tech.pcap", [
    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f1", dst="ff02::1", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_TCP, "1111:2222::1", "2220:ddd:ff1c:2030::1", 777, 12345, 2)),
    ipv6_recv("3333::4444", "2222::1111") / UDP(sport=21995, dport=21995) / Raw(make_payload6(socket.IPPROTO_TCP, "1111:2222::1", "2220:ddd:ff1c:2030::1", 777, 12345, 2)),
])



