#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ipaddress
import socket
import struct
from typing import List

from scapy.compat import raw
from scapy.layers.inet import UDP, IP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet, Raw
from scapy.utils import PcapWriter


def write_pcap(path: str, packets: List[Packet]) -> None:
    with PcapWriter(path) as fh:
        for p in packets:
            fh.write(p)


def eth4_tx() -> Packet:
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:11:11:11") / Dot1Q(vlan=100)


def eth4_rx() -> Packet:
    return Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55") / Dot1Q(vlan=200)


def eth6_tx() -> Packet:
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22") / Dot1Q(vlan=200)


def eth6_rx() -> Packet:
    return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55") / Dot1Q(vlan=100)


def ipv4_send(src: str, dst: str) -> Packet:
    return eth4_tx() / IP(src=src, dst=dst, ttl=64)


def ipv4_recv(src: str, dst: str) -> Packet:
    return eth4_rx() / IP(src=src, dst=dst, ttl=63)


def ipv6_send(src: str, dst: str) -> Packet:
    return eth6_tx() / IPv6(src=src, dst=dst, hlim=64, fl=0)


def ipv6_recv(src: str, dst: str) -> Packet:
    return eth6_rx() / IPv6(src=src, dst=dst, hlim=63, fl=0)


def make_payload6(proto: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    data = struct.pack(
        "<IIHHBBBB",
        0,  # dst_ip
        0,  # src_ip
        dst_port,
        src_port,
        0,  # fib
        proto,
        0,  # flags
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


def make_payload4(proto: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    data = b''
    data += ipaddress.ip_address(dst_ip).packed
    data += ipaddress.ip_address(src_ip).packed

    data += struct.pack(
        "<HHBBBB",
        dst_port,
        src_port,
        0,  # fib
        proto,
        0,  # flags
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


sa = SecurityAssociation(ESP, spi=0xdeadbeef, crypt_algo='AES-CBC', crypt_key=b'secret secret 16')

print(len(make_payload6(socket.IPPROTO_UDP, "1111:2222::0001", "dead:beef::1", 50000, 443) + make_payload6(socket.IPPROTO_UDP, "1111:2222::0002", "dead:beef::2", 50001, 443)))
write_pcap("001-send.pcap", [
    # Mimic external multicast sync event.
    Ether(src="00:00:00:33:33:33", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f2", dst="ff02::1", hlim=63, fl=0) / UDP(sport=11995, dport=11995) / (Raw(make_payload6(socket.IPPROTO_UDP, "1111:2222::0001", "dead:beef::1", 50000, 443) + make_payload6(socket.IPPROTO_UDP, "1111:2222::0002", "dead:beef::2", 50001, 443))),
])

write_pcap("001-expect.pcap", [
])

# Sleep for 1s.

write_pcap("002-send.pcap", [
    ipv6_send("dead:beef::1", "1111:2222::0001") / UDP(sport=443, dport=50000),
    ipv6_send("dead:beef::2", "1111:2222::0002") / UDP(sport=443, dport=50001),
])

write_pcap("002-expect.pcap", [
    ipv6_recv("dead:beef::1", "1111:2222::0001") / UDP(sport=443, dport=50000),
    ipv6_recv("dead:beef::2", "1111:2222::0002") / UDP(sport=443, dport=50001),
])
