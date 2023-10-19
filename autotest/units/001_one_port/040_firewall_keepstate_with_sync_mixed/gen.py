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


sa = SecurityAssociation(ESP, spi=0xdeadbeef, crypt_algo='AES-CBC', crypt_key=b'secret secret 16')

# IPv6 packets.
write_pcap("001-send.pcap", [
    ipv6_send("1111:2222::1", "2332:898:ff1c:2030::1") / UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::1", "2332:898:ff1c:2030::2") / TCP(sport=1024, dport=12345, flags="S"),
    ipv6_send("1111:2222::1", "2332:898:ff1c:2030::3") / ICMPv6DestUnreach(code=0),
    eth6_tx() / sa.encrypt(IPv6(raw(IPv6(src="1111:2222::1", dst="2332:898:ff1c:2030::4", hlim=64, fl=0) / TCP(sport=1024, dport=80, flags="S"))), seq_num=0, iv=16 * b' '),
])

write_pcap("001-expect.pcap", [
    ipv6_recv("1111:2222::1", "2332:898:ff1c:2030::1") / UDP(sport=1024, dport=53),
    ipv6_recv("1111:2222::1", "2332:898:ff1c:2030::2") / TCP(sport=1024, dport=12345, flags="S"),
    ipv6_recv("1111:2222::1", "2332:898:ff1c:2030::3") / ICMPv6DestUnreach(code=0),
    eth6_rx() / sa.encrypt(IPv6(raw(IPv6(src="1111:2222::1", dst="2332:898:ff1c:2030::4", hlim=63, fl=0) / TCP(sport=1024, dport=80, flags="S"))), seq_num=1, iv=16 * b' '),

    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f1", dst="ff02::1", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_UDP, "1111:2222::1", "2332:898:ff1c:2030::1", 1024, 53, 0)),
    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f1", dst="ff02::1", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_TCP, "1111:2222::1", "2332:898:ff1c:2030::2", 1024, 12345, 2)),
    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f1", dst="ff02::1", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_ICMPV6, "1111:2222::1", "2332:898:ff1c:2030::3", 0, 0, 0)),
    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f1", dst="ff02::1", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_ESP, "1111:2222::1", "2332:898:ff1c:2030::4", 0, 0, 0)),
])

# No state, must be dropped.
write_pcap("002-send.pcap", [
    ipv6_send("2a32:6b9:ff1c:2030::10", "1111:2222::10") / UDP(sport=35, dport=10240),
    ipv6_send("2a32:6b9:ff1c:2030::20", "1111:2222::10") / TCP(sport=54321, dport=10240, flags="S"),
    ipv6_send("2a32:6b9:ff1c:2030::30", "1111:2222::10") / ICMPv6DestUnreach(code=0),
    eth6_tx() / sa.encrypt(IPv6(raw(IPv6(src="2a32:6b9:ff1c:2030::40", dst="1111:2222::10", hlim=64, fl=0) / TCP(sport=1024, dport=80, flags="S"))), seq_num=0, iv=16 * b' '),
])

write_pcap("002-expect.pcap", [
])

write_pcap("003-send.pcap", [
    # Mimic external multicast sync event.
    Ether(src="00:00:00:33:33:33", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f2", dst="ff02::1", hlim=63, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_UDP, "1111:2222::10", "2a32:6b9:ff1c:2030::10", 10240, 35, 0)),
    Ether(src="00:00:00:33:33:33", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f2", dst="ff02::1", hlim=63, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_TCP, "1111:2222::10", "2a32:6b9:ff1c:2030::20", 10240, 54321, 0)),
    Ether(src="00:00:00:33:33:33", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f2", dst="ff02::1", hlim=63, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_ICMPV6, "1111:2222::10", "2a32:6b9:ff1c:2030::30", 0, 0, 0)),
    Ether(src="00:00:00:33:33:33", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f2", dst="ff02::1", hlim=63, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload6(socket.IPPROTO_ESP, "1111:2222::10", "2a32:6b9:ff1c:2030::40", 0, 0, 0)),
])

write_pcap("003-expect.pcap", [
])

# Sleep for 1s.

write_pcap("004-send.pcap", [
    ipv6_send("2a32:6b9:ff1c:2030::10", "1111:2222::10") / UDP(sport=35, dport=10240),
    ipv6_send("2a32:6b9:ff1c:2030::20", "1111:2222::10") / TCP(sport=54321, dport=10240, flags="S"),
    ipv6_send("2a32:6b9:ff1c:2030::30", "1111:2222::10") / ICMPv6DestUnreach(code=0),
    eth6_tx() / sa.encrypt(IPv6(raw(IPv6(src="2a32:6b9:ff1c:2030::40", dst="1111:2222::10", hlim=64, fl=0) / TCP(sport=1024, dport=80, flags="S"))), seq_num=0, iv=16 * b' '),
])

write_pcap("004-expect.pcap", [
    ipv6_recv("2a32:6b9:ff1c:2030::10", "1111:2222::10") / UDP(sport=35, dport=10240),
    ipv6_recv("2a32:6b9:ff1c:2030::20", "1111:2222::10") / TCP(sport=54321, dport=10240, flags="S"),
    ipv6_recv("2a32:6b9:ff1c:2030::30", "1111:2222::10") / ICMPv6DestUnreach(code=0),
    eth6_rx() / sa.encrypt(IPv6(raw(IPv6(src="2a32:6b9:ff1c:2030::40", dst="1111:2222::10", hlim=63, fl=0) / TCP(sport=1024, dport=80, flags="S"))), seq_num=1, iv=16 * b' '),
])

# FW clear state

# IPv4 packets.

write_pcap("005-send.pcap", [
    ipv4_send("13.0.0.1", "1.1.1.1") / UDP(sport=1000, dport=53),
    ipv4_send("13.0.0.1", "1.1.1.1") / TCP(sport=1000, dport=12345, flags="S"),
    ipv4_send("13.0.0.1", "1.1.1.1") / ICMP(type=10),
    eth4_tx() / sa.encrypt(IP(raw(IP(src="13.0.0.1", dst="1.1.1.1", ttl=64) / TCP(sport=1024, dport=80, flags="S"))), seq_num=0, iv=16 * b' '),
])

write_pcap("005-expect.pcap", [
    ipv4_recv("13.0.0.1", "1.1.1.1") / UDP(sport=1000, dport=53),
    ipv4_recv("13.0.0.1", "1.1.1.1") / TCP(sport=1000, dport=12345, flags="S"),
    ipv4_recv("13.0.0.1", "1.1.1.1") / ICMP(type=10),
    eth4_rx() / sa.encrypt(IP(raw(IP(src="13.0.0.1", dst="1.1.1.1", ttl=63) / TCP(sport=1024, dport=80, flags="S"))), seq_num=1, iv=16 * b' '),

    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f1", dst="ff02::1", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload4(socket.IPPROTO_UDP, "13.0.0.1", "1.1.1.1", 1000, 53, 0)),
    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f1", dst="ff02::1", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload4(socket.IPPROTO_TCP, "13.0.0.1", "1.1.1.1", 1000, 12345, 2)),
    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f1", dst="ff02::1", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload4(socket.IPPROTO_ICMP, "13.0.0.1", "1.1.1.1", 0, 0, 0)),
    Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f1", dst="ff02::1", hlim=64, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload4(socket.IPPROTO_ESP, "13.0.0.1", "1.1.1.1", 0, 0, 0)),
])

write_pcap("006-send.pcap", [
    # Mimic external multicast sync event.
    Ether(src="00:00:00:33:33:33", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f2", dst="ff02::1", hlim=63, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload4(socket.IPPROTO_UDP, "13.0.0.10", "1.1.1.10", 10000, 35, 0)),
    Ether(src="00:00:00:33:33:33", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f2", dst="ff02::1", hlim=63, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload4(socket.IPPROTO_TCP, "13.0.0.10", "1.1.1.10", 10000, 54321, 10)),
    Ether(src="00:00:00:33:33:33", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f2", dst="ff02::1", hlim=63, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload4(socket.IPPROTO_ICMP, "13.0.0.10", "1.1.1.10", 0, 0, 0)),
    Ether(src="00:00:00:33:33:33", dst="33:33:00:00:00:01") / Dot1Q(vlan=2000) / IPv6(src="fe80::f2", dst="ff02::1", hlim=63, fl=0) / UDP(sport=11995, dport=11995) / Raw(make_payload4(socket.IPPROTO_ESP, "13.0.0.10", "1.1.1.10", 0, 0, 0)),
])

write_pcap("006-expect.pcap", [
])

# Sleep for 1s.

write_pcap("007-send.pcap", [
    ipv4_send("1.1.1.10", "13.0.0.10") / UDP(sport=35, dport=10000),
    ipv4_send("1.1.1.10", "13.0.0.10") / TCP(sport=54321, dport=10000, flags="S"),
    ipv4_send("1.1.1.10", "13.0.0.10") / ICMP(type=0),
    eth4_tx() / sa.encrypt(IP(raw(IP(src="1.1.1.10", dst="13.0.0.10", ttl=64) / TCP(sport=1024, dport=80, flags="S"))), seq_num=0, iv=16 * b' '),
])

write_pcap("007-expect.pcap", [
    ipv4_recv("1.1.1.10", "13.0.0.10") / UDP(sport=35, dport=10000),
    ipv4_recv("1.1.1.10", "13.0.0.10") / TCP(sport=54321, dport=10000, flags="S"),
    ipv4_recv("1.1.1.10", "13.0.0.10") / ICMP(type=0),
    eth4_rx() / sa.encrypt(IP(raw(IP(src="1.1.1.10", dst="13.0.0.10", ttl=63) / TCP(sport=1024, dport=80, flags="S"))), seq_num=0, iv=16 * b' '),
])
