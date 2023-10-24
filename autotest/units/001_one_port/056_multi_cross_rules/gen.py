#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *


def write_pcap(filename, *packetsList):
    if len(packetsList) == 0:
        PcapWriter(filename)._write_header(Ether())
        return

    PcapWriter(filename)

    for packets in packetsList:
        if type(packets) == list:
            for packet in packets:
                packet.time = 0
                wrpcap(filename, [p for p in packet], append=True)
        else:
            packets.time = 0
            wrpcap(filename, [p for p in packets], append=True)


def ipv6_send(_src, _dst):
    return Ether(dst="00:11:22:33:44:55", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(src=_src, dst=_dst, hlim=64, fl=0)


def ipv6_recv(_src, _dst):
    return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src=_src, dst=_dst, hlim=63, fl=0)

def block(_func, _tcp_port):
    return [
        _func("2020:ddd:c00:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:c00:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:c00:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:c00:f:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:c00:f:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:c00:f:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:c00:f00:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:c00:f00:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:c00:f00:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:c0f:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:c0f:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:c0f:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:f00:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:f00:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddd:f00:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddf:c00:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddf:c00:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
        _func("2020:ddf:c00:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=_tcp_port, flags="S"),
    ]

def block_send(_tcp_port):
    return block(ipv6_send, _tcp_port)


write_pcap("001-send.pcap", *[
    block_send(16),
    block_send(32),
    block_send(40),
    block_send(48),
    block_send(56),
    block_send(64),
    block_send(80),
    block_send(443),
])

write_pcap("001-expect.pcap", *[
    ipv6_recv("2020:ddd:c00:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:c00:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:c00:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:c00:f:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:c00:f:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:c00:f:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:c00:f00:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:c00:f00:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:c00:f00:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:c0f:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:c0f:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:c0f:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:f00:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:f00:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),
    ipv6_recv("2020:ddd:f00:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=32, flags="S"),

    ipv6_recv("2020:ddd:c00:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),
    ipv6_recv("2020:ddd:c00:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),
    ipv6_recv("2020:ddd:c00:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),
    ipv6_recv("2020:ddd:c00:f:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),
    ipv6_recv("2020:ddd:c00:f:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),
    ipv6_recv("2020:ddd:c00:f:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),
    ipv6_recv("2020:ddd:c00:f00:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),
    ipv6_recv("2020:ddd:c00:f00:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),
    ipv6_recv("2020:ddd:c00:f00:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),
    ipv6_recv("2020:ddd:c0f:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),
    ipv6_recv("2020:ddd:c0f:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),
    ipv6_recv("2020:ddd:c0f:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=40, flags="S"),

    ipv6_recv("2020:ddd:c00:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=48, flags="S"),
    ipv6_recv("2020:ddd:c00:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=48, flags="S"),
    ipv6_recv("2020:ddd:c00:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=48, flags="S"),
    ipv6_recv("2020:ddd:c00:f:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=48, flags="S"),
    ipv6_recv("2020:ddd:c00:f:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=48, flags="S"),
    ipv6_recv("2020:ddd:c00:f:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=48, flags="S"),
    ipv6_recv("2020:ddd:c00:f00:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=48, flags="S"),
    ipv6_recv("2020:ddd:c00:f00:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=48, flags="S"),
    ipv6_recv("2020:ddd:c00:f00:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=48, flags="S"),

    ipv6_recv("2020:ddd:c00:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=56, flags="S"),
    ipv6_recv("2020:ddd:c00:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=56, flags="S"),
    ipv6_recv("2020:ddd:c00:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=56, flags="S"),
    ipv6_recv("2020:ddd:c00:f:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=56, flags="S"),
    ipv6_recv("2020:ddd:c00:f:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=56, flags="S"),
    ipv6_recv("2020:ddd:c00:f:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=56, flags="S"),

    ipv6_recv("2020:ddd:c00:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=64, flags="S"),
    ipv6_recv("2020:ddd:c00:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=64, flags="S"),
    ipv6_recv("2020:ddd:c00:0:ffff::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=64, flags="S"),

    ipv6_recv("2020:ddd:c00:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=80, flags="S"),
    ipv6_recv("2020:ddd:c00:f:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=80, flags="S"),
    ipv6_recv("2020:ddd:c00:f00:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=80, flags="S"),
    ipv6_recv("2020:ddd:c0f:0:aaaa::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=80, flags="S"),

    ipv6_recv("2020:ddd:c00:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=443, flags="S"),
    ipv6_recv("2020:ddd:c00:f:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=443, flags="S"),
    ipv6_recv("2020:ddd:c00:f00:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=443, flags="S"),
    ipv6_recv("2020:ddd:c0f:0:cccc::", "2020:ddd:0:3400::1")/TCP(sport=50000, dport=443, flags="S"),
])
