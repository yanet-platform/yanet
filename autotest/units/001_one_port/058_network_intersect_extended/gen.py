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


write_pcap("001-send.pcap", [
    # SEC_GAP1
    ipv6_send("1111:2222::1", "2020:ddd:1000::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::1", "2020:ddd:0000:0000:5555::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::1", "2020:ddd:1000:0000:5555::1")/UDP(sport=1024, dport=53),

    # SEC_GAP2
    ipv6_send("1111:2222::2", "2020:ddd:2000::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::2", "2020:ddd:0000:0000:6666::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::2", "2020:ddd:2000:0000:6666::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::2", "2020:ddd:2000:ffff:6666::1")/UDP(sport=1024, dport=53),

    # SEC_GAP3
    ipv6_send("1111:2222::3", "2020:ddd::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::3", "2020:ddd:0000:0000:7777::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::3", "2020:ddd:ffff:ffff:7777::1")/UDP(sport=1024, dport=53),

    # SEC_SIM
    ipv6_send("1111:2222::4", "2020:cccc:0:0:1111::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::4", "2020:cccc:4000:0:1111::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::4", "2020:cccc:4000:ffff:1111::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::4", "2020:cccc:5000:0:1111::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::4", "2020:cccc:5000:ffff:1111::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::4", "2020:cccc:0:0:1111::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::4", "2020:cccc:ffff:ffff:1111::1")/UDP(sport=1024, dport=53),
    ipv6_send("1111:2222::4", "2020:cccc:0:0:1111::1")/TCP(sport=1024, dport=22),
    ipv6_send("1111:2222::4", "2020:cccc:ffff:ffff:1111::1")/TCP(sport=1024, dport=22),
])


write_pcap("001-expect.pcap", *[
    # SEC_GAP1
#   ipv6_recv("1111:2222::1", "2020:ddd:1000::1")/UDP(sport=1024, dport=53),
#   ipv6_recv("1111:2222::1", "2020:ddd:0000:0000:5555::1")/UDP(sport=1024, dport=53),
    ipv6_recv("1111:2222::1", "2020:ddd:1000:0000:5555::1")/UDP(sport=1024, dport=53),

    # SEC_GAP2
#   ipv6_recv("1111:2222::2", "2020:ddd:2000::1")/UDP(sport=1024, dport=53),
#   ipv6_recv("1111:2222::2", "2020:ddd:0000:0000:6666::1")/UDP(sport=1024, dport=53),
    ipv6_recv("1111:2222::2", "2020:ddd:2000:0000:6666::1")/UDP(sport=1024, dport=53),
    ipv6_recv("1111:2222::2", "2020:ddd:2000:ffff:6666::1")/UDP(sport=1024, dport=53),

    # SEC_GAP3
#   ipv6_recv("1111:2222::3", "2020:ddd::1")/UDP(sport=1024, dport=53),
    ipv6_recv("1111:2222::3", "2020:ddd:0000:0000:7777::1")/UDP(sport=1024, dport=53),
    ipv6_recv("1111:2222::3", "2020:ddd:ffff:ffff:7777::1")/UDP(sport=1024, dport=53),

    # SEC_SIM
#   ipv6_recv("1111:2222::4", "2020:cccc:0:0:1111::1")/UDP(sport=1024, dport=53),
    ipv6_recv("1111:2222::4", "2020:cccc:4000:0:1111::1")/UDP(sport=1024, dport=53),
#   ipv6_recv("1111:2222::4", "2020:cccc:4000:ffff:1111::1")/UDP(sport=1024, dport=53),
    ipv6_recv("1111:2222::4", "2020:cccc:5000:0:1111::1")/UDP(sport=1024, dport=53),
    ipv6_recv("1111:2222::4", "2020:cccc:5000:ffff:1111::1")/UDP(sport=1024, dport=53),
#   ipv6_recv("1111:2222::4", "2020:cccc:0:0:1111::1")/UDP(sport=1024, dport=53),
#   ipv6_recv("1111:2222::4", "2020:cccc:ffff:ffff:1111::1")/UDP(sport=1024, dport=53),
    ipv6_recv("1111:2222::4", "2020:cccc:0:0:1111::1")/TCP(sport=1024, dport=22),
    ipv6_recv("1111:2222::4", "2020:cccc:ffff:ffff:1111::1")/TCP(sport=1024, dport=22),
])
