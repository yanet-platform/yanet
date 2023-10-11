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


write_pcap("001-send.pcap", *[
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2030::1")/UDP(sport=(1024, 1040), dport=53),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2030::1")/TCP(sport=50000, dport=80, flags="S"),
    # Do not pass, since [2121:bbb8:ff1c:2040::1]:80 is not allowed.
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2040::1")/TCP(sport=50000, dport=80, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2031::1")/TCP(sport=50000, dport=81, flags="S"),
    # Do not pass, since [2121:bbb8:ff1c:2032::1]:81 is not allowed.
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032::1")/TCP(sport=50000, dport=81, flags="S"),
    # Do not pass, since [2121:bbb8:ff1c:2032::1]:82 is not allowed.
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032::1")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::1")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::2")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::3")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::4")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::5")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::6")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::7")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::8")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::9")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678:9:9")/TCP(sport=50000, dport=82, flags="S"),
    # The following 4 packets should be dropped
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:567f:9:9")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:56f8:9:9")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:5f78:9:9")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:2032:0:f678:9:9")/TCP(sport=50000, dport=82, flags="S"),

    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:0:aaaa:bbbb::1")/TCP(sport=50000, dport=83, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:0:aaaa:bbbb:1:1")/TCP(sport=50000, dport=83, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:1:aaaa:bbbb:1:1")/TCP(sport=50000, dport=83, flags="S"),
    # The following 8 packets should be dropped
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:1:faaa:bbbb:1:1")/TCP(sport=50000, dport=83, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:1:afaa:bbbb:1:1")/TCP(sport=50000, dport=83, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:1:aafa:bbbb:1:1")/TCP(sport=50000, dport=83, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:1:aaaf:bbbb:1:1")/TCP(sport=50000, dport=83, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:1:aaaa:fbbb:1:1")/TCP(sport=50000, dport=83, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:1:aaaa:bfbb:1:1")/TCP(sport=50000, dport=83, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:1:aaaa:bbfb:1:1")/TCP(sport=50000, dport=83, flags="S"),
    ipv6_send("1111:2222::1", "2121:bbb8:ff1c:1:aaaa:bbbf:1:1")/TCP(sport=50000, dport=83, flags="S"),

    # local trafic
    ipv6_send("1111:2222::1", "fe80::2")/TCP(sport=50000, dport=80, flags="S"),
    
])


write_pcap("001-expect.pcap", *[
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2030::1")/UDP(sport=(1024, 1040), dport=53),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2030::1")/TCP(sport=50000, dport=80, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2031::1")/TCP(sport=50000, dport=81, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::1")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::2")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::3")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::4")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::5")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::6")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::7")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::8")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678::9")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:2032:0:5678:9:9")/TCP(sport=50000, dport=82, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:0:aaaa:bbbb::1")/TCP(sport=50000, dport=83, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:0:aaaa:bbbb:1:1")/TCP(sport=50000, dport=83, flags="S"),
    ipv6_recv("1111:2222::1", "2121:bbb8:ff1c:1:aaaa:bbbb:1:1")/TCP(sport=50000, dport=83, flags="S"),
    
    Ether(dst="71:71:71:71:71:71", src="00:00:00:22:22:22")/Dot1Q(vlan=200)/IPv6(src="1111:2222::1", dst="fe80::2", hlim=64, fl=0)/TCP(sport=50000, dport=80, flags="S"),
])
