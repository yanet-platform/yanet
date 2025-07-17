#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *


def write_pcap(filename, *packetsList):
    PcapWriter(filename)
    for packets in packetsList:
        if type(packets) == list:
            for packet in packets:
                packet.time = 0
                wrpcap(filename, [p for p in packet], append=True)
        else:
            packets.time = 0
            wrpcap(filename, [p for p in packets], append=True)


# Test 1: IPv6 -> IPv4 translation with correct/valid checksum
write_pcap("001-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/
           Dot1Q(vlan=100)/
           IPv6(dst="2222:987:0a00:0000::11.11.11.100", src="2000::", hlim=64)/
           UDP(dport=80, sport=2001)/
           Raw(b"test"))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/
           Dot1Q(vlan=200)/
           IP(dst="11.11.11.100", src="10.0.0.0", ttl=63, id=0)/
           UDP(dport=80, sport=12001, chksum=0xc85c)/
           Raw(b"test"))


# Test 2: IPv6 -> IPv4 translation with mathematically correct 0xffff checksum
# This payload (b'l/') mathematically produces UDP checksum = 0x0000, which RFC 768 
# requires to be represented as 0xffff in the header. YANET applies incremental 
# checksum update algorithm and produces 0x2499 as the final result.
write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/
           Dot1Q(vlan=100)/
           IPv6(dst="2222:987:0a00:0000::11.11.11.150", src="2000::", hlim=64)/
           UDP(dport=8080, sport=2001, chksum=0xffff)/
           Raw(b"l/"))

write_pcap("002-expect.pcap",
           Ether(dst="00:00:00:22:22:22", src="00:11:22:33:44:55")/
           Dot1Q(vlan=200)/
           IP(dst="11.11.11.150", src="10.0.0.0", ttl=63, id=0)/
           UDP(dport=8080, sport=12001, chksum=0x2499)/
           Raw(b"l/"))


# Test 3: IPv4 -> IPv6 translation with correct/valid checksum
write_pcap("003-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/
           Dot1Q(vlan=200)/
           IP(dst="10.0.0.0", src="11.11.11.150", ttl=64)/
           UDP(dport=12001, sport=8080)/
           Raw(b"data"))

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/
           Dot1Q(vlan=100)/
           IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.150", hlim=63, fl=0)/
           UDP(dport=2001, sport=8080, chksum=0x9368)/
           Raw(b"data"))


# Test 4: IPv4 -> IPv6 translation with UDP checksum = 0x0000
# This should calculate correct IPv4 checksum first, then convert to IPv6
write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/
           Dot1Q(vlan=200)/
           IP(dst="10.0.0.0", src="11.11.11.200", ttl=64)/
           UDP(dport=12001, sport=443, chksum=0x0000)/
           Raw(b"test_data_for_checksum"))

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/
           Dot1Q(vlan=100)/
           IPv6(dst="2000::", src="2222:987:0a00:0000::11.11.11.200", hlim=63, fl=0)/
           UDP(dport=2001, sport=443, chksum=0xfd1c)/
           Raw(b"test_data_for_checksum"))


print("Generated NAT64 UDP checksum test PCAP files:")
print("001: IPv6->IPv4 with standard checksum handling")
print("002: IPv6->IPv4 with mathematically correct 0xffff checksum (payload=b'l/' gives 0x0000 sum)")
print("003: IPv4->IPv6 with correct checksum (should be recalculated)")
print("004: IPv4->IPv6 with zero checksum and payload (should calculate proper checksum)")

