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


def ipv4_packet1():
	return Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.1", src="1.1.0.3", ttl=64)

def ipv6_packet1():
	return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="64:ff9b::1.1.0.3", hlim=63, fl=0)

def ipv4_packet2():
	return Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.1.0.1", src="1.2.0.3", ttl=64)

def ipv6_packet2():
	return Ether(dst="00:00:00:11:11:11", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2001::1", src="64:ff9b:1::1.2.0.3", hlim=63, fl=0)


write_pcap("001-send.pcap",
           ipv4_packet1()/ICMP(type=3, code=0)/IP(src="10.0.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty01",
           ipv4_packet2()/ICMP(type=3, code=0)/IP(src="10.1.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty01",
           ipv4_packet1()/ICMP(type=3, code=0)/IP(src="10.0.0.1", dst="1.1.3.0")/TCP(dport=53,sport=235)/"qwerty01",
           ipv4_packet2()/ICMP(type=3, code=0)/IP(src="10.1.0.1", dst="1.1.3.0")/TCP(dport=53,sport=235)/"qwerty01",
           ipv4_packet1()/ICMP(type=3, code=0)/IP(src="10.0.0.1", dst="1.1.3.0")/ICMP(type=8, id=0x555, seq=0x8765)/"pelmeni boyarskie",
           ipv4_packet2()/ICMP(type=3, code=0)/IP(src="10.1.0.1", dst="1.1.3.0")/ICMP(type=0, id=0x555, seq=0x8765)/"pelmeni boyarskie")

write_pcap("001-expect.pcap",
           ipv6_packet1()/ICMPv6DestUnreach(code=0)/IPv6(src="2000::1", dst="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty01",
           ipv6_packet2()/ICMPv6DestUnreach(code=0)/IPv6(src="2001::1", dst="64:ff9b:1::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty01",
           ipv6_packet1()/ICMPv6DestUnreach(code=0)/IPv6(src="2000::1", dst="64:ff9b::1.1.3.0", fl=0)/TCP(dport=53,sport=235)/"qwerty01",
           ipv6_packet2()/ICMPv6DestUnreach(code=0)/IPv6(src="2001::1", dst="64:ff9b:1::1.1.3.0", fl=0)/TCP(dport=53,sport=235)/"qwerty01",
           ipv6_packet1()/ICMPv6DestUnreach(code=0)/IPv6(src="2000::1", dst="64:ff9b::1.1.3.0", fl=0)/ICMPv6EchoRequest(id=0x555, seq=0x8765)/"pelmeni boyarskie",
           ipv6_packet2()/ICMPv6DestUnreach(code=0)/IPv6(src="2001::1", dst="64:ff9b:1::1.1.3.0", fl=0)/ICMPv6EchoReply(id=0x555, seq=0x8765)/"pelmeni boyarskie")

write_pcap("002-send.pcap",
           ipv4_packet1()/ICMP(type=3, code=4, nexthopmtu=1000)/IP(src="10.0.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty02",
           ipv4_packet2()/ICMP(type=3, code=4, nexthopmtu=1320)/IP(src="10.1.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty03",
           ipv4_packet1()/ICMP(type=11, code=0)/IP(src="10.0.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty04",
           ipv4_packet2()/ICMP(type=11, code=1)/IP(src="10.1.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty05",
           ipv4_packet1()/ICMP(type=12, code=0, ptr=13)/IP(src="10.0.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty06",
           ipv4_packet1()/ICMP(type=3, code=2)/IP(src="10.0.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty07")

write_pcap("002-expect.pcap",
           ipv6_packet1()/ICMPv6PacketTooBig(code=0, mtu=1280)/IPv6(src="2000::1", dst="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty02",
           ipv6_packet2()/ICMPv6PacketTooBig(code=0, mtu=1340)/IPv6(src="2001::1", dst="64:ff9b:1::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty03",
           ipv6_packet1()/ICMPv6TimeExceeded(code=0)/IPv6(src="2000::1", dst="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty04",
           ipv6_packet2()/ICMPv6TimeExceeded(code=1)/IPv6(src="2001::1", dst="64:ff9b:1::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty05",
           ipv6_packet1()/ICMPv6ParamProblem(code=0, ptr=8)/IPv6(src="2000::1", dst="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty06",
           ipv6_packet1()/ICMPv6ParamProblem(code=1, ptr=6)/IPv6(src="2000::1", dst="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty07")

write_pcap("003-send.pcap",
           ipv4_packet1()/ICMP(type=3, code=[0,1,3,5,6,7,8,9,10,11,12,13,15])/IP(src="10.0.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwertyqqi20",
           ipv4_packet1()/ICMP(type=12, code=[0,2], ptr=[0,1,2,3,8,9,12,13,14,15,16,17,18,19])/IP(src="10.0.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty06")

write_pcap("003-expect.pcap",
           ipv6_packet1()/ICMPv6DestUnreach(code=[0,0,4,0,0,0,0,1,1,0,0,1,1])/IPv6(src="2000::1", dst="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwertyqqi20",
           ipv6_packet1()/ICMPv6ParamProblem(code=[0,0], ptr=[0,1,4,4,7,6,8,8,8,8,24,24,24,24])/IPv6(src="2000::1", dst="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty06")

write_pcap("004-send.pcap",
           ipv4_packet1()/ICMP(type=3, code=[14, 16, 17])/IP(src="10.0.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty01",
           ipv4_packet1()/ICMP(type=12, code=1, ptr=[0,1,2,3,8,9,12,13,14,15,16,17,18,19])/IP(src="10.0.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty06",
           ipv4_packet1()/ICMP(type=12, code=[0,1,2], ptr=[4,5,6,7,10,11,25,34])/IP(src="10.0.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty06",
           ipv4_packet1()/ICMP(type=[1,2,4,5,6,7,9,10,13,14,15,16,17,18,19], code=[0,1,2])/IP(src="10.0.0.1", dst="1.1.3.0")/UDP(dport=53,sport=235)/"qwerty06",
           #fragment(ipv4_packet2()/ICMP(type=3, code=0)/IP(src="10.1.0.1", dst="1.1.3.0")/TCP(dport=53,sport=235)/("ABCDEFGH123456789012"*16), fragsize=208),
           ipv4_packet2()/ICMP(type=3, code=0)/IP(src="10.1.0.2", dst="1.1.3.0")/TCP(dport=53,sport=235)/"qwerty01", # wrong payload src inside mask
           ipv4_packet2()/ICMP(type=3, code=0)/IP(src="10.2.0.1", dst="1.1.3.0")/TCP(dport=53,sport=235)/"qwerty01", # wrong payload src outside mask
           ipv4_packet2()/ICMP(type=3, code=0)/IP(src="10.1.0.1", dst="1.1.3.0")/TCP(dport=53,sport=235)/"qwerty01")

write_pcap("004-expect.pcap",
           ipv6_packet2()/ICMPv6DestUnreach(code=0)/IPv6(src="2001::1", dst="64:ff9b:1::1.1.3.0", fl=0)/TCP(dport=53,sport=235)/"qwerty01")

ipv4_fragments1 = fragment(IP(src="10.0.0.1", dst="1.1.3.0",id=0x1234)/TCP(dport=80,sport=23456)/("ABCDEFGH123456789012"*20), fragsize=208)
ipv6_fragments1 = fragment6(IPv6(src="2000::1", dst="64:ff9b::1.1.3.0", fl=0)/IPv6ExtHdrFragment(id=0x12340000)/TCP(dport=80,sport=23456)/("ABCDEFGH123456789012"*20), fragSize=256)

write_pcap("005-send.pcap",
           ipv4_packet1()/ICMP(type=3, code=0)/ipv4_fragments1[0],
           ipv4_packet1()/ICMP(type=3, code=0)/ipv4_fragments1[1])

write_pcap("005-expect.pcap",
           ipv6_packet1()/ICMPv6DestUnreach(code=0)/ipv6_fragments1[0],
           ipv6_packet1()/ICMPv6DestUnreach(code=0)/ipv6_fragments1[1])

def ipv6_packet3():
	return Ether(src="00:00:00:11:11:11", dst="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src="2000::1", dst="64:ff9b::1.1.3.0", hlim=64, fl=0)

def ipv4_packet3():
	return Ether(src="00:11:22:33:44:55", dst="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(src="10.0.0.1", dst="1.1.3.0", ttl=63, id=0)

def ipv6_packet4():
	return Ether(src="00:00:00:11:11:11", dst="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(src="2001::1", dst="64:ff9b:1::1.2.3.0", hlim=64, fl=0)

def ipv4_packet4():
	return Ether(src="00:11:22:33:44:55", dst="00:00:00:22:22:22")/Dot1Q(vlan=200)/IP(src="10.1.0.1", dst="1.2.3.0", ttl=63, id=0)

write_pcap("006-send.pcap",
           ipv6_packet3()/ICMPv6DestUnreach(code=0)/IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty01",
           ipv6_packet4()/ICMPv6DestUnreach(code=0)/IPv6(dst="2001::1", src="64:ff9b:1::1.2.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty01",
           ipv6_packet3()/ICMPv6DestUnreach(code=0)/IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/TCP(dport=53,sport=235)/"qwerty01",
           ipv6_packet4()/ICMPv6DestUnreach(code=0)/IPv6(dst="2001::1", src="64:ff9b:1::1.2.3.0", fl=0)/TCP(dport=53,sport=235)/"qwerty01",
           ipv6_packet3()/ICMPv6DestUnreach(code=0)/IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/ICMPv6EchoRequest(id=0x555, seq=0x8765)/"pelmeni boyarskie",
           ipv6_packet4()/ICMPv6DestUnreach(code=0)/IPv6(dst="2001::1", src="64:ff9b:1::1.2.3.0", fl=0)/ICMPv6EchoReply(id=0x555, seq=0x8765)/"pelmeni boyarskie")


write_pcap("006-expect.pcap",
           ipv4_packet3()/ICMP(type=3, code=1)/IP(dst="10.0.0.1", src="1.1.3.0", id=0x2134)/UDP(dport=53,sport=235)/"qwerty01",
           ipv4_packet4()/ICMP(type=3, code=1)/IP(dst="10.1.0.1", src="1.2.3.0", id=0x2134)/UDP(dport=53,sport=235)/"qwerty01",
           ipv4_packet3()/ICMP(type=3, code=1)/IP(dst="10.0.0.1", src="1.1.3.0", id=0x2134)/TCP(dport=53,sport=235)/"qwerty01",
           ipv4_packet4()/ICMP(type=3, code=1)/IP(dst="10.1.0.1", src="1.2.3.0", id=0x2134)/TCP(dport=53,sport=235)/"qwerty01",
           ipv4_packet3()/ICMP(type=3, code=1)/IP(dst="10.0.0.1", src="1.1.3.0", id=0x2134)/ICMP(type=8, id=0x555, seq=0x8765)/"pelmeni boyarskie",
           ipv4_packet4()/ICMP(type=3, code=1)/IP(dst="10.1.0.1", src="1.2.3.0", id=0x2134)/ICMP(type=0, id=0x555, seq=0x8765)/"pelmeni boyarskie")

write_pcap("007-send.pcap",
           ipv6_packet3()/ICMPv6PacketTooBig(code=0, mtu=1020)/IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty02",
           ipv6_packet3()/ICMPv6TimeExceeded(code=0)/IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty04",
           ipv6_packet3()/ICMPv6ParamProblem(code=1, ptr=6)/IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty07",
           ipv6_packet3()/ICMPv6DestUnreach(code=[0,1,2,3,4])/IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwertyqqi20",
           ipv6_packet3()/ICMPv6ParamProblem(code=0, ptr=[0,1,4,5,6,7,8,15,17,23,24,33,37,39])/IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty06")


write_pcap("007-expect.pcap",
           ipv4_packet3()/ICMP(type=3, code=4, nexthopmtu=1000)/IP(dst="10.0.0.1", src="1.1.3.0", id=0x2134)/UDP(dport=53,sport=235)/"qwerty02",
           ipv4_packet3()/ICMP(type=11, code=0)/IP(dst="10.0.0.1", src="1.1.3.0", id=0x2134)/UDP(dport=53,sport=235)/"qwerty04",
           ipv4_packet3()/ICMP(type=3, code=2)/IP(dst="10.0.0.1", src="1.1.3.0", id=0x2134)/UDP(dport=53,sport=235)/"qwerty07",
           ipv4_packet3()/ICMP(type=3, code=[1,10,1,1,3])/IP(dst="10.0.0.1", src="1.1.3.0", id=0x2134)/UDP(dport=53,sport=235)/"qwertyqqi20",
           ipv4_packet3()/ICMP(type=12, code=0, ptr=[0,1,2,2,9,8,12,12,12,12,16,16,16,16])/IP(dst="10.0.0.1", src="1.1.3.0", id=0x2134)/UDP(dport=53,sport=235)/"qwerty06")

write_pcap("008-send.pcap",
           ipv6_packet3()/ICMPv6DestUnreach(code=[5,12])/IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwertyqqi20",
           ipv6_packet3()/ICMPv6ParamProblem(code=0, ptr=[2,3,40,45])/IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty06",
           ipv6_packet3()/ICMPv6DestUnreach(code=0)/IPv6(dst="2000::1", src="64:ff9b::1.1.3.1", fl=0)/UDP(dport=53,sport=235)/"qwerty01",
           ipv6_packet3()/ICMPv6DestUnreach(code=0)/IPv6(dst="2000::1", src="64:ff9c::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty01",
           ipv6_packet3()/ICMPv6DestUnreach(code=0)/IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/UDP(dport=53,sport=235)/"qwerty01")


write_pcap("008-expect.pcap",
           ipv4_packet3()/ICMP(type=3, code=1)/IP(dst="10.0.0.1", src="1.1.3.0", id=0x2134)/UDP(dport=53,sport=235)/"qwerty01")

ipv6_fragments3 = fragment6(IPv6(dst="2000::1", src="64:ff9b::1.1.3.0", fl=0)/IPv6ExtHdrFragment(id=0xbc23fe15)/UDP(dport=53,sport=235)/("ABCDEFGH123456789012"*20), fragSize=256)
ipv4_fragments3 = fragment(IP(dst="10.0.0.1", src="1.1.3.0", id=0xfe15)/UDP(dport=53,sport=235)/("ABCDEFGH123456789012"*20), fragsize=208)

write_pcap("009-send.pcap",
          ipv6_packet3()/ICMPv6DestUnreach(code=0)/ipv6_fragments3[0],
          ipv6_packet3()/ICMPv6DestUnreach(code=0)/ipv6_fragments3[1])

write_pcap("009-expect.pcap",
          ipv4_packet3()/ICMP(type=3, code=1)/ipv4_fragments3[0],
          ipv4_packet3()/ICMP(type=3, code=1)/ipv4_fragments3[1])
