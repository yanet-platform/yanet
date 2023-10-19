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

# src and dst are among expected ips, both inner and outer ip headers (of a packet sent from metabalancer to balancer) are of the same version
write_pcap("001-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.210.198.65", src="123.234.128.10", ttl=64)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:898:0:320::b2a", src="2222:898:0:320::1", hlim=64)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380))

write_pcap("001-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.1", src="100.0.0.50", ttl=63)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           # balancer src addr is not just taken from config, its 9-12 bytes are actual src addr's 9-12 bytes xored with 13-16 bytes
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::1:0:1", hlim=63)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380))

# src and dst are among expected ips, inner and outer ip headers (of a packet sent from metabalancer to balancer) are of different versions
write_pcap("002-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.210.198.65", src="123.234.64.5", ttl=64)/IPv6(dst="2004:dead:beef::1", src="2002::2", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:898:0:320::b2a", src="2222:898:0:160::1", hlim=64)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380))

write_pcap("002-expect.pcap",
           # balancer src addr is not just taken from config, its 9-12 bytes are actual src addr's 9-12 bytes xored with 13-16 bytes
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::2", src="2000:51b::2:0:1", hlim=63)/IPv6(dst="2004:dead:beef::1", src="2002::2", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.1", src="100.0.0.50", ttl=63)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380))

# BOTH src and dst are NOT among expected ips: packet is NOT decapsulated and is passed unchanged, interface is picked according to autotest.yaml and controlplane.conf
write_pcap("003-send.pcap",
           # inner and outer ip headers are of the same version
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.210.198.60", src="123.234.0.15", ttl=64)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:898:0:320::bbb", src="2222:898:0:80::1", hlim=64)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
           # inner and outer ip headers are of different versions
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.210.198.60", src="123.234.0.15", ttl=64)/IPv6(dst="2004:dead:beef::1", src="2002::2", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:898:0:320::bbb", src="2222:898:0:80::1", hlim=64)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380))

write_pcap("003-expect.pcap",
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.210.198.60", src="123.234.0.15", ttl=63)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="2222:898:0:320::bbb", src="2222:898:0:80::1", hlim=63)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IP(dst="1.210.198.60", src="123.234.0.15", ttl=63)/IPv6(dst="2004:dead:beef::1", src="2002::2", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:02", src="00:11:22:33:44:55")/Dot1Q(vlan=200)/IPv6(dst="2222:898:0:320::bbb", src="2222:898:0:80::1", hlim=63)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380))

# src and dst are among expected ips, but the packet is not encapsulated: packet's dst is the machine itself, normally packet will be routed to KNI (see handlePacketFromForwardingPlane() under CONFIG_YADECAP_AUTOTEST macro)
write_pcap("004-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.210.198.65", src="123.234.8.20", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:898:0:320::b2a", src="2222:898:0:40::1", hlim=64)/TCP(dport=80, sport=12380))

write_pcap("004-expect.pcap",
           Ether(dst="71:71:71:71:71:71", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.210.198.65", src="123.234.8.20", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="71:71:71:71:71:71", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IPv6(dst="2222:898:0:320::b2a", src="2222:898:0:40::1", hlim=64)/TCP(dport=80, sport=12380))

# src is among expected ips, but dst is NOT, therefore, no early decapsulation, packet will be passed unchanged (outer dst is not vip, no balancing)
write_pcap("005-send.pcap",
           # inner and outer ip headers are of the same version
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="100.100.20.200", src="123.234.128.10", ttl=64)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2333:898:0:320::a2b", src="2222:898:0:320::1", hlim=64)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
           # inner and outer ip headers are of different versions
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="100.100.20.200", src="123.234.128.10", ttl=64)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2333:898:0:320::a2b", src="2222:898:0:320::1", hlim=64)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           # no inner header
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="100.100.20.200", src="123.234.128.10", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2333:898:0:320::a2b", src="2222:898:0:320::1", hlim=64)/TCP(dport=80, sport=12380))

write_pcap("005-expect.pcap",
           # dst in sent packets were chosen specificaly so vlan will be changed, neighbor ip for such dst lives in another vlan, 00:00:00:00:00:01 is its only known neighbor mac
           # inner and outer ip headers are of the same version
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.100.20.200", src="123.234.128.10", ttl=63)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2333:898:0:320::a2b", src="2222:898:0:320::1", hlim=63)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
           # inner and outer ip headers are of different versions
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.100.20.200", src="123.234.128.10", ttl=63)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2333:898:0:320::a2b", src="2222:898:0:320::1", hlim=63)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           # no inner header
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.100.20.200", src="123.234.128.10", ttl=63)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2333:898:0:320::a2b", src="2222:898:0:320::1", hlim=63)/TCP(dport=80, sport=12380))

# dst is among expected ips, but src is NOT, therefore, no early decapsulation, packet's dst is the machine itself, normally packet will be routed to KNI (see handlePacketFromForwardingPlane() under CONFIG_YADECAP_AUTOTEST macro)
write_pcap("006-send.pcap",
           # inner and outer ip headers are of the same version
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="1.210.198.65", src="123.234.32.10", ttl=64)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2222:898:0:320::b2a", src="2222:898:0:640::1", hlim=64)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
           # inner and outer ip headers are of different versions
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="1.210.198.65", src="123.234.32.10", ttl=64)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2222:898:0:320::b2a", src="2222:898:0:640::1", hlim=64)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           # no inner header
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="1.210.198.65", src="123.234.32.10", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2222:898:0:320::b2a", src="2222:898:0:640::1", hlim=64)/TCP(dport=80, sport=12380))
write_pcap("006-expect.pcap",
           # inner and outer ip headers are of the same version
           Ether(dst="71:71:71:71:71:71", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="1.210.198.65", src="123.234.32.10", ttl=64)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="71:71:71:71:71:71", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2222:898:0:320::b2a", src="2222:898:0:640::1", hlim=64)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
            # inner and outer ip headers are of different versions
           Ether(dst="71:71:71:71:71:71", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="1.210.198.65", src="123.234.32.10", ttl=64)/IPv6(dst="2004:dead:beef::1", src="2002::1", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="71:71:71:71:71:71", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2222:898:0:320::b2a", src="2222:898:0:640::1", hlim=64)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
           # no inner header
           Ether(dst="71:71:71:71:71:71", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="1.210.198.65", src="123.234.32.10", ttl=64)/TCP(dport=80, sport=12380),
           Ether(dst="71:71:71:71:71:71", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2222:898:0:320::b2a", src="2222:898:0:640::1", hlim=64)/TCP(dport=80, sport=12380))

# src and dst are among expected ips, packet is encapsulated TWICE, wrapped in the same header - only first one should be decapped, then it will be dropped - should check acl_ingress_dropPackets
write_pcap("007-send.pcap",
           Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:01")/Dot1Q(vlan=100)/IP(dst="1.210.198.65", src="123.234.128.10", ttl=64)/IP(dst="1.210.198.65", src="123.234.128.10", ttl=64)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380))
write_pcap("007-expect.pcap")