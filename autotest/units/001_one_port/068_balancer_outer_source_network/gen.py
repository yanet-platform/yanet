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


write_pcap("001-send.pcap",
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.0.0.1", src="1.1.0.1", ttl=64) / TCP(dport=80, sport=12380),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IP(dst="10.0.0.1", src="1.1.0.2", ttl=64) / TCP(dport=80, sport=12380)
)

write_pcap("001-expect.pcap",
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2001:dead:beef::0101:0001:0:1", hlim=63)/IP(dst="10.0.0.1", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IPv6(dst="2000::1", src="2001:dead:beef::0101:0002:0:1", hlim=63)/IP(dst="10.0.0.1", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380)
)


write_pcap("002-send.pcap",
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.42", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IP(dst="10.0.0.42", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380)
)

write_pcap("002-expect.pcap",
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.42", src="123.0.0.12", ttl=63)/IP(dst="10.0.0.42", src="1.1.0.1", ttl=64)/TCP(dport=80, sport=12380),
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.42", src="123.0.0.12", ttl=63)/IP(dst="10.0.0.42", src="1.1.0.2", ttl=64)/TCP(dport=80, sport=12380)
)

write_pcap("003-send.pcap",
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2001:dead:beef::1", src="2002::1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2001:dead:beef::1", src="2002::2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("003-expect.pcap",
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::1", src="2001:dead:beef:1234::1:1", hlim=63) / IPv6(dst="2001:dead:beef::1", src="2002::1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::1", src="2001:dead:beef:1234::2:1", hlim=63) / IPv6(dst="2001:dead:beef::1", src="2002::2", hlim=64) / TCP(dport=80, sport=12443)
)


write_pcap("004-send.pcap",
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::2", src="2002::10", hlim=64)/TCP(dport=80, sport=12380),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02")/Dot1Q(vlan=200)/IPv6(dst="2001:dead:beef::2", src="2002::11", hlim=64)/TCP(dport=80, sport=12380)
)

write_pcap("004-expect.pcap",
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.6", src="123.0.12.0", ttl=63) /IPv6(dst="2001:dead:beef::2", src="2002::10", hlim=64)/TCP(dport=80, sport=12380),
           Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55")/Dot1Q(vlan=100)/IP(dst="100.0.0.6", src="123.0.12.0", ttl=63) /IPv6(dst="2001:dead:beef::2", src="2002::11", hlim=64)/TCP(dport=80, sport=12380)
)

write_pcap("005-send.pcap",
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2002:dead:beef::3", src="2002::1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2002:dead:beef::3", src="2002::2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("005-expect.pcap",
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600:0000:0100:0001", hlim=63) / IPv6(dst="2002:dead:beef::3", src="2002::1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600:0000:0200:0001", hlim=63) / IPv6(dst="2002:dead:beef::3", src="2002::2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("006-send.pcap",
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2003:dead:beef::3", src="2002::1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2003:dead:beef::3", src="2002::2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("006-expect.pcap",
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600::", hlim=63) / IPv6(dst="2003:dead:beef::3", src="2002::1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600::", hlim=63) / IPv6(dst="2003:dead:beef::3", src="2002::2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("007-send.pcap",
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2004:dead:beef::3", src="2002::1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2004:dead:beef::3", src="2002::2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("007-expect.pcap",
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600::", hlim=63) / IPv6(dst="2004:dead:beef::3", src="2002::1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600::", hlim=63) / IPv6(dst="2004:dead:beef::3", src="2002::2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("008-send.pcap",
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2005:dead:beef::3", src="2002::1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2005:dead:beef::3", src="2002::2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("008-expect.pcap",
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600::", hlim=63) / IPv6(dst="2005:dead:beef::3", src="2002::1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600::", hlim=63) / IPv6(dst="2005:dead:beef::3", src="2002::2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("009-send.pcap",
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2006:dead:beef::3", src="2002::1234:0:0:1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2006:dead:beef::3", src="2002::1234:0:0:2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("009-expect.pcap",
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600::0012:3400", hlim=63) / IPv6(dst="2006:dead:beef::3", src="2002::1234:0:0:1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600::0012:3400", hlim=63) / IPv6(dst="2006:dead:beef::3", src="2002::1234:0:0:2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("010-send.pcap",
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2007:dead:beef::3", src="2002::1234:0:0:1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2007:dead:beef::3", src="2002::1234:0:0:2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("010-expect.pcap",
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600::1234:0001", hlim=63) / IPv6(dst="2007:dead:beef::3", src="2002::1234:0:0:1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600::1234:0002", hlim=63) / IPv6(dst="2007:dead:beef::3", src="2002::1234:0:0:2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("011-send.pcap",
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2008:dead:beef::3", src="2002::1234:0:0:1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:11:22:33:44:55", src="00:00:00:00:00:02") / Dot1Q(vlan=200) / IPv6(dst="2008:dead:beef::3", src="2002::1234:0:0:2", hlim=64) / TCP(dport=80, sport=12443)
)

write_pcap("011-expect.pcap",
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600:1234:1:1", hlim=63) / IPv6(dst="2008:dead:beef::3", src="2002::1234:0:0:1", hlim=64) / TCP(dport=80, sport=12443),
            Ether(dst="00:00:00:00:00:01", src="00:11:22:33:44:55") / Dot1Q(vlan=100) / IPv6(dst="2000::2", src="2001:dead:beef:1234:5600:1234:2:1", hlim=63) / IPv6(dst="2008:dead:beef::3", src="2002::1234:0:0:2", hlim=64) / TCP(dport=80, sport=12443)
)
