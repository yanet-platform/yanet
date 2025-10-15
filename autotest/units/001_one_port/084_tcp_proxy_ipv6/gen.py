#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from proxy_test import *

IP_SERVER1 = "fc00::1:1"
IP_SERVER2 = "fc00::1:2"
IP_SERVER3 = "fc00::1:3"
IP_SERVER4 = "fc00::1:4"
IP_SERVER5 = "fc00::1:5"
IP_SERVER6 = "fc00::1:6"

IP_CLIENT = "fc00::2:1"
IP_BLOCKED_CLIENT = "14.0.0.1"
IP_BLOCKED_CLIENT2 = "15.0.0.1"

PORT_PROXY_INT = 32768
PORT_PROXY_INT2 = 32769
PORT_CLIENT = 12380

len_pr = ProxyTest.SIZE_PROXY_HEADER

data_client1 = 'client first'
data_client2 = 'client second'
data_server1 = 'server first'
data_server2 = 'server second'

ts_client = 2983139994
ts_proxy = 1
ts_server = 12345

options_client_syn = [("MSS", 1460), ("SAckOK", ''), ("Timestamp", (ts_client, 0)), ('WScale', 5), ("NOP", '')]
options_client_ack = [("Timestamp", (1, 2))]
options_server_syn = [("MSS", 1260), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client)), ('WScale', 3), ("NOP", '')]
options_server_syn_proxy = [("MSS", 1260-len_pr), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client)), ('WScale', 3)]

# 005 - pings

data_type_icmp = [
    (
        Ether(src=ProxyTest.MAC_CLIENT, dst=ProxyTest.MAC_PROXY)/Dot1Q(vlan=100)/IPv6(src=IP_CLIENT, dst=IP_SERVER1)/ICMPv6EchoRequest(type=8, code=0, id=1, seq=0x0001)/Raw("abcdef"),
        Ether(src=ProxyTest.MAC_PROXY, dst=ProxyTest.MAC_CLIENT)/Dot1Q(vlan=100)/IPv6(src=IP_SERVER1, dst=IP_CLIENT, hlim=64)/ICMPv6EchoReply(type=0, code=0, id=1, seq=0x0001)/Raw("abcdef"),
	),
    (
		Ether(src=ProxyTest.MAC_CLIENT, dst=ProxyTest.MAC_PROXY)/Dot1Q(vlan=100)/IPv6(src=IP_CLIENT, dst=IP_SERVER2)/ICMPv6EchoRequest(type=8, code=0, id=1, seq=0x0001)/Raw("abcd"),
		Ether(src=ProxyTest.MAC_PROXY, dst=ProxyTest.MAC_CLIENT)/Dot1Q(vlan=100)/IPv6(src=IP_SERVER2, dst=IP_CLIENT, hlim=64)/ICMPv6EchoReply(type=0, code=0, id=1, seq=0x0001)/Raw("abcd"),
	),
    (
		Ether(src=ProxyTest.MAC_CLIENT, dst=ProxyTest.MAC_PROXY)/Dot1Q(vlan=100)/IPv6(src=IP_CLIENT, dst=IP_SERVER3)/ICMPv6EchoRequest(type=8, code=0, id=1, seq=0x0001)/Raw("ab"),
		Ether(src=ProxyTest.MAC_PROXY, dst=ProxyTest.MAC_CLIENT)/Dot1Q(vlan=100)/IPv6(src=IP_SERVER3, dst=IP_CLIENT, hlim=64)/ICMPv6EchoReply(type=0, code=0, id=1, seq=0x0001)/Raw("ab"),
	),
    (
		Ether(src=ProxyTest.MAC_CLIENT, dst=ProxyTest.MAC_PROXY)/Dot1Q(vlan=100)/IPv6(src=IP_CLIENT, dst=IP_SERVER4)/ICMPv6EchoRequest(type=8, code=0, id=1, seq=0x0001),
		Ether(src=ProxyTest.MAC_PROXY, dst=ProxyTest.MAC_CLIENT)/Dot1Q(vlan=100)/IPv6(src=IP_SERVER4, dst=IP_CLIENT, hlim=64)/ICMPv6EchoReply(type=0, code=0, id=1, seq=0x0001),
	)
]

WriteTest("005", data_type_icmp)
