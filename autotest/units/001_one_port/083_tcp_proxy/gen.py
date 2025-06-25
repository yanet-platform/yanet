#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from proxy_test import *

IP_SERVER1 = "10.0.1.1"
IP_SERVER2 = "10.0.1.2"
IP_SERVER3 = "10.0.1.3"
IP_SERVER4 = "10.0.1.4"
IP_SERVER5 = "10.0.1.5"

IP_CLIENT = "10.0.2.1"
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


# 001 - type 1 - no proxy, no sec

test_001 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER1, ip_proxy=IP_SERVER1, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)

data_type1 = [
	(
		test_001.FromClient((0, None), 'S', options=options_client_syn),
		test_001.ToServer((0, None), 'S', options=options_client_syn)
	), (
		test_001.FromServer((0, 1), 'AS', options=options_server_syn),
		test_001.ToClient((0, 1), 'AS', options=options_server_syn)
	), (
		test_001.FromClient((1, 1), 'A', raw=data_client1, options=options_client_ack),
		test_001.ToServer((1, 1), 'A', raw=data_client1, options=options_client_ack)
	), (
		test_001.FromServer((1, 1 + len(data_client1)), 'A', raw=data_server1),
		test_001.ToClient((1, 1 + len(data_client1)), 'A', raw=data_server1)
	), (
		test_001.FromClient((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2),
		test_001.ToServer((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2)
	),
]

WriteTest("001", data_type1)


# 002 - type 2 - no proxy, sec

SYN_COOKIE2 = 0x4e490b0b

test_002 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER2, ip_proxy=IP_SERVER2, start_seq_to_client=SYN_COOKIE2, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)

data_type2 = [
	(
		test_002.FromClient((0, None), 'S', options=options_client_syn), 
		test_002.ToClient((0, 1), 'AS', window=0, options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (1, ts_client)), ('WScale', 5)])
	), (
		test_002.FromClient((1, 1), 'A', options=[("Timestamp", (ts_client + 1, 1))]),
		test_002.ToServer((0, None), 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_client + 1, 0)), ('WScale', 5)])
	), (
		# Need retransmit SYN to server
		test_002.FromClient((0, 1), 'A', options=[("Timestamp", (ts_client + 1, 1))]),
		test_002.ToServer((0, None), 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_client + 1, 0)), ('WScale', 5)])
	), (
		test_002.FromServer((0, 1), 'SA', window=20000, options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client + 1)), ('WScale', 9)]),
		test_002.ToClient((1, 1), 'A', window=20000//16, options=[("Timestamp", (ts_proxy, ts_client + 1))])
	),
	(
		test_002.FromClient((1, 1), 'A', raw=data_client1, options=[("Timestamp", (ts_client + 2, ts_proxy)), ("NOP", ''), ("NOP", '')]),
		test_002.ToServer((1, 1), 'A', raw=data_client1, options=[("Timestamp", (ts_client + 2, ts_server))])
	),
	(
		test_002.FromServer((1, 1 + len(data_client1)), 'A', window=20000, raw=data_server1, options=[("Timestamp", (ts_server + 1, ts_client + 2))]), 
		test_002.ToClient((1, 1 + len(data_client1)), 'A', window=20000//16, raw=data_server1, options=[("Timestamp", (ts_proxy + 1, ts_client + 2))])
	),
]

WriteTest("002", data_type2)


# 003 - type 3 - proxy, no sec

test_003 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER3, ip_proxy=IP_SERVER3, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)

data_type3 = [
	(
		test_003.FromClient((0, None), 'S', options=options_client_syn),
		test_003.ToServer((-len_pr, None), 'S', options=options_client_syn)
	), (
		test_003.FromServer((0, 1 - len_pr), 'AS', options=options_server_syn),
		test_003.ToClient((0, 1), 'AS', options=options_server_syn_proxy)
	), (
		test_003.FromClient((1, 1), 'A', options=options_client_ack), 
		test_003.ToServer((1 - len_pr, 1), 'A', raw=test_003.GetProxyHeader(), options=options_client_ack)
	), (
		test_003.FromClient((1, 1), 'A', raw=data_client1, options=options_client_ack), 
		test_003.ToServer((1 - len_pr, 1), 'A', raw=test_003.GetProxyHeader() + data_client1.encode(), options=options_client_ack)
	), (
		test_003.FromServer((1, 1 + len(data_client1)), 'A', raw=data_server1),
		test_003.ToClient((1, 1 + len(data_client1)), 'A', raw=data_server1)
	), (
		test_003.FromClient((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2),
		test_003.ToServer((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2)
	),
]

WriteTest("003", data_type3)


# 004 - type 4 - proxy, sec, sack

SYN_COOKIE3 = 0xde8bc93b

test_004 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER4, ip_proxy=IP_SERVER4, start_seq_to_client=SYN_COOKIE3, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)

data_type4 = [
	(
		test_004.FromClient((0, None), 'S', options=options_client_syn), 
		test_004.ToClient((0, 1), 'AS', window=0, options=[("MSS", 1300-len_pr), ("SAckOK", ''), ("Timestamp", (1, ts_client)), ('WScale', 9)])
	), (
		test_004.FromClient((1, 1), 'A', options=[("Timestamp", (ts_client + 1, 1))]),
		test_004.ToServer((-len_pr, None), 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_client + 1, 0)), ('WScale', 5)])
	), (
		test_004.FromServer((0, 1 - len_pr), 'SA', window=20000, options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client + 1)), ('WScale', 5), ("NOP", '')]),
		test_004.ToClient((1, 1), 'A', window=65535, options=[("Timestamp", (ts_proxy, ts_client + 1))])
	),
	(
		test_004.FromClient((1, 1), 'A', raw=data_client1),
		test_004.ToServer((1 - len_pr, 1), 'A', raw=test_004.GetProxyHeader() + data_client1.encode())
	),
	( # Packet#3 out of order
		test_004.FromServer((1 + len(data_server1)*2, 1 + len(data_client1)), 'A', window=20000, raw=data_server1), 
		test_004.ToClient((1 + len(data_server1)*2, 1 + len(data_client1)), 'A', window=65535, raw=data_server1)
	),
	( # Packet#1
		test_004.FromServer((1, 1 + len(data_client1)), 'A', window=20000, raw=data_server1), 
		test_004.ToClient((1, 1 + len(data_client1)), 'A', window=65535, raw=data_server1)
	),
	# ( # Packet#2 Lost
	# 	test_004.FromServer((1 + len(data_server1), 1 + len(data_client1)), 'A', raw=data_server1), 
	# 	test_004.ToClient((1 + len(data_server1), 1 + len(data_client1)), 'A', raw=data_server1)
	# ),
	( # Ack Packet#1, SAck Packet#3
		test_004.FromClient((1 + len(data_client1), 1 + len(data_server1)), 'A', options=[("SAck", (SYN_COOKIE3 + 1 + len(data_server1)*2, SYN_COOKIE3 + 1 + len(data_server1)*3))], raw=data_client1),
		test_004.ToServer((1 + len(data_client1), 1 + len(data_server1)), 'A', options=[("SAck", (ProxyTest.START_SERVER_SEQ + 1 + len(data_server1)*2, ProxyTest.START_SERVER_SEQ + 1 + len(data_server1)*3))], raw=data_client1)
	),
	( # Packet#5 out of order
		test_004.FromServer((1 + len(data_server1)*4, 1 + len(data_client1)), 'A', window=20000, raw=data_server1), 
		test_004.ToClient((1 + len(data_server1)*4, 1 + len(data_client1)), 'A', window=65535, raw=data_server1)
	),
	# ( # Packet#4 Lost
	# 	test_004.FromServer((1 + len(data_server1)*3, 1 + len(data_client1)), 'A', raw=data_server1), 
	# 	test_004.ToClient((1 + len(data_server1)*3, 1 + len(data_client1)), 'A', raw=data_server1)
	# ),
	( # Duplicate Ack Packet#1, SAck Packet#5 and Packet#3
		test_004.FromClient((1 + len(data_client1), 1 + len(data_server1)), 'A', options=[("SAck", (SYN_COOKIE3 + 1 + len(data_server1)*4, SYN_COOKIE3 + 1 + len(data_server1)*5)), ("SAck",(SYN_COOKIE3 + 1 + len(data_server1)*2, SYN_COOKIE3 + 1 + len(data_server1)*3))], raw=data_client2),
		test_004.ToServer((1 + len(data_client1), 1 + len(data_server1)), 'A', options=[("SAck", (ProxyTest.START_SERVER_SEQ + 1 + len(data_server1)*4, ProxyTest.START_SERVER_SEQ + 1 + len(data_server1)*5)), ("SAck", (ProxyTest.START_SERVER_SEQ + 1 + len(data_server1)*2 , ProxyTest.START_SERVER_SEQ + 1 + len(data_server1)*3))], raw=data_client2)
	),
]

WriteTest("004", data_type4)


# 005 - pings

write_pcap("005-send.pcap",
           Ether(src=ProxyTest.MAC_CLIENT, dst=ProxyTest.MAC_PROXY)/Dot1Q(vlan=100)/IP(src=IP_CLIENT, dst=IP_SERVER1)/ICMP(type=8, code=0, id=1, seq=0x0001)/Raw("abcdef"),
           Ether(src=ProxyTest.MAC_CLIENT, dst=ProxyTest.MAC_PROXY)/Dot1Q(vlan=100)/IP(src=IP_CLIENT, dst=IP_SERVER2)/ICMP(type=8, code=0, id=1, seq=0x0001)/Raw("abcd"),
           Ether(src=ProxyTest.MAC_CLIENT, dst=ProxyTest.MAC_PROXY)/Dot1Q(vlan=100)/IP(src=IP_CLIENT, dst=IP_SERVER3)/ICMP(type=8, code=0, id=1, seq=0x0001)/Raw("ab"),
           Ether(src=ProxyTest.MAC_CLIENT, dst=ProxyTest.MAC_PROXY)/Dot1Q(vlan=100)/IP(src=IP_CLIENT, dst=IP_SERVER4)/ICMP(type=8, code=0, id=1, seq=0x0001),
)

write_pcap("005-expect.pcap",
           Ether(src=ProxyTest.MAC_PROXY, dst=ProxyTest.MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=IP_SERVER1, dst=IP_CLIENT, ttl=64)/ICMP(type=0, code=0, id=1, seq=0x0001)/Raw("abcdef"),
           Ether(src=ProxyTest.MAC_PROXY, dst=ProxyTest.MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=IP_SERVER2, dst=IP_CLIENT, ttl=64)/ICMP(type=0, code=0, id=1, seq=0x0001)/Raw("abcd"),
           Ether(src=ProxyTest.MAC_PROXY, dst=ProxyTest.MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=IP_SERVER3, dst=IP_CLIENT, ttl=64)/ICMP(type=0, code=0, id=1, seq=0x0001)/Raw("ab"),
           Ether(src=ProxyTest.MAC_PROXY, dst=ProxyTest.MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=IP_SERVER4, dst=IP_CLIENT, ttl=64)/ICMP(type=0, code=0, id=1, seq=0x0001),
)

# 006 - blacklist

test_005 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER5, ip_proxy=IP_SERVER5, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)
test_005_blocked = ProxyTest(ip_client=IP_BLOCKED_CLIENT, ip_server=IP_SERVER5, ip_proxy=IP_SERVER5, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)
test_005_blocked2 = ProxyTest(ip_client=IP_BLOCKED_CLIENT2, ip_server=IP_SERVER5, ip_proxy=IP_SERVER5, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)

data_type5 = [
    # Blocked client
    (
		test_005_blocked.FromClient((0, None), 'S', options=options_client_syn),
        # Drop
	),
    # Allowed client
	(
		test_005.FromClient((0, None), 'S', options=options_client_syn),
		test_005.ToServer((0, None), 'S', options=options_client_syn)
	), (
		test_005.FromServer((0, 1), 'AS', options=options_server_syn),
		test_005.ToClient((0, 1), 'AS', options=options_server_syn)
	), (
		test_005.FromClient((1, 1), 'A', raw=data_client1, options=options_client_ack),
		test_005.ToServer((1, 1), 'A', raw=data_client1, options=options_client_ack)
	), (
		test_005.FromServer((1, 1 + len(data_client1)), 'A', raw=data_server1),
		test_005.ToClient((1, 1 + len(data_client1)), 'A', raw=data_server1)
	), (
		test_005.FromClient((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2),
		test_005.ToServer((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2)
	),
    # Blocked client
    (
		test_005_blocked2.FromClient((0, None), 'S', options=options_client_syn),
        # Drop
	),
]

WriteTest("006", data_type5)


# 007 - Client send SYN, service don't answer, client send ACK

test_007 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER1, ip_proxy=IP_SERVER1, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT + 1, cport=PORT_CLIENT)

data_type7 = [
	(
		test_007.FromClient((0, None), 'S', options=options_client_syn),
		test_007.ToServer((0, None), 'S', options=options_client_syn)
	),
    # (
	#	test_007.FromServer((0, 1), 'AS', options=options_server_syn),
	#	test_007.ToClient((0, 1), 'AS', options=options_server_syn)
	# ),
    (
		test_007.FromClient((1, 1), 'A', raw=data_client1, options=options_client_ack),
	)
]

WriteTest("007", data_type7)
