#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from proxy_test import *

IP_SERVER1 = "10.0.1.1"

IP_CLIENT = "10.0.2.1"

PORT_PROXY_INT = 32768
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


# 001 - 1st prefix

test_001 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER1, ip_proxy=IP_SERVER1, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)

data_type1 = [
	(
		test_001.FromClient((0, None), 'S', options=options_client_syn),
		test_001.ToServer((0, None), 'S', options=options_client_syn)
	),
    (
		test_001.FromServer((0, 1), 'AS', options=options_server_syn),
		test_001.ToClient((0, 1), 'AS', options=options_server_syn)
	),
    (
		test_001.FromClient((1, 1), 'A', raw=data_client1, options=options_client_ack),
		test_001.ToServer((1, 1), 'A', raw=data_client1, options=options_client_ack)
	),
    (
		test_001.FromServer((1, 1 + len(data_client1)), 'A', raw=data_server1),
		test_001.ToClient((1, 1 + len(data_client1)), 'A', raw=data_server1)
	),
    (
		test_001.FromClient((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2),
		test_001.ToServer((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2)
	),
]

WriteTest("001", data_type1)

# 002 - 2nd prefix

test_002 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER1, ip_proxy=IP_SERVER1, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT+1, proxy_int=ProxyTest.IP_PROXY_INT2)

data_type2 = [
	(
		test_002.FromClient((0, None), 'S', options=options_client_syn),
		test_002.ToServer((0, None), 'S', options=options_client_syn)
	),
    (
		test_002.FromServer((0, 1), 'AS', options=options_server_syn),
		test_002.ToClient((0, 1), 'AS', options=options_server_syn)
	),
    (
		test_002.FromClient((1, 1), 'A', raw=data_client1, options=options_client_ack),
		test_002.ToServer((1, 1), 'A', raw=data_client1, options=options_client_ack)
	),
    (
		test_002.FromServer((1, 1 + len(data_client1)), 'A', raw=data_server1),
		test_002.ToClient((1, 1 + len(data_client1)), 'A', raw=data_server1)
	),
    (
		test_002.FromClient((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2),
		test_002.ToServer((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2)
	),
]

WriteTest("002", data_type2)

# 003 - 3rd prefix

test_003 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER1, ip_proxy=IP_SERVER1, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT+2, proxy_int=ProxyTest.IP_PROXY_INT3)

data_type3 = [
	(
		test_003.FromClient((0, None), 'S', options=options_client_syn),
		test_003.ToServer((0, None), 'S', options=options_client_syn)
	),
    (
		test_003.FromServer((0, 1), 'AS', options=options_server_syn),
		test_003.ToClient((0, 1), 'AS', options=options_server_syn)
	),
    (
		test_003.FromClient((1, 1), 'A', raw=data_client1, options=options_client_ack),
		test_003.ToServer((1, 1), 'A', raw=data_client1, options=options_client_ack)
	),
    (
		test_003.FromServer((1, 1 + len(data_client1)), 'A', raw=data_server1),
		test_003.ToClient((1, 1 + len(data_client1)), 'A', raw=data_server1)
	),
    (
		test_003.FromClient((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2),
		test_003.ToServer((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2)
	),
]

WriteTest("003", data_type3)
