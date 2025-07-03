#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
sys.path.insert(1, '../083_tcp_proxy')

from proxy_test import *

IP_SERVER1 = "10.0.4.1"
IP_SERVER2 = "10.0.4.2"
IP_SERVER3 = "10.0.4.3"

IP_CLIENT = "10.0.2.1"

PORT_CLIENT = 12380
PORT_PROXY_INT = 32768

ts_client = 2983139994
ts_proxy = 1
ts_server = 12345

data_client1 = 'client first'
data_client2 = 'client second'
data_server1 = 'client first'

options_client_syn = [("MSS", 1460), ("SAckOK", ''), ("Timestamp", (ts_client, 0)), ('WScale', 5), ("NOP", '')]

# 001 - syn rentransmit use the same local address + port

test_001 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER1, ip_proxy=IP_SERVER1, start_seq_to_client=0, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)

data_type1 = [
	(
		test_001.FromClient((0, None), 'S', options=options_client_syn),
		test_001.ToServer((0, None), 'S', options=options_client_syn)
	), (
		test_001.FromClient((0, None), 'S', options=options_client_syn),
		test_001.ToServer((0, None), 'S', options=options_client_syn)
	),
]

WriteTest("001", data_type1)

# 002 - Error in SACK config - the server does not support SACK, although the configuration file states that it supports

SYN_COOKIE2 = 0x46964916
test_002 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER2, ip_proxy=IP_SERVER2, start_seq_to_client=SYN_COOKIE2, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)

data_type2 = [
	(
		test_002.FromClient((0, None), 'S', options=options_client_syn), 
		test_002.ToClient((0, 1), 'AS', window=0, options=Options(mss=1460, sack_ok=True, ts=(1, ts_client), wscale=14))
	), (
		test_002.FromClient((1, 1), 'A', options=Options(ts=(ts_client + 1, 1))),
		test_002.ToServer((0, None), 'S', options=Options(mss=1460, sack_ok=True, ts=(ts_client + 1, 0), wscale=5))
	), (
		# No SAckOK from server
		test_002.FromServer((0, 1), 'SA', window=10000, options=Options(mss=1460, ts=(ts_server, ts_client + 1), wscale=12)),
		test_002.ToClient((1, 1), 'A', window=10000 * 4, options=Options(ts=(ts_proxy, ts_client + 1)))
	), (
		# Client send SACK, proxy will remove it
		test_002.FromClient((1, 1), 'A', raw=data_client1, options=[("SAck", (SYN_COOKIE2 + 1, SYN_COOKIE2 + 2)), ("Timestamp", (ts_client + 2, ts_proxy))]),
		test_002.ToServer((1, 1), 'A', raw=data_client1, options=Options(ts=(ts_client + 2, ts_server)))
	),
]

WriteTest("002", data_type2)

'''
	Tests with timestamps - case syn-cookie
'''

PORT_CLIENT_TS = 12500

# ts1 - Client does not support timestamps

SYN_COOKIE_TS_1 = 0x391dfefa
test_ts1 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER2, ip_proxy=IP_SERVER2, start_seq_to_client=SYN_COOKIE_TS_1, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT_TS)

# The first client packet does not contain timestamps, the proxy response should not contain timestamps
data_type_ts_1 = [
	(
		test_ts1.FromClient((0, None), 'S', options=[("MSS", 1460), ("SAckOK", ''), ('WScale', 5), ("NOP", ''), ("NOP", ''), ("NOP", '')]),
		test_ts1.ToClient((0, 1), 'AS', window=0, options=[("MSS", 1460), ("SAckOK", ''), ('WScale', 14)])
	)
]

WriteTest("003_ts_1", data_type_ts_1)

# ts2 - Client supports timestamps, but on proxy - disabled

SYN_COOKIE_TS_2 = 0x535e3eda
test_ts2 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER3, ip_proxy=IP_SERVER3, start_seq_to_client=SYN_COOKIE_TS_2, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT_TS+1)

# The first client packet contains timestamps, but timestamps disabled on proxy, the proxy response should not contain timestamps
data_type_ts_2 = [
	(
		test_ts2.FromClient((0, None), 'S', options=options_client_syn),
		test_ts2.ToClient((0, 1), 'AS', window=0, options=[("MSS", 1460), ("SAckOK", ''), ('WScale', 14)])
	)
]

WriteTest("003_ts_2", data_type_ts_2)

# ts3 - Client and proxy supports timestamps, but service does not

SYN_COOKIE_TS_3 = 0x908e7fba
test_ts3 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER2, ip_proxy=IP_SERVER2, start_seq_to_client=SYN_COOKIE_TS_3, port_proxy=PORT_PROXY_INT + 1, cport=PORT_CLIENT_TS+2)

data_type_ts_3 = [
	(
		test_ts3.FromClient((0, None), 'S', options=options_client_syn), 
		test_ts3.ToClient((0, 1), 'AS', window=0, options=[("MSS", 1460), ("SAckOK", ''), ("Timestamp", (ts_proxy, ts_client)), ('WScale', 14)])
	), (
		test_ts3.FromClient((1, 1), 'A', options=[("Timestamp", (ts_client + 1, 1))]),
		test_ts3.ToServer((0, None), 'S', options=[("MSS", 1460), ("SAckOK", ''), ("Timestamp", (ts_client + 1, 0)), ('WScale', 5)])
	), (
		# no timestamp from service, add timestamps to client
		test_ts3.FromServer((0, 1), 'SA', options=[("MSS", 1460), ("SAckOK", ''), ('WScale', 14)]),
		test_ts3.ToClient((1, 1), 'A', options=[("Timestamp", (ts_proxy + 1, ts_client + 1))])
	),
	(
		# remove timestamp for service
		test_ts3.FromClient((1, 1), 'A', raw=data_client1, options=[("Timestamp", (ts_client + 2, ts_proxy + 1)), ("NOP", ''), ("NOP", '')]),
		test_ts3.ToServer((1, 1), 'A', raw=data_client1)
	),
	(
		# no timestamp from service, add timestamps to client
		test_ts3.FromServer((1, 1 + len(data_client1)), 'A', raw=data_server1), 
		test_ts3.ToClient((1, 1 + len(data_client1)), 'A', raw=data_server1, options=[("Timestamp", (ts_proxy + 2, ts_client + 2))])
	)
]

WriteTest("003_ts_3", data_type_ts_3)
