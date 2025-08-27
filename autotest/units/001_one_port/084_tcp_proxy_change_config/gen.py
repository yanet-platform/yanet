#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
sys.path.insert(1, '../084_tcp_proxy')

from proxy_test import *
from scapy.all import *

IP_SERVER1 = "10.0.5.1"
IP_SERVER2 = "10.0.5.2"
IP_SERVER3 = "10.0.5.3"
IP_SERVER4 = "10.0.5.4"

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

def FullSessionFromClient(test):
	data = [
		(
			test.FromClient((0, None), 'S', options=options_client_syn),
			test.ToServer((0, None), 'S', options=options_client_syn)
		), (
			test.FromServer((0, 1), 'AS', options=options_server_syn),
			test.ToClient((0, 1), 'AS', options=options_server_syn)
		), (
			test.FromClient((1, 1), 'A', raw=data_client1, options=options_client_ack),
			test.ToServer((1, 1), 'A', raw=data_client1, options=options_client_ack)
		), (
			test.FromServer((1, 1 + len(data_client1)), 'A', raw=data_server1),
			test.ToClient((1, 1 + len(data_client1)), 'A', raw=data_server1)
		), (
			test.FromClient((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2),
			test.ToServer((1 + len(data_client1), 1 + len(data_server1)), 'A', raw=data_client2)
		),
	]
	return data

def RemoveAnswers(data):
	return [[first] for first, _ in data]

# Step 1:
# 	3 services: IP_SERVER1, IP_SERVER2, IP_SERVER3

test1 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER1, ip_proxy=IP_SERVER1, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)
WriteTest("001_1", FullSessionFromClient(test1))

test2 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER2, ip_proxy=IP_SERVER2, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)
WriteTest("001_2", FullSessionFromClient(test2))

test3 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER3, ip_proxy=IP_SERVER3, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)
WriteTest("001_3", FullSessionFromClient(test3))


# Step 2:
#	Remove service IP_SERVER1
#   No changes for service IP_SERVER2
#	Changed table sizes for service IP_SERVER3 - all connections cleared
#	New service IP_SERVER4

WriteTest("002_1", RemoveAnswers(FullSessionFromClient(test1)))

WriteTest("002_2_1", FullSessionFromClient(test2)[-2:])
test2.cport = PORT_CLIENT + 1
test2.proxy_int = ProxyTest.IP_PROXY_INT2
WriteTest("002_2_2", FullSessionFromClient(test2))

WriteTest("002_3_1", RemoveAnswers(FullSessionFromClient(test3)[-2:]))	# No old sessions
WriteTest("002_3_2", FullSessionFromClient(test3))

test4 = ProxyTest(ip_client=IP_CLIENT, ip_server=IP_SERVER4, ip_proxy=IP_SERVER4, start_seq_to_client=ProxyTest.START_SERVER_SEQ, port_proxy=PORT_PROXY_INT, cport=PORT_CLIENT)
WriteTest("002_4", FullSessionFromClient(test4))

# Step 3:
# Remove services IP_SERVER3, IP_SERVER4
# Changed prefix in local pool - for service IP_SERVER2 all connections cleared

test2.cport = PORT_CLIENT
test2.proxy_int = ProxyTest.IP_PROXY_INT
WriteTest("003_2_1", RemoveAnswers(FullSessionFromClient(test2)[-2:]))	# No old sessions
WriteTest("003_2_2", FullSessionFromClient(test2))

WriteTest("003_3", RemoveAnswers(FullSessionFromClient(test3)))

WriteTest("003_4", RemoveAnswers(FullSessionFromClient(test4)))
