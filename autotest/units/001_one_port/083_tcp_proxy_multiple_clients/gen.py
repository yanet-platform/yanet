#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.contrib.mpls import MPLS

import ipaddress

MAC_PROXY = "00:11:22:33:44:55"
MAC_CLIENT = "00:00:00:00:00:01"
MAC_SERVER = "00:00:00:00:00:0A"
IP_CLIENT1 = "10.0.2.1"
IP_CLIENT2 = "10.0.2.2"
IP_PROXY_INT = "10.0.0.1"
IP_SERVER1 = "10.0.3.1"
IP_SERVER2 = "10.0.3.2"
IP_SERVER3 = "10.0.3.3"
IP_SERVER4 = "10.0.3.4"

PORT_SERVER = 8080
PORT_PROXY_EXT = 80
PORT_PROXY_INT = 32768
PORT_PROXY_INT2 = 32769
PORT_PROXY_INT3 = PORT_PROXY_INT
PORT_PROXY_INT4 = PORT_PROXY_INT2
PORT_CLIENT = 12380

START_CLIENT_SEQ = 1000
START_CLIENT_SEQ2 = 10000
START_SERVER_SEQ = 2000
START_SERVER_SEQ2 = 20000


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

def FromClient(src, dst, seq, ack, flags, ttl=64, raw='', options=[]):
	return Ether(src=MAC_CLIENT, dst=MAC_PROXY)/Dot1Q(vlan=100)/IP(src=src, dst=dst, ttl=ttl)/TCP(sport=PORT_CLIENT, dport=PORT_PROXY_EXT, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)

def ToClient(src, dst, seq, ack, flags, ttl=63, raw='', options=[], window=8192):
	return Ether(src=MAC_PROXY, dst=MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=src, dst=dst, ttl=ttl)/TCP(sport=PORT_PROXY_EXT, dport=PORT_CLIENT, flags=flags, seq=seq, ack=ack, window=window, options=options)/Raw(raw)

def ToServer(src_port, dst, seq, ack, flags, ttl=63, raw='', options=[]):
	return Ether(src=MAC_PROXY, dst=MAC_SERVER)/Dot1Q(vlan=200)/IP(src=IP_PROXY_INT, dst=dst, ttl=ttl)/TCP(sport=src_port, dport=PORT_SERVER, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)

def FromServer(dst_port, src, seq, ack, flags, ttl=64, raw='', options=[]):
	return Ether(src=MAC_SERVER, dst=MAC_PROXY)/Dot1Q(vlan=200)/IP(src=src, dst=IP_PROXY_INT, ttl=ttl)/TCP(sport=PORT_SERVER, dport=dst_port, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)


def WriteTest(index, data):
	write_pcap(index + "-send.pcap", [pair[0] for pair in data])
	write_pcap(index + "-expect.pcap", [pair[1] for pair in data])

def get_proxy_header(client_addr, proxy_addr):
	client_addr = client_addr
	client_port = PORT_CLIENT
	proxy_port = PORT_PROXY_EXT
	proxy_signature = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
	return proxy_signature.encode() + "\x21\x11\x00\x0c".encode() +\
		int(ipaddress.ip_address(client_addr)).to_bytes(4, 'big') +\
		int(ipaddress.ip_address(proxy_addr)).to_bytes(4, 'big') +\
		client_port.to_bytes(2, 'big') + proxy_port.to_bytes(2, 'big')

data_client1 = 'client first'
data_client2 = 'client second'
data_server1 = 'client first'

ts_client = 2983139994
ts_proxy = 1
ts_server = 12345

len_pr = len(get_proxy_header(0, 0))

options_client_syn = [("MSS", 1460), ("SAckOK", ''), ("Timestamp", (ts_client, 0)), ('WScale', 5), ("NOP", '')]
options_client_ack = [("Timestamp", (1, 2)), ("NOP", ''), ("NOP", '')]
options_server_syn = [("MSS", 1260), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client)), ('WScale', 3), ("NOP", '')]
options_server_syn_proxy = [("MSS", 1260-len_pr), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client)), ('WScale', 3)]

# 001 - type 1 - no proxy, no sec

data_type1 = [
	(
		FromClient(IP_CLIENT1, IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(PORT_PROXY_INT, IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	),
	(
		FromClient(IP_CLIENT2, IP_SERVER1, START_CLIENT_SEQ2, 0, 'S', options=options_client_syn),
		ToServer(PORT_PROXY_INT2, IP_SERVER1, START_CLIENT_SEQ2, 0, 'S', options=options_client_syn)
	),
	(
		FromServer(PORT_PROXY_INT, IP_SERVER1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn),
		ToClient(IP_SERVER1, IP_CLIENT1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn)
    ),
	(
		FromServer(PORT_PROXY_INT2, IP_SERVER1, START_SERVER_SEQ2, START_CLIENT_SEQ2 + 1, 'AS', options=options_server_syn),
		ToClient(IP_SERVER1, IP_CLIENT2, START_SERVER_SEQ2, START_CLIENT_SEQ2 + 1, 'AS', options=options_server_syn)
    ),
	(
		FromClient(IP_CLIENT1, IP_SERVER1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack),
		ToServer(PORT_PROXY_INT, IP_SERVER1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack)
    ),
	(
		FromClient(IP_CLIENT2, IP_SERVER1, START_CLIENT_SEQ2 + 1, START_SERVER_SEQ2 + 1, 'A', raw=data_client1, options=options_client_ack),
		ToServer(PORT_PROXY_INT2, IP_SERVER1, START_CLIENT_SEQ2 + 1, START_SERVER_SEQ2 + 1, 'A', raw=data_client1, options=options_client_ack)
    ),
]

WriteTest("001", data_type1)

# 002 - type 2 - no proxy, sec

SYN_COOKIE = 0xa8624b85
SYN_COOKIE2 = 0xb8285337

data_type2 = [
	# clients syn -> synack clients
	(
		FromClient(IP_CLIENT1, IP_SERVER2, START_CLIENT_SEQ, 0, 'S', options=options_client_syn), 
		ToClient(IP_SERVER2, IP_CLIENT1, SYN_COOKIE, START_CLIENT_SEQ + 1, 'AS', window=0, options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_proxy, ts_client)), ('WScale', 9)])
	),
	(
		FromClient(IP_CLIENT2, IP_SERVER2, START_CLIENT_SEQ2, 0, 'S', options=options_client_syn), 
		ToClient(IP_SERVER2, IP_CLIENT2, SYN_COOKIE2, START_CLIENT_SEQ2 + 1, 'AS', window=0, options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_proxy, ts_client)), ('WScale', 9)])
	),
	# clients ack -> syn server
	(
		FromClient(IP_CLIENT1, IP_SERVER2, START_CLIENT_SEQ + 1, SYN_COOKIE + 1, 'A', options=[("Timestamp", (ts_client, ts_proxy))]),
		ToServer(PORT_PROXY_INT, IP_SERVER2, START_CLIENT_SEQ, 0, 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_client, 0)), ('WScale', 5)])
	),
	(
		FromClient(IP_CLIENT2, IP_SERVER2, START_CLIENT_SEQ2 + 1, SYN_COOKIE2 + 1, 'A', options=[("Timestamp", (ts_client, ts_proxy))]),
		ToServer(PORT_PROXY_INT2, IP_SERVER2, START_CLIENT_SEQ2, 0, 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_client, 0)), ('WScale', 5)])
	),
	# server synack -> ack clients
	(
		FromServer(PORT_PROXY_INT, IP_SERVER2, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'SA', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client)), ('WScale', 9), ("NOP", '')]),
		ToClient(IP_SERVER2, IP_CLIENT1, SYN_COOKIE + 1, START_CLIENT_SEQ + 1, 'A', options=[("Timestamp", (ts_proxy, ts_client))])
	),
	(
		FromServer(PORT_PROXY_INT2, IP_SERVER2, START_SERVER_SEQ2, START_CLIENT_SEQ2 + 1, 'SA', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client)), ('WScale', 9), ("NOP", '')]),
		ToClient(IP_SERVER2, IP_CLIENT2, SYN_COOKIE2 + 1, START_CLIENT_SEQ2 + 1, 'A', options=[("Timestamp", (ts_proxy, ts_client))])
	),
	# clients ack -> ack server
	(
		FromClient(IP_CLIENT1, IP_SERVER2, START_CLIENT_SEQ + 1, SYN_COOKIE + 1, 'A', raw=data_client1),
		ToServer(PORT_PROXY_INT, IP_SERVER2, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1)
	),
	(
		FromClient(IP_CLIENT2, IP_SERVER2, START_CLIENT_SEQ2 + 1, SYN_COOKIE2 + 1, 'A', raw=data_client1),
		ToServer(PORT_PROXY_INT2, IP_SERVER2, START_CLIENT_SEQ2 + 1, START_SERVER_SEQ2 + 1, 'A', raw=data_client1)
	),
	# server ack -> ack clients
	(
		FromServer(PORT_PROXY_INT, IP_SERVER2, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1), 
		ToClient(IP_SERVER2, IP_CLIENT1, SYN_COOKIE + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	),
	(
		FromServer(PORT_PROXY_INT2, IP_SERVER2, START_SERVER_SEQ2 + 1, START_CLIENT_SEQ2 + 1 + len(data_client1), 'A', raw=data_server1), 
		ToClient(IP_SERVER2, IP_CLIENT2, SYN_COOKIE2 + 1, START_CLIENT_SEQ2 + 1 + len(data_client1), 'A', raw=data_server1)
	),
]

WriteTest("002", data_type2)

# 003 - type 3 - proxy, no sec

data_type3 = [
	# clients syn -> syn server
	(
		FromClient(IP_CLIENT1, IP_SERVER3, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(PORT_PROXY_INT, IP_SERVER3, START_CLIENT_SEQ - len_pr, 0, 'S', options=options_client_syn)
	),
	(
		FromClient(IP_CLIENT2, IP_SERVER3, START_CLIENT_SEQ2, 0, 'S', options=options_client_syn),
		ToServer(PORT_PROXY_INT2, IP_SERVER3, START_CLIENT_SEQ2 - len_pr, 0, 'S', options=options_client_syn)
	),
	# server synack -> synack clients
	(
		FromServer(PORT_PROXY_INT, IP_SERVER3, START_SERVER_SEQ, START_CLIENT_SEQ + 1 - len_pr, 'AS', options=options_server_syn),
		ToClient(IP_SERVER3, IP_CLIENT1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn_proxy)
	),
	(
		FromServer(PORT_PROXY_INT2, IP_SERVER3, START_SERVER_SEQ2, START_CLIENT_SEQ2 + 1 - len_pr, 'AS', options=options_server_syn),
		ToClient(IP_SERVER3, IP_CLIENT2, START_SERVER_SEQ2, START_CLIENT_SEQ2 + 1, 'AS', options=options_server_syn_proxy)
	),
	# clients ack -> ack server
	(
		FromClient(IP_CLIENT1, IP_SERVER3, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack), 
		ToServer(PORT_PROXY_INT, IP_SERVER3, START_CLIENT_SEQ + 1 - len_pr, START_SERVER_SEQ + 1, 'A', raw=get_proxy_header(IP_CLIENT1, IP_SERVER3) + data_client1.encode(), options=options_client_ack)
	),
	(
		FromClient(IP_CLIENT2, IP_SERVER3, START_CLIENT_SEQ2 + 1, START_SERVER_SEQ2 + 1, 'A', raw=data_client1, options=options_client_ack), 
		ToServer(PORT_PROXY_INT2, IP_SERVER3, START_CLIENT_SEQ2 + 1 - len_pr, START_SERVER_SEQ2 + 1, 'A', raw=get_proxy_header(IP_CLIENT2, IP_SERVER3) + data_client1.encode(), options=options_client_ack)
	),
	# server ack -> ack clients
	(
		FromServer(PORT_PROXY_INT, IP_SERVER3, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1),
		ToClient(IP_SERVER3, IP_CLIENT1, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	),
	(
		FromServer(PORT_PROXY_INT2, IP_SERVER3, START_SERVER_SEQ2 + 1, START_CLIENT_SEQ2 + 1 + len(data_client1), 'A', raw=data_server1),
		ToClient(IP_SERVER3, IP_CLIENT2, START_SERVER_SEQ2 + 1, START_CLIENT_SEQ2 + 1 + len(data_client1), 'A', raw=data_server1)
	),
	# clients ack -> ack server
	(
		FromClient(IP_CLIENT1, IP_SERVER3, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', raw=data_client2),
		ToServer(PORT_PROXY_INT, IP_SERVER3, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', raw=data_client2)
	),
	(
		FromClient(IP_CLIENT2, IP_SERVER3, START_CLIENT_SEQ2 + 1 + len(data_client1), START_SERVER_SEQ2 + 1 + len(data_server1), 'A', raw=data_client2),
		ToServer(PORT_PROXY_INT2, IP_SERVER3, START_CLIENT_SEQ2 + 1 + len(data_client1), START_SERVER_SEQ2 + 1 + len(data_server1), 'A', raw=data_client2)
	),
]

WriteTest("003", data_type3)

# 004 - type 4 - proxy, sec

SYN_COOKIE3 = 0x189488b5
SYN_COOKIE4 = 0x48f69107

data_type4  = [
	# clients syn -> synack clients
	(
		FromClient(IP_CLIENT1, IP_SERVER4, START_CLIENT_SEQ, 0, 'S', options=options_client_syn), 
		ToClient(IP_SERVER4, IP_CLIENT1, SYN_COOKIE3, START_CLIENT_SEQ + 1, 'AS', window=0, options=[("MSS", 1300-len_pr), ("SAckOK", ''), ("Timestamp", (ts_proxy, ts_client)), ('WScale', 9)])
	),
	(
		FromClient(IP_CLIENT2, IP_SERVER4, START_CLIENT_SEQ2, 0, 'S', options=options_client_syn), 
		ToClient(IP_SERVER4, IP_CLIENT2, SYN_COOKIE4, START_CLIENT_SEQ2 + 1, 'AS', window=0, options=[("MSS", 1300-len_pr), ("SAckOK", ''), ("Timestamp", (ts_proxy, ts_client)), ('WScale', 9)])
	),
	# clients ack -> syn server
	(
		FromClient(IP_CLIENT1, IP_SERVER4, START_CLIENT_SEQ + 1, SYN_COOKIE3 + 1, 'A', options=[("Timestamp", (ts_server, ts_proxy))]),
		ToServer(PORT_PROXY_INT3, IP_SERVER4, START_CLIENT_SEQ - len_pr, 0, 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_server, 0)), ('WScale', 5)])
	),
	(
		FromClient(IP_CLIENT2, IP_SERVER4, START_CLIENT_SEQ2 + 1, SYN_COOKIE4 + 1, 'A', options=[("Timestamp", (ts_server, ts_proxy))]),
		ToServer(PORT_PROXY_INT4, IP_SERVER4, START_CLIENT_SEQ2 - len_pr, 0, 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_server, 0)), ('WScale', 5)])
	),
	# server synack -> ack clients
	(
		FromServer(PORT_PROXY_INT3, IP_SERVER4, START_SERVER_SEQ, START_CLIENT_SEQ + 1 - len_pr, 'SA', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client)), ('WScale', 9), ("NOP", '')]),
		ToClient(IP_SERVER4, IP_CLIENT1, SYN_COOKIE3 + 1, START_CLIENT_SEQ + 1, 'A', options=[("Timestamp", (ts_proxy, ts_client))])
	),
	(
		FromServer(PORT_PROXY_INT4, IP_SERVER4, START_SERVER_SEQ2, START_CLIENT_SEQ2 + 1 - len_pr, 'SA', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client)), ('WScale', 9), ("NOP", '')]),
		ToClient(IP_SERVER4, IP_CLIENT2, SYN_COOKIE4 + 1, START_CLIENT_SEQ2 + 1, 'A', options=[("Timestamp", (ts_proxy, ts_client))])
	),
	# clients ack -> ack server
	(
		FromClient(IP_CLIENT1, IP_SERVER4, START_CLIENT_SEQ + 1, SYN_COOKIE3 + 1, 'A', raw=data_client1),
		ToServer(PORT_PROXY_INT3, IP_SERVER4, START_CLIENT_SEQ + 1 - len_pr, START_SERVER_SEQ + 1, 'A', raw=get_proxy_header(IP_CLIENT1, IP_SERVER4) + data_client1.encode())
	),
	(
		FromClient(IP_CLIENT2, IP_SERVER4, START_CLIENT_SEQ2 + 1, SYN_COOKIE4 + 1, 'A', raw=data_client1),
		ToServer(PORT_PROXY_INT4, IP_SERVER4, START_CLIENT_SEQ2 + 1 - len_pr, START_SERVER_SEQ2 + 1, 'A', raw=get_proxy_header(IP_CLIENT2, IP_SERVER4) + data_client1.encode())
	),
	# server ack -> ack clients
	(
		FromServer(PORT_PROXY_INT3, IP_SERVER4, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1), 
		ToClient(IP_SERVER4, IP_CLIENT1, SYN_COOKIE3 + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	),
	(
		FromServer(PORT_PROXY_INT4, IP_SERVER4, START_SERVER_SEQ2 + 1, START_CLIENT_SEQ2 + 1 + len(data_client1), 'A', raw=data_server1), 
		ToClient(IP_SERVER4, IP_CLIENT2, SYN_COOKIE4 + 1, START_CLIENT_SEQ2 + 1 + len(data_client1), 'A', raw=data_server1)
	),
]

WriteTest("004", data_type4)