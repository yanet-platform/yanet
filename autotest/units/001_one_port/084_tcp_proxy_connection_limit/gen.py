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

IP_PROXY_INT = "10.0.0.0"
IP_PROXY_INT2 = "10.0.0.1"
IP_PROXY_INT3 = "10.0.0.2"
IP_PROXY_INT4 = "10.0.0.3"
IP_PROXY_INT5 = "10.0.0.4"

IP_SERVER1 = "10.0.1.1"
IP_SERVER2 = "10.0.1.2"

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


def write_pcap(filename, packetsList):
	if len(packetsList) == 0:
		print("No packets to write")
		PcapWriter(filename, linktype=DLT_EN10MB)._write_header(Ether())
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

def FromClient(src, dst, port, seq, ack, flags, ttl=64, raw='', options=[]):
	return Ether(src=MAC_CLIENT, dst=MAC_PROXY)/Dot1Q(vlan=100)/IP(src=src, dst=dst, ttl=ttl)/TCP(sport=port, dport=PORT_PROXY_EXT, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)

def ToClient(src, dst, port, seq, ack, flags, ttl=63, raw='', options=[], window=8192):
	return Ether(src=MAC_PROXY, dst=MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=src, dst=dst, ttl=ttl)/TCP(sport=PORT_PROXY_EXT, dport=port, flags=flags, seq=seq, ack=ack, window=window, options=options)/Raw(raw)

def ToServer(src, dst, seq, ack, flags, ttl=63, raw='', options=[]):
	return Ether(src=MAC_PROXY, dst=MAC_SERVER)/Dot1Q(vlan=200)/IP(src=src, dst=dst, ttl=ttl)/TCP(sport=PORT_PROXY_INT, dport=PORT_SERVER, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)

def FromServer(dst, src, seq, ack, flags, ttl=64, raw='', options=[]):
	return Ether(src=MAC_SERVER, dst=MAC_PROXY)/Dot1Q(vlan=200)/IP(src=src, dst=dst, ttl=ttl)/TCP(sport=PORT_SERVER, dport=PORT_PROXY_INT, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)


def WriteTest(index, data):
	write_pcap(index + "-send.pcap", [pair[0] for pair in data])
	write_pcap(index + "-expect.pcap", [pair[1] for pair in data if len(pair) == 2])

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

# 001 - before blacklist

data_type1 = [
	(
		FromClient(IP_CLIENT1, IP_SERVER1, PORT_CLIENT, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(IP_PROXY_INT, IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	),
	(
		FromServer(IP_PROXY_INT, IP_SERVER1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn),
		ToClient(IP_SERVER1, IP_CLIENT1, PORT_CLIENT, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn)
    ),
	(
		FromClient(IP_CLIENT1, IP_SERVER1, PORT_CLIENT, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack),
		ToServer(IP_PROXY_INT, IP_SERVER1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack)
    ),
]

WriteTest("001", data_type1)

# 002 - after blacklist

data_type2 = [
	(
		FromClient(IP_CLIENT1, IP_SERVER1, PORT_CLIENT + 1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
	),
]

WriteTest("002", data_type2)

# 003 - blacklist timeout, second connection

data_type3 = [
	(
		FromClient(IP_CLIENT1, IP_SERVER1, PORT_CLIENT + 1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(IP_PROXY_INT2, IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	),
	(
		FromServer(IP_PROXY_INT2, IP_SERVER1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn),
		ToClient(IP_SERVER1, IP_CLIENT1, PORT_CLIENT + 1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn)
    ),
	(
		FromClient(IP_CLIENT1, IP_SERVER1, PORT_CLIENT + 1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack),
		ToServer(IP_PROXY_INT2, IP_SERVER1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack)
    ),
]

WriteTest("003", data_type3)

# 004 - max connections reached, blacklist

data_type4 = [
	(
		FromClient(IP_CLIENT1, IP_SERVER1, PORT_CLIENT + 2, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
	),
]

WriteTest("004", data_type4)

# 005 - whitelist part 1

data_type5 = [
	# 1st connection
	(
		FromClient(IP_CLIENT2, IP_SERVER1, PORT_CLIENT, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(IP_PROXY_INT3, IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	),
	(
		FromServer(IP_PROXY_INT3, IP_SERVER1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn),
		ToClient(IP_SERVER1, IP_CLIENT2, PORT_CLIENT, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn)
    ),
	(
		FromClient(IP_CLIENT2, IP_SERVER1, PORT_CLIENT, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack),
		ToServer(IP_PROXY_INT3, IP_SERVER1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack)
    ),
	# 2nd connection
	(
		FromClient(IP_CLIENT2, IP_SERVER1, PORT_CLIENT + 1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(IP_PROXY_INT4, IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	),
	(
		FromServer(IP_PROXY_INT4, IP_SERVER1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn),
		ToClient(IP_SERVER1, IP_CLIENT2, PORT_CLIENT + 1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn)
    ),
	(
		FromClient(IP_CLIENT2, IP_SERVER1, PORT_CLIENT + 1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack),
		ToServer(IP_PROXY_INT4, IP_SERVER1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack)
    ),
]

WriteTest("005", data_type5)

# conn limit reached, but address is in whitelist
# 3rd connection
data_type5_2 = [
	(
		FromClient(IP_CLIENT2, IP_SERVER1, PORT_CLIENT + 2, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(IP_PROXY_INT5, IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	),
	(
		FromServer(IP_PROXY_INT5, IP_SERVER1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn),
		ToClient(IP_SERVER1, IP_CLIENT2, PORT_CLIENT + 2, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn)
    ),
	(
		FromClient(IP_CLIENT2, IP_SERVER1, PORT_CLIENT + 2, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack),
		ToServer(IP_PROXY_INT5, IP_SERVER1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack)
    )
]

WriteTest("005_2", data_type5_2)

# dry run

# 006 - before blacklist

data_type6 = [
	(
		FromClient(IP_CLIENT1, IP_SERVER2, PORT_CLIENT, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(IP_PROXY_INT, IP_SERVER2, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	),
	(
		FromServer(IP_PROXY_INT, IP_SERVER2, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn),
		ToClient(IP_SERVER2, IP_CLIENT1, PORT_CLIENT, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn)
    ),
	(
		FromClient(IP_CLIENT1, IP_SERVER2, PORT_CLIENT, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack),
		ToServer(IP_PROXY_INT, IP_SERVER2, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack)
    ),
]

WriteTest("006", data_type6)

# 007 - after blacklist

data_type7 = [
	(
		FromClient(IP_CLIENT1, IP_SERVER2, PORT_CLIENT + 1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(IP_PROXY_INT2, IP_SERVER2, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	),
	(
		FromServer(IP_PROXY_INT2, IP_SERVER2, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn),
		ToClient(IP_SERVER2, IP_CLIENT1, PORT_CLIENT + 1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn)
    ),
	(
		FromClient(IP_CLIENT1, IP_SERVER2, PORT_CLIENT + 1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack),
		ToServer(IP_PROXY_INT2, IP_SERVER2, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack)
    ),
]

WriteTest("007", data_type7)