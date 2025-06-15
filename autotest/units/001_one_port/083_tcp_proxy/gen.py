#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.contrib.mpls import MPLS

import ipaddress

MAC_PROXY = "00:11:22:33:44:55"
MAC_CLIENT = "00:00:00:00:00:01"
MAC_SERVER = "00:00:00:00:00:0A"
IP_CLIENT = "10.0.2.1"
IP_PROXY_INT = "10.0.0.1"
IP_SERVER1 = "10.0.1.1"
IP_SERVER2 = "10.0.1.2"
IP_SERVER3 = "10.0.1.3"
IP_SERVER4 = "10.0.1.4"

PORT_SERVER = 8080
PORT_PROXY_EXT = 80
PORT_PROXY_INT = 32768
PORT_PROXY_INT2 = 32769
PORT_CLIENT = 12380

START_CLIENT_SEQ = 1000
START_SERVER_SEQ = 2000


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

def FromClient(dst, seq, ack, flags, ttl=64, raw='', options=[]):
	return Ether(src=MAC_CLIENT, dst=MAC_PROXY)/Dot1Q(vlan=100)/IP(src=IP_CLIENT, dst=dst, ttl=ttl)/TCP(sport=PORT_CLIENT, dport=PORT_PROXY_EXT, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)

def ToClient(src, seq, ack, flags, ttl=63, raw='', options=[], window=8192):
	return Ether(src=MAC_PROXY, dst=MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=src, dst=IP_CLIENT, ttl=ttl)/TCP(sport=PORT_PROXY_EXT, dport=PORT_CLIENT, flags=flags, seq=seq, ack=ack, window=window, options=options)/Raw(raw)

def ToServer(port, dst, seq, ack, flags, ttl=63, raw='', options=[]):
	return Ether(src=MAC_PROXY, dst=MAC_SERVER)/Dot1Q(vlan=200)/IP(src=IP_PROXY_INT, dst=dst, ttl=ttl)/TCP(sport=port, dport=PORT_SERVER, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)

def FromServer(port, src, seq, ack, flags, ttl=64, raw='', window=8192, options=[]):
	return Ether(src=MAC_SERVER, dst=MAC_PROXY)/Dot1Q(vlan=200)/IP(src=src, dst=IP_PROXY_INT, ttl=ttl)/TCP(sport=PORT_SERVER, dport=port, flags=flags, seq=seq, ack=ack, options=options, window=window)/Raw(raw)


def WriteTest(index, data):
	write_pcap(index + "-send.pcap", [pair[0] for pair in data])
	write_pcap(index + "-expect.pcap", [pair[1] for pair in data])

def get_proxy_header(proxy_addr):
	client_addr = IP_CLIENT
	client_port = PORT_CLIENT
	proxy_port = PORT_PROXY_EXT
	proxy_signature = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
	return proxy_signature.encode() + "\x21\x11\x00\x0c".encode() +\
		int(ipaddress.ip_address(client_addr)).to_bytes(4, 'big') +\
		int(ipaddress.ip_address(proxy_addr)).to_bytes(4, 'big') +\
		client_port.to_bytes(2, 'big') + proxy_port.to_bytes(2, 'big')

len_pr = len(get_proxy_header(0))

data_client1 = 'client first'
data_client2 = 'client second'
data_server1 = 'server first'
data_server2 = 'server second'

ts_client = 2983139994
ts_proxy = 1
ts_server = 12345

options_client_syn = [("MSS", 1460), ("SAckOK", ''), ("Timestamp", (ts_client, 0)), ('WScale', 5), ("NOP", '')]
options_client_ack = [("Timestamp", (1, 2)), ("NOP", ''), ("NOP", '')]
options_server_syn = [("MSS", 1260), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client)), ('WScale', 3), ("NOP", '')]
options_server_syn_proxy = [("MSS", 1260-len_pr), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client)), ('WScale', 3), ("NOP", '')]


# 001 - type 1 - no proxy, no sec

data_type1 = [
	(
		FromClient(IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(PORT_PROXY_INT, IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	), (
		FromServer(PORT_PROXY_INT, IP_SERVER1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn),
		ToClient(IP_SERVER1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn)
	), (
		FromClient(IP_SERVER1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack),
		ToServer(PORT_PROXY_INT, IP_SERVER1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack)
	), (
		FromServer(PORT_PROXY_INT, IP_SERVER1, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1),
		ToClient(IP_SERVER1, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	), (
		FromClient(IP_SERVER1, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', raw=data_client2),
		ToServer(PORT_PROXY_INT, IP_SERVER1, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', raw=data_client2)
	),
]

WriteTest("001", data_type1)


# 002 - type 2 - no proxy, sec

SYN_COOKIE2 = 0x4e490b0b

data_type2 = [
	(
		FromClient(IP_SERVER2, START_CLIENT_SEQ, 0, 'S', options=options_client_syn), 
		ToClient(IP_SERVER2, SYN_COOKIE2, START_CLIENT_SEQ + 1, 'AS', window=0, options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (1, ts_client)), ('WScale', 5), ("NOP", '')])
	), (
		FromClient(IP_SERVER2, START_CLIENT_SEQ + 1, SYN_COOKIE2 + 1, 'A', options=[("Timestamp", (ts_client + 1, 1))]),
		ToServer(PORT_PROXY_INT, IP_SERVER2, START_CLIENT_SEQ, 0, 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_client + 1, 0)), ('WScale', 5), ("NOP", '')])
	), (
		# Need retransmit SYN to server
		FromClient(IP_SERVER2, START_CLIENT_SEQ, SYN_COOKIE2 + 1, 'A', options=[("Timestamp", (ts_client + 1, 1))]),
		ToServer(PORT_PROXY_INT, IP_SERVER2, START_CLIENT_SEQ, 0, 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_client + 1, 0)), ('WScale', 5), ("NOP", '')])
	), (
		FromServer(PORT_PROXY_INT, IP_SERVER2, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'SA', window=20000, options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client + 1)), ('WScale', 9), ("NOP", '')]),
		ToClient(IP_SERVER2, SYN_COOKIE2 + 1, START_CLIENT_SEQ + 1, 'A', window=20000//16, options=[("Timestamp", (ts_proxy, ts_client + 1)), ("NOP", ''), ("NOP", '')])
	),
	(
		FromClient(IP_SERVER2, START_CLIENT_SEQ + 1, SYN_COOKIE2 + 1, 'A', raw=data_client1, options=[("Timestamp", (ts_client + 2, ts_proxy)), ("NOP", ''), ("NOP", '')]),
		ToServer(PORT_PROXY_INT, IP_SERVER2, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=[("Timestamp", (ts_client + 2, ts_server)), ("NOP", ''), ("NOP", '')])
	),
	(
		FromServer(PORT_PROXY_INT, IP_SERVER2, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', window=20000, raw=data_server1, options=[("Timestamp", (ts_server + 1, ts_client + 2)), ("NOP", ''), ("NOP", '')]), 
		ToClient(IP_SERVER2, SYN_COOKIE2 + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', window=20000//16, raw=data_server1, options=[("Timestamp", (ts_proxy + 1, ts_client + 2)), ("NOP", ''), ("NOP", '')])
	),
]

WriteTest("002", data_type2)


# 003 - type 3 - proxy, no sec

data_type3 = [
	(
		FromClient(IP_SERVER3, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(PORT_PROXY_INT, IP_SERVER3, START_CLIENT_SEQ - len_pr, 0, 'S', options=options_client_syn)
	), (
		FromServer(PORT_PROXY_INT, IP_SERVER3, START_SERVER_SEQ, START_CLIENT_SEQ + 1 - len_pr, 'AS', options=options_server_syn),
		ToClient(IP_SERVER3, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn_proxy)
	), (
		FromClient(IP_SERVER3, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', options=options_client_ack), 
		ToServer(PORT_PROXY_INT, IP_SERVER3, START_CLIENT_SEQ + 1 - len_pr, START_SERVER_SEQ + 1, 'A', raw=get_proxy_header(IP_SERVER3), options=options_client_ack)
	), (
		FromClient(IP_SERVER3, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack), 
		ToServer(PORT_PROXY_INT, IP_SERVER3, START_CLIENT_SEQ + 1 - len_pr, START_SERVER_SEQ + 1, 'A', raw=get_proxy_header(IP_SERVER3) + data_client1.encode(), options=options_client_ack)
	), (
		FromServer(PORT_PROXY_INT, IP_SERVER3, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1),
		ToClient(IP_SERVER3, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	), (
		FromClient(IP_SERVER3, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', raw=data_client2),
		ToServer(PORT_PROXY_INT, IP_SERVER3, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', raw=data_client2)
	),
]

WriteTest("003", data_type3)


# 004 - type 4 - proxy, sec, sack

SYN_COOKIE3 = 0xde8bc93b

data_type4 = [
	(
		FromClient(IP_SERVER4, START_CLIENT_SEQ, 0, 'S', options=options_client_syn), 
		ToClient(IP_SERVER4, SYN_COOKIE3, START_CLIENT_SEQ + 1, 'AS', window=0, options=[("MSS", 1300-len_pr), ("SAckOK", ''), ("Timestamp", (1, ts_client)), ('WScale', 9), ("NOP", '')])
	), (
		FromClient(IP_SERVER4, START_CLIENT_SEQ + 1, SYN_COOKIE3 + 1, 'A', options=[("Timestamp", (ts_client + 1, 1))]),
		ToServer(PORT_PROXY_INT, IP_SERVER4, START_CLIENT_SEQ - len_pr, 0, 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_client + 1, 0)), ('WScale', 5), ("NOP", '')])
	), (
		FromServer(PORT_PROXY_INT, IP_SERVER4, START_SERVER_SEQ, START_CLIENT_SEQ + 1 - len_pr, 'SA', window=20000, options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (ts_server, ts_client + 1)), ('WScale', 5), ("NOP", '')]),
		ToClient(IP_SERVER4, SYN_COOKIE3 + 1, START_CLIENT_SEQ + 1, 'A', window=65535, options=[("Timestamp", (ts_proxy, ts_client + 1)), ("NOP", ''), ("NOP", '')])
	),
	(
		FromClient(IP_SERVER4, START_CLIENT_SEQ + 1, SYN_COOKIE3 + 1, 'A', raw=data_client1),
		ToServer(PORT_PROXY_INT, IP_SERVER4, START_CLIENT_SEQ + 1 - len_pr, START_SERVER_SEQ + 1, 'A', raw=get_proxy_header(IP_SERVER4) + data_client1.encode())
	),
	( # Packet#3 out of order
		FromServer(PORT_PROXY_INT, IP_SERVER4, START_SERVER_SEQ + 1 + len(data_server1)*2, START_CLIENT_SEQ + 1 + len(data_client1), 'A', window=20000, raw=data_server1), 
		ToClient(IP_SERVER4, SYN_COOKIE3 + 1 + len(data_server1)*2, START_CLIENT_SEQ + 1 + len(data_client1), 'A', window=65535, raw=data_server1)
	),
	( # Packet#1
		FromServer(PORT_PROXY_INT, IP_SERVER4, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', window=20000, raw=data_server1), 
		ToClient(IP_SERVER4, SYN_COOKIE3 + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', window=65535, raw=data_server1)
	),
	# ( # Packet#2 Lost
	# 	FromServer(IP_SERVER4, START_SERVER_SEQ + 1 + len(data_server1), START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1), 
	# 	ToClient(IP_SERVER4, SYN_COOKIE3 + 1 + len(data_server1), START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	# ),
	( # Ack Packet#1, SAck Packet#3
		FromClient(IP_SERVER4, START_CLIENT_SEQ + 1 + len(data_client1), SYN_COOKIE3 + 1 + len(data_server1), 'A', options=[("SAck", (SYN_COOKIE3 + 1 + len(data_server1)*2, SYN_COOKIE3 + 1 + len(data_server1)*3))], raw=data_client1),
		ToServer(PORT_PROXY_INT, IP_SERVER4, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', options=[("SAck", (START_SERVER_SEQ + 1 + len(data_server1)*2, START_SERVER_SEQ + 1 + len(data_server1)*3))], raw=data_client1)
	),
	( # Packet#5 out of order
		FromServer(PORT_PROXY_INT, IP_SERVER4, START_SERVER_SEQ + 1 + len(data_server1)*4, START_CLIENT_SEQ + 1 + len(data_client1), 'A', window=20000, raw=data_server1), 
		ToClient(IP_SERVER4, SYN_COOKIE3 + 1 + len(data_server1)*4, START_CLIENT_SEQ + 1 + len(data_client1), 'A', window=65535, raw=data_server1)
	),
	# ( # Packet#4 Lost
	# 	FromServer(IP_SERVER4, START_SERVER_SEQ + 1 + len(data_server1)*3, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1), 
	# 	ToClient(IP_SERVER4, SYN_COOKIE3 + 1 + len(data_server1)*3, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	# ),
	( # Duplicate Ack Packet#1, SAck Packet#5 and Packet#3
		FromClient(IP_SERVER4, START_CLIENT_SEQ + 1 + len(data_client1), SYN_COOKIE3 + 1 + len(data_server1), 'A', options=[("SAck", (SYN_COOKIE3 + 1 + len(data_server1)*4, SYN_COOKIE3 + 1 + len(data_server1)*5)), ("SAck",(SYN_COOKIE3 + 1 + len(data_server1)*2, SYN_COOKIE3 + 1 + len(data_server1)*3))], raw=data_client2),
		ToServer(PORT_PROXY_INT, IP_SERVER4, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', options=[("SAck", (START_SERVER_SEQ + 1 + len(data_server1)*4, START_SERVER_SEQ + 1 + len(data_server1)*5)), ("SAck", (START_SERVER_SEQ + 1 + len(data_server1)*2 , START_SERVER_SEQ + 1 + len(data_server1)*3))], raw=data_client2)
	),
]

WriteTest("004", data_type4)


# 005 - pings

write_pcap("005-send.pcap",
           Ether(src=MAC_CLIENT, dst=MAC_PROXY)/Dot1Q(vlan=100)/IP(src=IP_CLIENT, dst=IP_SERVER1)/ICMP(type=8, code=0, id=1, seq=0x0001)/Raw("abcdef"),
           Ether(src=MAC_CLIENT, dst=MAC_PROXY)/Dot1Q(vlan=100)/IP(src=IP_CLIENT, dst=IP_SERVER2)/ICMP(type=8, code=0, id=1, seq=0x0001)/Raw("abcd"),
           Ether(src=MAC_CLIENT, dst=MAC_PROXY)/Dot1Q(vlan=100)/IP(src=IP_CLIENT, dst=IP_SERVER3)/ICMP(type=8, code=0, id=1, seq=0x0001)/Raw("ab"),
           Ether(src=MAC_CLIENT, dst=MAC_PROXY)/Dot1Q(vlan=100)/IP(src=IP_CLIENT, dst=IP_SERVER4)/ICMP(type=8, code=0, id=1, seq=0x0001),
)

write_pcap("005-expect.pcap",
           Ether(src=MAC_PROXY, dst=MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=IP_SERVER1, dst=IP_CLIENT, ttl=64)/ICMP(type=0, code=0, id=1, seq=0x0001)/Raw("abcdef"),
           Ether(src=MAC_PROXY, dst=MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=IP_SERVER2, dst=IP_CLIENT, ttl=64)/ICMP(type=0, code=0, id=1, seq=0x0001)/Raw("abcd"),
           Ether(src=MAC_PROXY, dst=MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=IP_SERVER3, dst=IP_CLIENT, ttl=64)/ICMP(type=0, code=0, id=1, seq=0x0001)/Raw("ab"),
           Ether(src=MAC_PROXY, dst=MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=IP_SERVER4, dst=IP_CLIENT, ttl=64)/ICMP(type=0, code=0, id=1, seq=0x0001),
)
