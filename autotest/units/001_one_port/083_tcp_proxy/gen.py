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
PORT_PROXY_INT = 1025
PORT_PROXY_INT2 = 1026
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

def ToServer(dst, seq, ack, flags, ttl=63, raw='', options=[]):
	return Ether(src=MAC_PROXY, dst=MAC_SERVER)/Dot1Q(vlan=200)/IP(src=IP_PROXY_INT, dst=dst, ttl=ttl)/TCP(sport=PORT_PROXY_INT, dport=PORT_SERVER, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)

def FromServer(src, seq, ack, flags, ttl=64, raw='', options=[]):
	return Ether(src=MAC_SERVER, dst=MAC_PROXY)/Dot1Q(vlan=200)/IP(src=src, dst=IP_PROXY_INT, ttl=ttl)/TCP(sport=PORT_SERVER, dport=PORT_PROXY_INT, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)


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

options_client_syn = [("MSS", 1460), ("SAckOK", ''), ("Timestamp", (2983139994, 0)), ('WScale', 5), ("NOP", '')]
options_client_ack = [("Timestamp", (1, 2)), ("NOP", ''), ("NOP", '')]
options_server_syn = [("MSS", 1260), ("SAckOK", ''), ("Timestamp", (123456789, 2983139994)), ('WScale', 3), ("NOP", '')]
options_server_syn_proxy = [("MSS", 1260-len_pr), ("SAckOK", ''), ("Timestamp", (123456789, 2983139994)), ('WScale', 3), ("NOP", '')]


# 001 - type 1 - no proxy, no sec

data_type1 = [
	(
		FromClient(IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	), (
		FromServer(IP_SERVER1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn),
		ToClient(IP_SERVER1, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn)
	), (
		FromClient(IP_SERVER1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack),
		ToServer(IP_SERVER1, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack)
	), (
		FromServer(IP_SERVER1, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1),
		ToClient(IP_SERVER1, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	), (
		FromClient(IP_SERVER1, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', raw=data_client2),
		ToServer(IP_SERVER1, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', raw=data_client2)
	),
]

WriteTest("001", data_type1)

# 002 - type 2 - no proxy, sec

SYN_COOKIE2 = 0x08857553

data_type2 = [
	(
		FromClient(IP_SERVER2, START_CLIENT_SEQ, 0, 'S', options=options_client_syn), 
		ToClient(IP_SERVER2, SYN_COOKIE2, START_CLIENT_SEQ + 1, 'AS', window=0, options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (1, 2983139994)), ('WScale', 9), ("NOP", '')])
	), (
		FromClient(IP_SERVER2, START_CLIENT_SEQ + 1, SYN_COOKIE2 + 1, 'A', options=[("Timestamp", (12345, 54321))]),
		ToServer(IP_SERVER2, START_CLIENT_SEQ, 0, 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (12345, 0)), ('WScale', 5), ("NOP", '')])
	), (
		FromServer(IP_SERVER2, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'SA', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (33333, 12345)), ('WScale', 9), ("NOP", '')]),
		ToClient(IP_SERVER2, SYN_COOKIE2 + 1, START_CLIENT_SEQ + 1, 'A', options=[("Timestamp", (33333, 12345)), ('WScale', 9), ("NOP", ''), ("NOP", ''), ("NOP", '')])
	),
	(
		FromClient(IP_SERVER2, START_CLIENT_SEQ + 1, SYN_COOKIE2 + 1, 'A', raw=data_client1),
		ToServer(IP_SERVER2, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1)
	),
	(
		FromServer(IP_SERVER2, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1), 
		ToClient(IP_SERVER2, SYN_COOKIE2 + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	),
]

WriteTest("002", data_type2)

# 003 - type 3 - proxy, no sec

data_type3 = [
	(
		FromClient(IP_SERVER3, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(IP_SERVER3, START_CLIENT_SEQ - len_pr, 0, 'S', options=options_client_syn)
	), (
		FromServer(IP_SERVER3, START_SERVER_SEQ, START_CLIENT_SEQ + 1 - len_pr, 'AS', options=options_server_syn),
		ToClient(IP_SERVER3, START_SERVER_SEQ, START_CLIENT_SEQ + 1, 'AS', options=options_server_syn_proxy)
	), (
		FromClient(IP_SERVER3, START_CLIENT_SEQ + 1, START_SERVER_SEQ + 1, 'A', raw=data_client1, options=options_client_ack), 
		ToServer(IP_SERVER3, START_CLIENT_SEQ + 1 - len_pr, START_SERVER_SEQ + 1, 'A', raw=get_proxy_header(IP_SERVER3) + data_client1.encode(), options=options_client_ack)
	), (
		FromServer(IP_SERVER3, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1),
		ToClient(IP_SERVER3, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	), (
		FromClient(IP_SERVER3, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', raw=data_client2),
		ToServer(IP_SERVER3, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', raw=data_client2)
	),
]

WriteTest("003", data_type3)

# 004 - type 4 - proxy, sec, sack

SYN_COOKIE3 = 0x784fb723

data_type4 = [
	(
		FromClient(IP_SERVER4, START_CLIENT_SEQ, 0, 'S', options=options_client_syn), 
		ToClient(IP_SERVER4, SYN_COOKIE3, START_CLIENT_SEQ + 1, 'AS', window=0, options=[("MSS", 1300-len_pr), ("SAckOK", ''), ("Timestamp", (1, 2983139994)), ('WScale', 9), ("NOP", '')])
	), (
		FromClient(IP_SERVER4, START_CLIENT_SEQ + 1, SYN_COOKIE3 + 1, 'A', options=[("Timestamp", (12345, 54321))]),
		ToServer(IP_SERVER4, START_CLIENT_SEQ - len_pr, 0, 'S', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (12345, 0)), ('WScale', 5), ("NOP", '')])
	), (
		FromServer(IP_SERVER4, START_SERVER_SEQ, START_CLIENT_SEQ + 1 - len_pr, 'SA', options=[("MSS", 1300), ("SAckOK", ''), ("Timestamp", (33333, 12345)), ('WScale', 9), ("NOP", '')]),
		ToClient(IP_SERVER4, SYN_COOKIE3 + 1, START_CLIENT_SEQ + 1, 'A', options=[("Timestamp", (33333, 12345)), ('WScale', 9), ("NOP", ''), ("NOP", ''), ("NOP", '')])
	),
	(
		FromClient(IP_SERVER4, START_CLIENT_SEQ + 1, SYN_COOKIE3 + 1, 'A', raw=data_client1),
		ToServer(IP_SERVER4, START_CLIENT_SEQ + 1 - len_pr, START_SERVER_SEQ + 1, 'A', raw=get_proxy_header(IP_SERVER4) + data_client1.encode())
	),
	( # Packet#3 out of order
		FromServer(IP_SERVER4, START_SERVER_SEQ + 1 + len(data_server1)*2, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1), 
		ToClient(IP_SERVER4, SYN_COOKIE3 + 1 + len(data_server1)*2, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	),
	( # Packet#1
		FromServer(IP_SERVER4, START_SERVER_SEQ + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1), 
		ToClient(IP_SERVER4, SYN_COOKIE3 + 1, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	),
	# ( # Packet#2 Lost
	# 	FromServer(IP_SERVER4, START_SERVER_SEQ + 1 + len(data_server1), START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1), 
	# 	ToClient(IP_SERVER4, SYN_COOKIE3 + 1 + len(data_server1), START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	# ),
	( # Ack Packet#1, SAck Packet#3
		FromClient(IP_SERVER4, START_CLIENT_SEQ + 1 + len(data_client1), SYN_COOKIE3 + 1 + len(data_server1), 'A', options=[("SAck", (SYN_COOKIE3 + 1 + len(data_server1)*2, SYN_COOKIE3 + 1 + len(data_server1)*3))], raw=data_client1),
		ToServer(IP_SERVER4, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', options=[("SAck", (START_SERVER_SEQ + 1 + len(data_server1)*2, START_SERVER_SEQ + 1 + len(data_server1)*3))], raw=data_client1)
	),
	( # Packet#5 out of order
		FromServer(IP_SERVER4, START_SERVER_SEQ + 1 + len(data_server1)*4, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1), 
		ToClient(IP_SERVER4, SYN_COOKIE3 + 1 + len(data_server1)*4, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	),
	# ( # Packet#4 Lost
	# 	FromServer(IP_SERVER4, START_SERVER_SEQ + 1 + len(data_server1)*3, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1), 
	# 	ToClient(IP_SERVER4, SYN_COOKIE3 + 1 + len(data_server1)*3, START_CLIENT_SEQ + 1 + len(data_client1), 'A', raw=data_server1)
	# ),
	( # Duplicate Ack Packet#1, SAck Packet#5 and Packet#3
		FromClient(IP_SERVER4, START_CLIENT_SEQ + 1 + len(data_client1), SYN_COOKIE3 + 1 + len(data_server1), 'A', options=[("SAck", (SYN_COOKIE3 + 1 + len(data_server1)*4, SYN_COOKIE3 + 1 + len(data_server1)*5)), ("SAck",(SYN_COOKIE3 + 1 + len(data_server1)*2, SYN_COOKIE3 + 1 + len(data_server1)*3))], raw=data_client2),
		ToServer(IP_SERVER4, START_CLIENT_SEQ + 1 + len(data_client1), START_SERVER_SEQ + 1 + len(data_server1), 'A', options=[("SAck", (START_SERVER_SEQ + 1 + len(data_server1)*4, START_SERVER_SEQ + 1 + len(data_server1)*5)), ("SAck", (START_SERVER_SEQ + 1 + len(data_server1)*2 , START_SERVER_SEQ + 1 + len(data_server1)*3))], raw=data_client2)
	),
]

WriteTest("004", data_type4)


'''
---------------------------------------------------------------------------
'''



# #pr = "PROXY TCP4 10.0.0.2 10.0.0.1 12380 80\r\n"
# pr = get_proxy_header(IP_CLIENT1)
# # print(pr)
# ds = "data_from_server"
# dc = "data_from_client"
# len_dc = len(dc)
# len_ds = len(ds)
# len_pr = 28 # len(pr)

# def parse_dt(dt, shift_seq, shift_ack):
# 	(seq, ack, flags) = dt
# 	return (seq + shift_seq, 0 if flags=='S' else ack + shift_ack, flags)

# def packet_client_proxy(dt, ip, raw='', tcp_options=[]):
# 	(seq, ack, flags) = parse_dt(dt, START_CLIENT_SEQ, 2000)
# 	return Ether(dst=MAC_PROXY, src=MAC_CLIENT)/Dot1Q(vlan=100)/IP(dst=IP_PROXY_EXT, src=ip, ttl=63)/TCP(dport=80, sport=PORT_CLIENT, flags=flags, seq=seq, ack=ack, options=tcp_options)/Raw(raw)

# def packet_server_proxy(dt, port_proxy, raw='', tcp_options=[]):
# 	(seq, ack, flags) = parse_dt(dt, 3000, START_CLIENT_SEQ)
# 	return Ether(dst=MAC_PROXY, src=MAC_SERVER)/Dot1Q(vlan=200)/IP(dst=IP_PROXY_INT, src=IP_SERVER, ttl=63)/TCP(sport=PORT_SERVER, dport=port_proxy, flags=flags, seq=seq, ack=ack, options=tcp_options)/Raw(raw)

# def packet_proxy_client(dt, ip_client, ttl, window=8192, raw='', tcp_options=[]):
# 	(seq, ack, flags) = parse_dt(dt, 2000, START_CLIENT_SEQ)
# 	return Ether(dst=MAC_CLIENT, src=MAC_PROXY)/Dot1Q(vlan=100)/IP(dst=ip_client, src=IP_PROXY_EXT, ttl=ttl)/TCP(dport=PORT_CLIENT, sport=80, flags=flags, seq=seq, ack=ack, window=window, options=tcp_options)/Raw(raw)

# def packet_proxy_server(dt, port, ttl=63, raw='', tcp_options=[]):
# 	(seq, ack, flags) = parse_dt(dt, START_CLIENT_SEQ, 3000)
# 	return Ether(dst=MAC_SERVER, src=MAC_PROXY)/Dot1Q(vlan=200)/IP(dst=IP_SERVER, src=IP_PROXY_INT, ttl=ttl)/TCP(dport=PORT_SERVER, sport=port, flags=flags, seq=seq, ack=ack, options=tcp_options)/Raw(raw)

# def CC(dt1, dt2, ip_client, tcp_options=[], tcp_options_answer=[]):
# 	return (packet_client_proxy(dt1, ip_client, tcp_options=tcp_options),	packet_proxy_client(dt2, ip_client, ttl=63, window=0, tcp_options=tcp_options_answer))

# def CS(dt1, dt2, ip_client, port_proxy, raw='', raw_res='', tcp_options=[], tcp_options_forward=[], ttl=63):
# 	return (packet_client_proxy(dt1, ip_client, raw=raw, tcp_options=tcp_options),	packet_proxy_server(dt2, port_proxy, raw=raw_res, tcp_options=tcp_options_forward, ttl=ttl))

# def SC(dt1, dt2, ip_client, port_proxy, raw='', raw_res='', tcp_options=[]):
# 	return (packet_server_proxy(dt1, port_proxy, raw=raw),	packet_proxy_client(dt2, ip_client, ttl=62, raw=raw_res, tcp_options=tcp_options))

# def SS(dt1, dt2, port_proxy, raw='', raw_res='', tcp_options=[]):
# 	return (packet_server_proxy(dt1, port_proxy, raw=raw, tcp_options=tcp_options),	packet_proxy_server(dt2, port_proxy, raw=raw_res))

# tcp_options_client = options = [("MSS", 1460), ("SAckOK", ''), ("Timestamp", (2983139994, 0)), ('WScale', 5), ("NOP", '')]
# tcp_options_answer_to_client = [("MSS", 1000), ("SAckOK", ''), ("Timestamp", (1234567, 2983139994)), ('WScale', 3), ("NOP", '')]
# tcp_options_server = options = [("MSS", 1000), ("SAckOK", ''), ("Timestamp", (1234567890, 2983139994)), ("NOP", ''), ('WScale', 3)]
# tcp_options_server_to_client = options = [("Timestamp", (1234567890, 2983139994)), ("NOP", ''), ("NOP", '')]

# data = [
# 	CC((0, 0, 'S'),  (0, 1, 'SA'), IP_CLIENT1, tcp_options=tcp_options_client, tcp_options_answer=tcp_options_answer_to_client),							# 1
# 	CS((1, 1, 'A'),  (-len_pr, 0, 'S'), IP_CLIENT1, PORT_PROXY_INT, tcp_options=[("Timestamp", (1, 2))], tcp_options_forward=tcp_options_client),					# 2
# 	SS((0, 1-len_pr, 'AS'), (1-len_pr, 1, 'A'), PORT_PROXY_INT, raw_res=pr, tcp_options=tcp_options_server),		# 3
# 	SC((1, 1, 'A'), (1, 1, 'A'), IP_CLIENT1, PORT_PROXY_INT, tcp_options=tcp_options_server_to_client),							# 4 - data from server?!
# 	CS((1 + len_dc, 1, 'A'), (1 + len_dc, 1, 'A'), IP_CLIENT1, PORT_PROXY_INT, raw=dc, raw_res=dc, ttl=62),				# 5
# 	SC((1 + len_ds, 1 + len_dc, 'A'), (1 + len_ds, 1 + len_dc, 'A'), IP_CLIENT1, PORT_PROXY_INT, raw=ds, raw_res=ds),	# 6
# 	# CS((1, 1, 'A'),  (1, 1, 'A'), raw=dc, raw_res=dc),			# 4
# 	CC((0, 0, 'S'),  (0, 1, 'SA'), IP_CLIENT3, tcp_options=tcp_options_client, tcp_options_answer=tcp_options_answer_to_client), # new client
# 	CS((1, 1, 'A'),  (-len_pr, 0, 'S'), IP_CLIENT3, PORT_PROXY_INT2, tcp_options=[("Timestamp", (1, 2))], tcp_options_forward=tcp_options_client),	# 2
# 	SS((0, 1-len_pr, 'AS'), (1-len_pr, 1, 'A'), PORT_PROXY_INT2, raw_res=get_proxy_header(IP_CLIENT3), tcp_options=tcp_options_server),				# 3
# 	SC((1, 1, 'A'), (1, 1, 'A'), IP_CLIENT3, PORT_PROXY_INT2, tcp_options=tcp_options_server_to_client),							# 4
# 	CS((1 + len_dc, 1, 'A'), (1 + len_dc, 1, 'A'), IP_CLIENT3, PORT_PROXY_INT2, raw=dc, raw_res=dc, ttl=62),			# 5
# 	SC((1 + len_ds, 1 + len_dc, 'A'), (1 + len_ds, 1 + len_dc, 'A'), IP_CLIENT3, PORT_PROXY_INT2, raw=ds, raw_res=ds),	# 6
# ]




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
