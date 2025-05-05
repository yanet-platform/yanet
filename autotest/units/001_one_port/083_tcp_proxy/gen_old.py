#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.contrib.mpls import MPLS

import ipaddress

MAC_PROXY = "00:11:22:33:44:55"
MAC_CLIENT = "00:00:00:00:00:01"
MAC_SERVER = "00:00:00:00:00:0A"
IP_CLIENT1 = "1.0.0.1"
IP_CLIENT2 = "3.0.0.1"
IP_CLIENT3 = "2.0.0.1"
IP_PROXY_EXT = "11.0.0.1"
IP_PROXY_INT = "10.0.1.1"
IP_SERVER = "10.0.3.1"
PORT_SERVER = 8080
PORT_PROXY_EXT = 80
PORT_PROXY_INT = 1025
PORT_PROXY_INT2 = 1026
PORT_CLIENT = 12380


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
           Ether(dst=MAC_PROXY, src=MAC_CLIENT)/Dot1Q(vlan=100)/IP(dst=IP_PROXY_EXT, src=IP_CLIENT1)/ICMP(type=8, code=0, id=1, seq=0x0001)/Raw("abcdef"),
		   Ether(dst=MAC_PROXY, src=MAC_CLIENT)/Dot1Q(vlan=100)/IP(dst=IP_PROXY_EXT, src=IP_CLIENT1)/ICMP(type=8, code=1, id=1, seq=0x0001),	# drop - not 8/0 echo request
           #Ether(dst=MAC_PROXY, src=MAC_CLIENT)/Dot1Q(vlan=100)/IP(dst=IP_PROXY_EXT, src=IP_CLIENT1)/TCP(dport=80, sport=1025, flags='S', options=[("MSS", 1460), ("SAckOK", ''), ("Timestamp", (2983139994, 0)), ("NOP", ''), ('WScale', 5)]),
		   #Ether(dst=MAC_PROXY, src=MAC_CLIENT)/Dot1Q(vlan=100)/IP(dst=IP_PROXY_EXT, src=IP_CLIENT1)/TCP(dport=80, sport=1026, flags='A'),
		   Ether(dst=MAC_PROXY, src=MAC_CLIENT)/Dot1Q(vlan=100)/IP(dst=IP_PROXY_EXT, src=IP_CLIENT2)/TCP(dport=80, sport=1027, flags='A'),		# drop - blacklist
		   Ether(dst=MAC_PROXY, src=MAC_CLIENT)/Dot1Q(vlan=100)/IP(dst=IP_PROXY_EXT, src=IP_CLIENT1)/TCP(dport=80, sport=1028, flags='SA'),		# drop - SYN+ACK from client
		   #Ether(dst=MAC_PROXY, src=MAC_CLIENT)/Dot1Q(vlan=200)/IP(dst=IP_PROXY_INT, src="10.0.3.1")/TCP(sport=8080, dport=1029, flags='SA'),
		   #Ether(dst=MAC_PROXY, src=MAC_CLIENT)/Dot1Q(vlan=200)/IP(dst=IP_PROXY_INT, src="10.0.3.3")/TCP(sport=80, dport=1030, flags='A'),
		   Ether(dst=MAC_PROXY, src=MAC_CLIENT)/Dot1Q(vlan=200)/IP(dst=IP_PROXY_INT, src=IP_SERVER)/TCP(sport=8080, dport=1031, flags='S'),	# drop - SYN from client
)

write_pcap("001-expect.pcap",
           Ether(dst=MAC_CLIENT, src=MAC_PROXY)/Dot1Q(vlan=100)/IP(dst=IP_CLIENT1, src=IP_PROXY_EXT, ttl=64)/ICMP(type=0, code=0, id=1, seq=0x0001)/Raw("abcdef"),
		   #Ether(dst=MAC_CLIENT, src=MAC_PROXY)/Dot1Q(vlan=100)/IP(dst=IP_CLIENT1, src=IP_PROXY_EXT, ttl=63)/TCP(dport=1025, sport=80, flags='AS', window=0, ack=0x0001, seq=123456),
)


'''
---------------------------------------------------------------------------
'''

START_CLIENT_SEQ = 1000

def get_proxy_header(ip_client):
	proxy_signature = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
	return proxy_signature.encode() + "\x21\x11\x00\x0c".encode() +\
		int(ipaddress.ip_address(ip_client)).to_bytes(4, 'big') +\
		int(ipaddress.ip_address(IP_PROXY_EXT)).to_bytes(4, 'big') +\
		PORT_CLIENT.to_bytes(2, 'big') + PORT_PROXY_EXT.to_bytes(2, 'big')

#pr = "PROXY TCP4 10.0.0.2 10.0.0.1 12380 80\r\n"
pr = get_proxy_header(IP_CLIENT1)
# print(pr)
ds = "data_from_server"
dc = "data_from_client"
len_dc = len(dc)
len_ds = len(ds)
len_pr = 28 # len(pr)

def parse_dt(dt, shift_seq, shift_ack):
	(seq, ack, flags) = dt
	return (seq + shift_seq, 0 if flags=='S' else ack + shift_ack, flags)

def packet_client_proxy(dt, ip, raw='', tcp_options=[]):
	(seq, ack, flags) = parse_dt(dt, START_CLIENT_SEQ, 2000)
	return Ether(dst=MAC_PROXY, src=MAC_CLIENT)/Dot1Q(vlan=100)/IP(dst=IP_PROXY_EXT, src=ip, ttl=63)/TCP(dport=80, sport=PORT_CLIENT, flags=flags, seq=seq, ack=ack, options=tcp_options)/Raw(raw)

def packet_server_proxy(dt, port_proxy, raw='', tcp_options=[]):
	(seq, ack, flags) = parse_dt(dt, 3000, START_CLIENT_SEQ)
	return Ether(dst=MAC_PROXY, src=MAC_SERVER)/Dot1Q(vlan=200)/IP(dst=IP_PROXY_INT, src=IP_SERVER, ttl=63)/TCP(sport=PORT_SERVER, dport=port_proxy, flags=flags, seq=seq, ack=ack, options=tcp_options)/Raw(raw)

def packet_proxy_client(dt, ip_client, ttl, window=8192, raw='', tcp_options=[]):
	(seq, ack, flags) = parse_dt(dt, 2000, START_CLIENT_SEQ)
	return Ether(dst=MAC_CLIENT, src=MAC_PROXY)/Dot1Q(vlan=100)/IP(dst=ip_client, src=IP_PROXY_EXT, ttl=ttl)/TCP(dport=PORT_CLIENT, sport=80, flags=flags, seq=seq, ack=ack, window=window, options=tcp_options)/Raw(raw)

def packet_proxy_server(dt, port, ttl=63, raw='', tcp_options=[]):
	(seq, ack, flags) = parse_dt(dt, START_CLIENT_SEQ, 3000)
	return Ether(dst=MAC_SERVER, src=MAC_PROXY)/Dot1Q(vlan=200)/IP(dst=IP_SERVER, src=IP_PROXY_INT, ttl=ttl)/TCP(dport=PORT_SERVER, sport=port, flags=flags, seq=seq, ack=ack, options=tcp_options)/Raw(raw)

def CC(dt1, dt2, ip_client, tcp_options=[], tcp_options_answer=[]):
	return (packet_client_proxy(dt1, ip_client, tcp_options=tcp_options),	packet_proxy_client(dt2, ip_client, ttl=63, window=0, tcp_options=tcp_options_answer))

def CS(dt1, dt2, ip_client, port_proxy, raw='', raw_res='', tcp_options=[], tcp_options_forward=[], ttl=63):
	return (packet_client_proxy(dt1, ip_client, raw=raw, tcp_options=tcp_options),	packet_proxy_server(dt2, port_proxy, raw=raw_res, tcp_options=tcp_options_forward, ttl=ttl))

def SC(dt1, dt2, ip_client, port_proxy, raw='', raw_res='', tcp_options=[]):
	return (packet_server_proxy(dt1, port_proxy, raw=raw),	packet_proxy_client(dt2, ip_client, ttl=62, raw=raw_res, tcp_options=tcp_options))

def SS(dt1, dt2, port_proxy, raw='', raw_res='', tcp_options=[]):
	return (packet_server_proxy(dt1, port_proxy, raw=raw, tcp_options=tcp_options),	packet_proxy_server(dt2, port_proxy, raw=raw_res))

tcp_options_client = options = [("MSS", 1460), ("SAckOK", ''), ("Timestamp", (2983139994, 0)), ('WScale', 5), ("NOP", '')]
tcp_options_answer_to_client = [("MSS", 1000), ("SAckOK", ''), ("Timestamp", (1234567, 2983139994)), ('WScale', 3), ("NOP", '')]
tcp_options_server = options = [("MSS", 1000), ("SAckOK", ''), ("Timestamp", (1234567890, 2983139994)), ("NOP", ''), ('WScale', 3)]
tcp_options_server_to_client = options = [("Timestamp", (1234567890, 2983139994)), ("NOP", ''), ("NOP", '')]

data = [
	CC((0, 0, 'S'),  (0, 1, 'SA'), IP_CLIENT1, tcp_options=tcp_options_client, tcp_options_answer=tcp_options_answer_to_client),							# 1
	CS((1, 1, 'A'),  (-len_pr, 0, 'S'), IP_CLIENT1, PORT_PROXY_INT, tcp_options=[("Timestamp", (1, 2))], tcp_options_forward=tcp_options_client),					# 2
	SS((0, 1-len_pr, 'AS'), (1-len_pr, 1, 'A'), PORT_PROXY_INT, raw_res=pr, tcp_options=tcp_options_server),		# 3
	SC((1, 1, 'A'), (1, 1, 'A'), IP_CLIENT1, PORT_PROXY_INT, tcp_options=tcp_options_server_to_client),							# 4 - data from server?!
	CS((1 + len_dc, 1, 'A'), (1 + len_dc, 1, 'A'), IP_CLIENT1, PORT_PROXY_INT, raw=dc, raw_res=dc, ttl=62),				# 5
	SC((1 + len_ds, 1 + len_dc, 'A'), (1 + len_ds, 1 + len_dc, 'A'), IP_CLIENT1, PORT_PROXY_INT, raw=ds, raw_res=ds),	# 6
	# CS((1, 1, 'A'),  (1, 1, 'A'), raw=dc, raw_res=dc),			# 4
	CC((0, 0, 'S'),  (0, 1, 'SA'), IP_CLIENT3, tcp_options=tcp_options_client, tcp_options_answer=tcp_options_answer_to_client), # new client
	CS((1, 1, 'A'),  (-len_pr, 0, 'S'), IP_CLIENT3, PORT_PROXY_INT2, tcp_options=[("Timestamp", (1, 2))], tcp_options_forward=tcp_options_client),	# 2
	SS((0, 1-len_pr, 'AS'), (1-len_pr, 1, 'A'), PORT_PROXY_INT2, raw_res=get_proxy_header(IP_CLIENT3), tcp_options=tcp_options_server),				# 3
	SC((1, 1, 'A'), (1, 1, 'A'), IP_CLIENT3, PORT_PROXY_INT2, tcp_options=tcp_options_server_to_client),							# 4
	CS((1 + len_dc, 1, 'A'), (1 + len_dc, 1, 'A'), IP_CLIENT3, PORT_PROXY_INT2, raw=dc, raw_res=dc, ttl=62),			# 5
	SC((1 + len_ds, 1 + len_dc, 'A'), (1 + len_ds, 1 + len_dc, 'A'), IP_CLIENT3, PORT_PROXY_INT2, raw=ds, raw_res=ds),	# 6
]

write_pcap("002-send.pcap", [pair[0] for pair in data])
write_pcap("002-expect.pcap", [pair[1] for pair in data])
