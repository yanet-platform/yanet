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
data_server1 = 'client first'

options_client_syn = [("MSS", 1460), ("SAckOK", ''), ("Timestamp", (2983139994, 0)), ('WScale', 5), ("NOP", '')]
options_client_ack = [("Timestamp", (1, 2)), ("NOP", ''), ("NOP", '')]
options_server_syn = [("MSS", 1260), ("SAckOK", ''), ("Timestamp", (123456789, 2983139994)), ('WScale', 3), ("NOP", '')]

# 001 - type 1 - no proxy, no sec

data_type1 = [
	(
		FromClient(IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	), (
		FromClient(IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn),
		ToServer(IP_SERVER1, START_CLIENT_SEQ, 0, 'S', options=options_client_syn)
	),
]

WriteTest("001", data_type1)
