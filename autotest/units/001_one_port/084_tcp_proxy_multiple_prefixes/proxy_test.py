from scapy.all import *
import ipaddress


def write_pcap(filename, *packetsList):
	if len(*packetsList) == 0:
		PcapWriter(filename).close()
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

def WriteTest(index, data):
	write_pcap(index + "-send.pcap", [pair[0] for pair in data])
	write_pcap(index + "-expect.pcap", [pair[1] for pair in data if len(pair) > 1])

def add(first, second):
	return 0 if first is None else first + second

def unpack_seq_ack(seq_ack, first, second):
    return add(seq_ack[0], first), add(seq_ack[1], second)

class ProxyTest:
    MAC_PROXY = "00:11:22:33:44:55"
    MAC_CLIENT = "00:00:00:00:00:01"
    MAC_SERVER = "00:00:00:00:00:0A"
    
    IP_PROXY_INT = "10.0.0.1"
    IP_PROXY_INT2 = "11.0.0.1"
    IP_PROXY_INT3 = "12.0.0.1"

    START_CLIENT_SEQ = 1000
    START_SERVER_SEQ = 2000
    
    PORT_SERVER = 8080
    PORT_PROXY_EXT = 80
	
    SIZE_PROXY_HEADER = 28

    def __init__(self, ip_client, ip_server, ip_proxy, start_seq_to_client, port_proxy, cport, proxy_int=IP_PROXY_INT):
        self.ip_client = ip_client
        self.ip_server = ip_server
        self.ip_proxy = ip_proxy
        self.start_seq_to_client = start_seq_to_client
        self.port_proxy = port_proxy
        self.cport = cport
        self.proxy_int = proxy_int

    def FromClient(self, seq_ack, flags, ttl=64, raw='', options=[]):
        seq, ack = unpack_seq_ack(seq_ack, self.START_CLIENT_SEQ, self.start_seq_to_client)
        dst = self.ip_proxy
        cport = self.cport
        return Ether(src=self.MAC_CLIENT, dst=self.MAC_PROXY)/Dot1Q(vlan=100)/IP(src=self.ip_client, dst=dst, ttl=ttl)/TCP(sport=cport, dport=self.PORT_PROXY_EXT, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)

    def ToClient(self, seq_ack, flags, ttl=63, raw='', options=[], window=8192):
        seq, ack = unpack_seq_ack(seq_ack, self.start_seq_to_client, self.START_CLIENT_SEQ)
        src = self.ip_proxy
        cport = self.cport
        return Ether(src=self.MAC_PROXY, dst=self.MAC_CLIENT)/Dot1Q(vlan=100)/IP(src=src, dst=self.ip_client, ttl=ttl)/TCP(sport=self.PORT_PROXY_EXT, dport=cport, flags=flags, seq=seq, ack=ack, window=window, options=options)/Raw(raw)

    def ToServer(self, seq_ack, flags, ttl=63, raw='', options=[]):
        dst = self.ip_server
        seq, ack = unpack_seq_ack(seq_ack, self.START_CLIENT_SEQ, self.START_SERVER_SEQ)
        port = self.port_proxy
        return Ether(src=self.MAC_PROXY, dst=self.MAC_SERVER)/Dot1Q(vlan=200)/IP(src=self.proxy_int, dst=dst, ttl=ttl)/TCP(sport=port, dport=self.PORT_SERVER, flags=flags, seq=seq, ack=ack, options=options)/Raw(raw)

    def FromServer(self, seq_ack, flags, ttl=64, raw='', window=8192, options=[]):
        seq, ack = unpack_seq_ack(seq_ack, self.START_SERVER_SEQ, self.START_CLIENT_SEQ)
        src = self.ip_server
        port = self.port_proxy
        return Ether(src=self.MAC_SERVER, dst=self.MAC_PROXY)/Dot1Q(vlan=200)/IP(src=src, dst=self.proxy_int, ttl=ttl)/TCP(sport=self.PORT_SERVER, dport=port, flags=flags, seq=seq, ack=ack, options=options, window=window)/Raw(raw)

    def GetProxyHeader(self):
        client_addr = self.ip_client
        proxy_addr = self.ip_proxy
        client_port = self.cport
        proxy_port = self.PORT_PROXY_EXT
        proxy_signature = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
        return proxy_signature.encode() + "\x21\x11\x00\x0c".encode() +\
            int(ipaddress.ip_address(client_addr)).to_bytes(4, 'big') +\
            int(ipaddress.ip_address(proxy_addr)).to_bytes(4, 'big') +\
            client_port.to_bytes(2, 'big') + proxy_port.to_bytes(2, 'big')

def Options(mss=0, sack_ok=False, ts=None, wscale=None):
	options = []
	if mss != 0:
		options.append(("MSS", mss))
	if sack_ok:
		options.append(("SAckOK", ''))
	if ts is not None:
		options.append(("Timestamp", ts))
	if wscale is not None:
		options.append(('WScale', wscale))
	return options
