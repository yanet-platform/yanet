#include "icmp_translations.h"

namespace dataplane
{

bool do_icmp_translate_v6_to_v4(rte_mbuf* mbuf,
                                const dataplane::globalBase::nat64stateless_translation_t& translation)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	rte_ipv4_hdr* ipv4ExtHeader = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);

	if (ipv4ExtHeader->next_proto_id != IPPROTO_ICMP)
	{
		return false;
	}

	unsigned int payloadExtLen = rte_be_to_cpu_16(ipv4ExtHeader->total_length) - sizeof(rte_ipv4_hdr);

	if (payloadExtLen < sizeof(icmp_header_t*) + sizeof(rte_ipv6_hdr))
	{
		return false;
	}

	icmp_header_t* icmpHeader = rte_pktmbuf_mtod_offset(mbuf, icmp_header_t*, metadata->network_headerOffset + sizeof(rte_ipv4_hdr));
	uint8_t type = icmpHeader->type;
	uint8_t code = icmpHeader->code;

	if (type == ICMP6_DST_UNREACH)
	{
		type = ICMP_DEST_UNREACH;

		if (code == ICMP6_DST_UNREACH_NOROUTE || code == ICMP6_DST_UNREACH_BEYONDSCOPE ||
		    code == ICMP6_DST_UNREACH_ADDR)
		{
			code = ICMP_HOST_UNREACH;
		}
		else if (code == ICMP6_DST_UNREACH_ADMIN)
		{
			code = ICMP_HOST_ANO;
		}
		else if (code == ICMP6_DST_UNREACH_NOPORT)
		{
			code = ICMP_PORT_UNREACH;
		}
		else
		{
			return false;
		}
	}
	else if (type == ICMP6_PACKET_TOO_BIG)
	{
		type = ICMP_DEST_UNREACH;
		code = ICMP_FRAG_NEEDED;

		uint32_t mtu = rte_be_to_cpu_32(icmpHeader->data32[0]) - 20;
		icmpHeader->data32[0] = 0;
		icmpHeader->data16[1] = rte_cpu_to_be_16(mtu);
	}
	else if (type == ICMP6_TIME_EXCEEDED)
	{
		type = ICMP_TIME_EXCEEDED;
	}
	else if (type == ICMP6_PARAM_PROB)
	{

		if (code == ICMP6_PARAMPROB_HEADER)
		{
			type = ICMP_PARAMETERPROB;
			code = 0;
			uint32_t ptr = rte_be_to_cpu_32(icmpHeader->data32[0]);
			icmpHeader->data32[0] = 0;

			if (ptr == 0 || ptr == 1)
			{
				/// unchanged
			}
			else if (ptr == 4 || ptr == 5)
			{
				ptr = 2;
			}
			else if (ptr == 6)
			{
				ptr = 9;
			}
			else if (ptr == 7)
			{
				ptr = 8;
			}
			else if (ptr >= 8 && ptr < 24)
			{
				ptr = 12;
			}
			else if (ptr >= 24 && ptr < 40)
			{
				ptr = 16;
			}
			else
			{
				return false;
			}

			icmpHeader->data8[0] = ptr;
		}
		else if (code == ICMP6_PARAMPROB_NEXTHEADER)
		{
			type = ICMP_DEST_UNREACH;
			code = ICMP_PROT_UNREACH;
			icmpHeader->data32[0] = 0;
		}
	}
	else
	{
		return false;
	}

	icmpHeader->type = type;
	icmpHeader->code = code;

	rte_ipv6_hdr* ipv6PayloadHeader = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset + sizeof(rte_ipv4_hdr) + sizeof(icmp_header_t));

	/// @todo: think about it.
	if (memcmp(ipv6PayloadHeader->dst_addr, translation.ipv6Address.bytes, 16))
	{
		return false;
	}

	if (memcmp(ipv6PayloadHeader->src_addr, translation.ipv6DestinationAddress.bytes, 12))
	{
		return false;
	}

	uint32_t addressSource = *(uint32_t*)&ipv6PayloadHeader->src_addr[12];

	if (addressSource != ipv4ExtHeader->dst_addr)
	{
		return false;
	}

	uint32_t addressDestination = *(uint32_t*)&ipv6PayloadHeader->dst_addr[12];
	addressDestination = translation.ipv4Address.address;

	uint16_t checksum6 = yanet_checksum(&ipv6PayloadHeader->src_addr[0], 32);
	uint16_t payloadLength = rte_be_to_cpu_16(ipv6PayloadHeader->payload_len);

	unsigned int ipv6PayloadHeaderSize = sizeof(rte_ipv6_hdr);

	uint16_t packet_id = 0x3421; ///< @todo: nat64statelessPacketId;
	uint16_t fragment_offset = 0; ///< @todo: rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
	uint8_t nextPayloadHeader = ipv6PayloadHeader->proto;

	if (nextPayloadHeader == IPPROTO_FRAGMENT)
	{
		if (payloadExtLen < sizeof(icmp_header_t*) + sizeof(rte_ipv6_hdr) + sizeof(tIPv6ExtensionFragment*))
		{
			return false;
		}
		tIPv6ExtensionFragment* extension = (tIPv6ExtensionFragment*)(((char*)ipv6PayloadHeader) + ipv6PayloadHeaderSize);
		packet_id = static_cast<uint16_t>(extension->identification >> 16);
		fragment_offset = rte_cpu_to_be_16(rte_be_to_cpu_16(extension->offsetFlagM) >> 3);
		fragment_offset |= (extension->offsetFlagM & 0x0100) >> 3;

		nextPayloadHeader = extension->nextHeader;

		ipv6PayloadHeaderSize += 8;
	}

	if (nextPayloadHeader == IPPROTO_HOPOPTS ||
	    nextPayloadHeader == IPPROTO_ROUTING ||
	    nextPayloadHeader == IPPROTO_FRAGMENT ||
	    nextPayloadHeader == IPPROTO_NONE ||
	    nextPayloadHeader == IPPROTO_DSTOPTS ||
	    nextPayloadHeader == IPPROTO_MH)
	{
		/// @todo: ipv6 extensions

		return false;
	}

	if (nextPayloadHeader == IPPROTO_ICMPV6)
	{
		nextPayloadHeader = IPPROTO_ICMP;
	}

	rte_ipv4_hdr* ipv4PayloadHeader = (rte_ipv4_hdr*)((char*)ipv6PayloadHeader + ipv6PayloadHeaderSize - sizeof(rte_ipv4_hdr));

	ipv4PayloadHeader->version_ihl = 0x45;
	ipv4PayloadHeader->type_of_service = (rte_be_to_cpu_32(ipv6PayloadHeader->vtc_flow) >> 20) & 0xFF;
	ipv4PayloadHeader->total_length = rte_cpu_to_be_16(payloadLength + 20 - (ipv6PayloadHeaderSize - 40));
	ipv4PayloadHeader->packet_id = packet_id;
	ipv4PayloadHeader->fragment_offset = fragment_offset;
	ipv4PayloadHeader->time_to_live = ipv6PayloadHeader->hop_limits;
	ipv4PayloadHeader->next_proto_id = nextPayloadHeader;
	ipv4PayloadHeader->src_addr = addressSource;
	ipv4PayloadHeader->dst_addr = addressDestination;

	yanet_ipv4_checksum(ipv4PayloadHeader);

	uint16_t checksum4 = yanet_checksum(&ipv4PayloadHeader->src_addr, 8);

	{
		unsigned int delta = ipv6PayloadHeaderSize - sizeof(rte_ipv4_hdr);

		memcpy(rte_pktmbuf_mtod_offset(mbuf, char*, delta),
		       rte_pktmbuf_mtod(mbuf, char*),
		       metadata->network_headerOffset + sizeof(rte_ipv4_hdr) + sizeof(icmp_header_t));

		rte_pktmbuf_adj(mbuf, delta);

		icmpHeader = (icmp_header_t*)((char*)icmpHeader + delta);
		ipv4ExtHeader = (rte_ipv4_hdr*)((char*)ipv4ExtHeader + delta);

		uint16_t csum = ~ipv4ExtHeader->hdr_checksum;
		csum = csum_minus(csum, ipv4ExtHeader->total_length);
		ipv4ExtHeader->total_length = rte_cpu_to_be_16(rte_be_to_cpu_16(ipv4ExtHeader->total_length) - delta);
		csum = csum_plus(csum, ipv4ExtHeader->total_length);
		ipv4ExtHeader->hdr_checksum = (csum == 0xffff) ? csum : ~csum;
	}

	if ((fragment_offset & 0xFF1F) == 0)
	{
		if (nextPayloadHeader == IPPROTO_TCP)
		{
			/// @todo: check packet size

			rte_tcp_hdr* tcpPayloadHeader = (rte_tcp_hdr*)((char*)ipv4PayloadHeader + sizeof(rte_ipv4_hdr));
			yanet_tcp_checksum_v6_to_v4(tcpPayloadHeader, checksum6, checksum4);
		}
		else if (nextPayloadHeader == IPPROTO_UDP)
		{
			/// @todo: check packet size

			rte_udp_hdr* udpPayloadHeader = (rte_udp_hdr*)((char*)ipv4PayloadHeader + sizeof(rte_ipv4_hdr));
			yanet_udp_checksum_v6_to_v4(udpPayloadHeader, checksum6, checksum4);
		}
		else if (nextPayloadHeader == IPPROTO_ICMP)
		{
			/// @todo: check packet size

			icmp_header_t* icmpPayloadHeader = (icmp_header_t*)((char*)ipv4PayloadHeader + sizeof(rte_ipv4_hdr));

			if ((fragment_offset & 0xFF3F) != 0 ||
			    !yanet_icmp_translate_v6_to_v4(icmpPayloadHeader,
			                                   payloadLength,
			                                   checksum6))
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	icmpHeader->checksum = 0;
	uint32_t sum = __rte_raw_cksum(icmpHeader, sizeof(icmp_header_t) + sizeof(rte_ipv4_hdr) + payloadLength, 0);
	icmpHeader->checksum = ~__rte_raw_cksum_reduce(sum);

	return true;
}

bool do_icmp_translate_v4_to_v6(rte_mbuf* mbuf,
                                const dataplane::globalBase::nat64stateless_translation_t& translation)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	rte_ipv6_hdr* ipv6ExtHeader = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);

	if (ipv6ExtHeader->proto != IPPROTO_ICMPV6)
	{
		return false;
	}

	unsigned int ipv6ExtHeaderSize = sizeof(rte_ipv6_hdr);

	unsigned int payloadLen = rte_be_to_cpu_16(ipv6ExtHeader->payload_len);

	if (payloadLen < sizeof(icmp_header_t) + sizeof(rte_ipv4_hdr))
	{
		return false;
	}

	icmp_header_t* icmpHeader = rte_pktmbuf_mtod_offset(mbuf, icmp_header_t*, metadata->network_headerOffset + ipv6ExtHeaderSize);
	uint8_t type = icmpHeader->type;
	uint8_t code = icmpHeader->code;

	if (type == ICMP_DEST_UNREACH)
	{
		type = ICMP6_DST_UNREACH;

		if (code == ICMP_NET_UNREACH || code == ICMP_HOST_UNREACH ||
		    code == ICMP_SR_FAILED || code == ICMP_NET_UNKNOWN ||
		    code == ICMP_HOST_UNKNOWN || code == ICMP_HOST_ISOLATED ||
		    code == ICMP_NET_UNR_TOS || code == ICMP_HOST_UNR_TOS)
		{
			code = ICMP6_DST_UNREACH_NOROUTE;
		}
		else if (code == ICMP_PORT_UNREACH)
		{
			code = ICMP6_DST_UNREACH_NOPORT;
		}
		else if (code == ICMP_NET_ANO || code == ICMP_HOST_ANO ||
		         code == ICMP_PKT_FILTERED || code == ICMP_PREC_CUTOFF)
		{
			code = ICMP6_DST_UNREACH_ADMIN;
		}
		else if (code == ICMP_PROT_UNREACH)
		{
			type = ICMP6_PARAM_PROB;
			code = ICMP6_PARAMPROB_NEXTHEADER;

			icmpHeader->data32[0] = rte_cpu_to_be_32(6);
		}
		else if (code == ICMP_FRAG_NEEDED)
		{
			type = ICMP6_PACKET_TOO_BIG;
			code = 0;

			uint32_t mtu = rte_be_to_cpu_16(icmpHeader->data16[1]) + 20;
			if (mtu < 1280)
			{
				mtu = 1280;
			}

			icmpHeader->data32[0] = rte_cpu_to_be_32(mtu);
		}
		else
		{
			return false;
		}
	}
	else if (type == ICMP_TIME_EXCEEDED)
	{
		type = ICMP6_TIME_EXCEEDED;
	}
	else if (type == ICMP_PARAMETERPROB)
	{
		if (code != 0 && code != 2)
		{
			return false;
		}

		uint8_t ptr = icmpHeader->data8[0];

		if (ptr == 0 || ptr == 1)
		{
			/// unchanged
		}
		else if (ptr == 2 || ptr == 3)
		{
			ptr = 4;
		}
		else if (ptr == 8)
		{
			ptr = 7;
		}
		else if (ptr == 9)
		{
			ptr = 6;
		}
		else if (ptr >= 12 && ptr < 16)
		{
			ptr = 8;
		}
		else if (ptr >= 16 && ptr < 20)
		{
			ptr = 24;
		}
		else
		{
			return false;
		}

		type = ICMP6_PARAM_PROB;
		code = ICMP6_PARAMPROB_HEADER;

		icmpHeader->data32[0] = rte_cpu_to_be_32(ptr);
	}
	else
	{
		return false;
	}

	icmpHeader->type = type;
	icmpHeader->code = code;

	rte_ipv4_hdr* ipv4PayloadHeader = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset + ipv6ExtHeaderSize + sizeof(icmp_header_t));

	/// @todo: check ipv4 payload header length

	if (ipv4PayloadHeader->src_addr != translation.ipv4Address.address)
	{
		return false;
	}

	unsigned int ipv6PayloadHeaderSize = sizeof(rte_ipv6_hdr);

	if ((ipv4PayloadHeader->fragment_offset & 0xFF3F) != 0)
	{
		ipv6PayloadHeaderSize += 8;
	}

	{
		unsigned int delta = ipv6PayloadHeaderSize - sizeof(rte_ipv4_hdr);

		rte_pktmbuf_prepend(mbuf, delta);

		memcpy(rte_pktmbuf_mtod(mbuf, char*),
		       rte_pktmbuf_mtod_offset(mbuf, char*, delta),
		       metadata->network_headerOffset + ipv6ExtHeaderSize + sizeof(icmp_header_t));

		icmpHeader = (icmp_header_t*)((char*)icmpHeader - delta);
		ipv6ExtHeader = (rte_ipv6_hdr*)((char*)ipv6ExtHeader - delta);
		payloadLen += delta;
		ipv6ExtHeader->payload_len = rte_cpu_to_be_16(payloadLen);
	}

	rte_ipv6_hdr* ipv6PayloadHeader = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset + ipv6ExtHeaderSize + sizeof(icmp_header_t));

	uint32_t addressDestination = ipv4PayloadHeader->dst_addr;
	uint16_t checksum4 = yanet_checksum(&ipv4PayloadHeader->src_addr, 8);

	uint16_t fragment_offset = ipv4PayloadHeader->fragment_offset;
	uint8_t nextPayloadHeader = ipv4PayloadHeader->next_proto_id;

	if (nextPayloadHeader == IPPROTO_ICMP)
	{
		nextPayloadHeader = IPPROTO_ICMPV6;
	}

	if ((fragment_offset & 0xFF3F) != 0)
	{
		tIPv6ExtensionFragment* extension = (tIPv6ExtensionFragment*)(((char*)ipv6PayloadHeader) + sizeof(rte_ipv6_hdr));
		extension->nextHeader = nextPayloadHeader;
		extension->reserved = 0;
		extension->offsetFlagM = rte_cpu_to_be_16(rte_be_to_cpu_16(fragment_offset) << 3);
		extension->offsetFlagM |= (fragment_offset & 0x0020) << 3;

		/// @todo:  it is not original identification.
		extension->identification = ipv4PayloadHeader->packet_id;

		ipv6PayloadHeader->proto = IPPROTO_FRAGMENT;
	}
	else
	{
		ipv6PayloadHeader->proto = nextPayloadHeader;
	}

	ipv6PayloadHeader->vtc_flow = rte_cpu_to_be_32((0x6 << 28) | (ipv4PayloadHeader->type_of_service << 20));
	ipv6PayloadHeader->payload_len = rte_cpu_to_be_16(rte_be_to_cpu_16(ipv4PayloadHeader->total_length) - 20 + (ipv6PayloadHeaderSize - 40));
	ipv6PayloadHeader->hop_limits = ipv4PayloadHeader->time_to_live;
	;

	memcpy(ipv6PayloadHeader->src_addr, translation.ipv6Address.bytes, 16);

	if (memcmp(ipv6PayloadHeader->src_addr, ipv6ExtHeader->dst_addr, 16))
	{
		return false;
	}

	memcpy(&ipv6PayloadHeader->dst_addr[0], translation.ipv6DestinationAddress.bytes, 12);
	memcpy(&ipv6PayloadHeader->dst_addr[12], &addressDestination, 4);

	uint16_t checksum6 = yanet_checksum(&ipv6PayloadHeader->src_addr[0], 32);

	if ((fragment_offset & 0xFF1F) == 0)
	{
		if (nextPayloadHeader == IPPROTO_TCP)
		{
			/// @todo: check packet size

			rte_tcp_hdr* tcpPayloadHeader = (rte_tcp_hdr*)((char*)ipv6PayloadHeader + ipv6PayloadHeaderSize);
			yanet_tcp_checksum_v4_to_v6(tcpPayloadHeader, checksum4, checksum6);
		}
		else if (nextPayloadHeader == IPPROTO_UDP)
		{
			/// @todo: check packet size

			rte_udp_hdr* udpPayloadHeader = (rte_udp_hdr*)((char*)ipv6PayloadHeader + ipv6PayloadHeaderSize);
			yanet_udp_checksum_v4_to_v6(udpPayloadHeader, checksum4, checksum6);
		}
		else if (nextPayloadHeader == IPPROTO_ICMPV6)
		{
			/// @todo: check packet size

			icmp_header_t* icmpPayloadHeader = (icmp_header_t*)((char*)ipv6PayloadHeader + ipv6PayloadHeaderSize);

			if ((fragment_offset & 0xFF3F) != 0 ||
			    !yanet_icmp_translate_v4_to_v6(icmpPayloadHeader,
			                                   rte_be_to_cpu_16(ipv6PayloadHeader->payload_len),
			                                   checksum6))
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	icmpHeader->checksum = 0;
	uint32_t sum = __rte_raw_cksum(ipv6ExtHeader->src_addr, 16, 0);
	sum = __rte_raw_cksum(ipv6ExtHeader->dst_addr, 16, sum);

	uint32_t tmp = ((uint32_t)rte_cpu_to_be_16(IPPROTO_ICMPV6) << 16) + rte_cpu_to_be_16(payloadLen);
	sum = __rte_raw_cksum(&tmp, 4, sum);
	sum = __rte_raw_cksum(icmpHeader, payloadLen, sum);

	icmpHeader->checksum = ~__rte_raw_cksum_reduce(sum);

	return true;
}

} // namespace dataplane