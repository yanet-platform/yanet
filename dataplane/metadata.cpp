#include "metadata.h"

namespace dataplane
{

void calcHash(rte_mbuf* mbuf, uint8_t flags)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	metadata->hash = 0;

	if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
	{
		rte_ipv4_hdr* ipv4Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);

		metadata->hash = rte_hash_crc(&ipv4Header->next_proto_id, 1, metadata->hash);
		metadata->hash = rte_hash_crc(&ipv4Header->src_addr, 4 + 4, metadata->hash);
	}
	else if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
	{
		rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);

		metadata->hash = rte_hash_crc(&ipv6Header->proto, 1, metadata->hash);
		metadata->hash = rte_hash_crc(&ipv6Header->src_addr, 16 + 16, metadata->hash);
	}

	if (!((metadata->network_flags & YANET_NETWORK_FLAG_NOT_FIRST_FRAGMENT) || (flags & YANET_BALANCER_PURE_L3)))
	{
		if (metadata->transport_headerType == IPPROTO_ICMP)
		{
			icmp_header_t* icmpHeader = rte_pktmbuf_mtod_offset(mbuf, icmp_header_t*, metadata->transport_headerOffset);

			if (icmpHeader->type == ICMP_ECHO ||
			    icmpHeader->type == ICMP_ECHOREPLY)
			{
				metadata->hash = rte_hash_crc(&icmpHeader->identifier, 2, metadata->hash);
			}
		}
		else if (metadata->transport_headerType == IPPROTO_ICMPV6)
		{
			icmpv6_header_t* icmpHeader = rte_pktmbuf_mtod_offset(mbuf, icmpv6_header_t*, metadata->transport_headerOffset);

			if (icmpHeader->type == ICMP6_ECHO_REQUEST ||
			    icmpHeader->type == ICMP6_ECHO_REPLY)
			{
				metadata->hash = rte_hash_crc(&icmpHeader->identifier, 2, metadata->hash);
			}
		}
		else if (metadata->transport_headerType == IPPROTO_TCP)
		{
			rte_tcp_hdr* tcpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
			metadata->hash = rte_hash_crc(&tcpHeader->src_port, 2 + 2, metadata->hash);
		}
		else if (metadata->transport_headerType == IPPROTO_UDP)
		{
			rte_udp_hdr* udpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_udp_hdr*, metadata->transport_headerOffset);
			metadata->hash = rte_hash_crc(&udpHeader->src_port, 2 + 2, metadata->hash);
		}
	}
}

}
