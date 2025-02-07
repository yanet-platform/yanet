#include "icmp.h"

#include "metadata.h"

namespace yanet::icmp
{

constexpr uint8_t TTL = 128;

uint32_t create_icmp_package(TypePackage type, rte_mbuf* mbuf_target, const CreatePackagePayload& payload)
{
	if (type == TypePackage::TimeExceeded)
	{
		return create_icmp_package_time_exceeded(mbuf_target, std::get<CreateTimeExceededPackagePayload>(payload));
	}
	return 1;
};

uint32_t create_icmp_package_time_exceeded(rte_mbuf* mbuf_target, const CreateTimeExceededPackagePayload& payload)
{
	if (mbuf_target == nullptr || payload.mbuf_source == nullptr)
	{
		return 1;
	}
	auto host_config = payload.host_config;
	auto metadata = YADECAP_METADATA(mbuf_target);
	*metadata = *YADECAP_METADATA(payload.mbuf_source);

	// copy ethernet header
	rte_memcpy(rte_pktmbuf_mtod(mbuf_target, char*),
	           rte_pktmbuf_mtod(payload.mbuf_source, char*),
	           metadata->network_headerOffset);

	// copy main transport header
	if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
	{
		rte_memcpy(rte_pktmbuf_mtod_offset(mbuf_target, char*, metadata->network_headerOffset),
		           rte_pktmbuf_mtod_offset(payload.mbuf_source, char*, metadata->network_headerOffset),
		           sizeof(rte_ipv4_hdr));
	}
	else if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
	{
		rte_memcpy(rte_pktmbuf_mtod_offset(mbuf_target, char*, metadata->network_headerOffset),
		           rte_pktmbuf_mtod_offset(payload.mbuf_source, char*, metadata->network_headerOffset),
		           sizeof(rte_ipv6_hdr));
	}
	else
	{
		return 1;
	}

	// rewrite transport header
	if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
	{
		rte_ipv4_hdr* ip_header = rte_pktmbuf_mtod_offset(mbuf_target, rte_ipv4_hdr*, metadata->network_headerOffset);
		ip_header->version_ihl = 0x45;
		ip_header->fragment_offset = 0;
		ip_header->time_to_live = TTL; // set new ttl
		RTE_SWAP(ip_header->dst_addr, ip_header->src_addr);
		if (host_config.show_real_address && !host_config.ipv4_address.is_default())
		{
			ip_header->src_addr = host_config.ipv4_address.address;
		}
		ip_header->next_proto_id = IPPROTO_ICMP;
		ip_header->packet_id = rte_cpu_to_be_16(0x01);
		ip_header->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
		                                           sizeof(struct rte_icmp_hdr) +
		                                           metadata->transport_headerOffset - metadata->network_headerOffset + 8);
		ip_header->hdr_checksum = 0;
		ip_header->hdr_checksum = rte_ipv4_cksum(ip_header);

		metadata->transport_headerType = IPPROTO_ICMP;
		metadata->transport_headerOffset = metadata->network_headerOffset + sizeof(struct rte_ipv4_hdr);
	}
	else if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
	{
		rte_ipv6_hdr* ip_header = rte_pktmbuf_mtod_offset(mbuf_target, rte_ipv6_hdr*, metadata->network_headerOffset);
		ip_header->hop_limits = TTL;
		{
			if (host_config.show_real_address && !host_config.ipv6_address.empty())
			{
				rte_memcpy(ip_header->dst_addr, ip_header->src_addr, 16);
				rte_memcpy(ip_header->src_addr, host_config.ipv6_address.bytes, 16);
			}
			else
			{
				uint8_t addr[16];
				rte_memcpy(addr, ip_header->dst_addr, 16);
				rte_memcpy(ip_header->dst_addr, ip_header->src_addr, 16);
				rte_memcpy(ip_header->src_addr, addr, 16);
			}
		}
		ip_header->proto = IPPROTO_ICMPV6;
		// update payload_len according to RFC 4443 clause 3.3
		if (rte_be_to_cpu_16(ip_header->payload_len) >= 1280 - sizeof(struct rte_ipv6_hdr) * 2 - sizeof(rte_icmp_hdr))
		{
			ip_header->payload_len = rte_be_to_cpu_16(1280 - sizeof(struct rte_ipv6_hdr));
		}
		else
		{
			ip_header->payload_len = rte_be_to_cpu_16(sizeof(rte_icmp_hdr) + sizeof(struct rte_ipv6_hdr) + rte_be_to_cpu_16(ip_header->payload_len));
		}

		metadata->transport_headerType = IPPROTO_ICMPV6;
		metadata->transport_headerOffset = metadata->network_headerOffset + sizeof(struct rte_ipv6_hdr);
	}

	// fill icmp header (RFC 792/4443)
	rte_icmp_hdr* icmp_header = rte_pktmbuf_mtod_offset(mbuf_target, rte_icmp_hdr*, metadata->transport_headerOffset);
	icmp_header->icmp_code = 0; // TTL  expired in transit
	icmp_header->icmp_ident = 0;
	icmp_header->icmp_seq_nb = 0;
	icmp_header->icmp_cksum = 0;
	if (metadata->transport_headerType == IPPROTO_ICMP)
	{
		icmp_header->icmp_type = 11;

		// copy network header and next 64bits of source package (RFC 792)
		rte_ipv4_hdr* ip_header = rte_pktmbuf_mtod_offset(mbuf_target, rte_ipv4_hdr*, metadata->network_headerOffset);
		rte_memcpy(rte_pktmbuf_mtod_offset(mbuf_target, char*, metadata->transport_headerOffset + sizeof(rte_icmp_hdr)),
		           rte_pktmbuf_mtod_offset(payload.mbuf_source, char*, metadata->network_headerOffset),
		           rte_be_to_cpu_16(ip_header->total_length) - sizeof(rte_ipv4_hdr) - sizeof(rte_icmp_hdr));

		// calculate checksum of icmp package
		yanet_icmpv4_checksum((icmp_header_t*)icmp_header, rte_be_to_cpu_16(ip_header->total_length) - sizeof(rte_ipv4_hdr));

		mbuf_target->pkt_len = metadata->network_headerOffset + rte_cpu_to_be_16(ip_header->total_length);
		mbuf_target->data_len = mbuf_target->pkt_len;
	}
	else
	{
		icmp_header->icmp_type = 3;
		rte_ipv6_hdr* ip_header = rte_pktmbuf_mtod_offset(mbuf_target, rte_ipv6_hdr*, metadata->network_headerOffset);

		rte_memcpy(rte_pktmbuf_mtod_offset(mbuf_target, char*, metadata->transport_headerOffset + sizeof(rte_icmp_hdr)),
		           rte_pktmbuf_mtod_offset(payload.mbuf_source, char*, metadata->network_headerOffset),
		           rte_be_to_cpu_16(ip_header->payload_len) - sizeof(rte_icmp_hdr));

		yanet_icmpv6_checksum((icmp_header_t*)icmp_header, rte_be_to_cpu_16(ip_header->payload_len), ip_header->src_addr, ip_header->dst_addr);

		mbuf_target->pkt_len = metadata->transport_headerOffset + rte_cpu_to_be_16(ip_header->payload_len);
		mbuf_target->data_len = mbuf_target->pkt_len;
	}

	// update metadata
	metadata->network_flags = 0;
	metadata->transport_flags = 0;
	dataplane::calcHash(mbuf_target);

	return 0;
}

} // namespace yanet::icmp;
