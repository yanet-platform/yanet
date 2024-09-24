#pragma once

#include "metadata.h"
#include "type.h"

inline bool prepareL3(rte_mbuf* mbuf, dataplane::metadata* metadata)
{
	if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
	{
		const rte_ipv4_hdr* ipv4Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);

		/// @todo: check version

		if (rte_pktmbuf_pkt_len(mbuf) < (uint32_t)metadata->network_headerOffset + rte_be_to_cpu_16(ipv4Header->total_length))
		{
			metadata->network_headerType = YANET_NETWORK_TYPE_UNKNOWN;
			return false;
		}

		if ((ipv4Header->version_ihl & 0x0F) < 0x05)
		{
			metadata->network_headerType = YANET_NETWORK_TYPE_UNKNOWN;
			return false;
		}
		else
		{
			if ((ipv4Header->version_ihl & 0x0F) != 0x05)
			{
				metadata->network_flags |= YANET_NETWORK_FLAG_HAS_EXTENSION;
			}

			if ((ipv4Header->fragment_offset & 0xFF3F) != 0)
			{
				metadata->network_flags |= YANET_NETWORK_FLAG_FRAGMENT;

				if ((ipv4Header->fragment_offset & 0xFF1F) != 0)
				{
					metadata->network_flags |= YANET_NETWORK_FLAG_NOT_FIRST_FRAGMENT;
				}
			}

			metadata->transport_headerType = ipv4Header->next_proto_id;
			metadata->transport_headerOffset = metadata->network_headerOffset + 4 * (ipv4Header->version_ihl & 0x0F);
		}

		if (rte_be_to_cpu_16(ipv4Header->total_length) < 4 * (ipv4Header->version_ihl & 0x0F))
		{
			metadata->network_headerType = YANET_NETWORK_TYPE_UNKNOWN;
			return false;
		}
	}
	else if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
	{
		const rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);

		/// @todo: check version

		if (rte_pktmbuf_pkt_len(mbuf) < (uint32_t)metadata->network_headerOffset + sizeof(rte_ipv6_hdr) + rte_be_to_cpu_16(ipv6Header->payload_len))
		{
			metadata->network_headerType = YANET_NETWORK_TYPE_UNKNOWN;
			return false;
		}

		uint8_t transport_headerType = ipv6Header->proto;
		uint16_t transport_headerOffset = metadata->network_headerOffset + sizeof(rte_ipv6_hdr);

		unsigned int extension_i = 0;
		for (extension_i = 0;
		     extension_i < CONFIG_YADECAP_IPV6_EXTENSIONS_MAX + 1;
		     extension_i++)
		{
			if (transport_headerType == IPPROTO_HOPOPTS ||
			    transport_headerType == IPPROTO_ROUTING ||
			    transport_headerType == IPPROTO_DSTOPTS)
			{
				const ipv6_extension_t* extension = rte_pktmbuf_mtod_offset(mbuf, ipv6_extension_t*, transport_headerOffset);

				if (extension->extensionLength > CONFIG_YADECAP_IPV6_EXTENSION_SIZE_MAX)
				{
					metadata->network_headerType = YANET_NETWORK_TYPE_UNKNOWN;
					return false;
				}

				transport_headerType = extension->nextHeader;
				transport_headerOffset += 8 + extension->extensionLength * 8;

				metadata->network_flags |= YANET_NETWORK_FLAG_HAS_EXTENSION;
			}
			else if (transport_headerType == IPPROTO_FRAGMENT)
			{
				const ipv6_extension_fragment_t* extension = rte_pktmbuf_mtod_offset(mbuf, ipv6_extension_fragment_t*, transport_headerOffset);

				if ((extension->offsetFlagM & 0xF9FF) != 0x0000) ///< not atomic fragment
				{
					metadata->network_flags |= YANET_NETWORK_FLAG_FRAGMENT;
					metadata->network_fragmentHeaderOffset = transport_headerOffset;

					if ((extension->offsetFlagM & 0xF8FF) != 0x0000)
					{
						metadata->network_flags |= YANET_NETWORK_FLAG_NOT_FIRST_FRAGMENT;
					}
				}

				transport_headerType = extension->nextHeader;
				transport_headerOffset += 8;

				metadata->network_flags |= YANET_NETWORK_FLAG_HAS_EXTENSION;

				/** @todo: last extension?
				metadata->transport_headerType = transport_headerType;
				metadata->transport_headerOffset = transport_headerOffset;

				break;
				*/
			}
			else
			{
				metadata->transport_headerType = transport_headerType;
				metadata->transport_headerOffset = transport_headerOffset;

				break;
			}
		}
		if (extension_i == CONFIG_YADECAP_IPV6_EXTENSIONS_MAX + 1)
		{
			metadata->network_headerType = YANET_NETWORK_TYPE_UNKNOWN;
			return false;
		}

		if (rte_be_to_cpu_16(ipv6Header->payload_len) < metadata->transport_headerOffset - metadata->network_headerOffset - sizeof(rte_ipv6_hdr))
		{
			metadata->network_headerType = YANET_NETWORK_TYPE_UNKNOWN;
			return false;
		}
	}

	return true;
}
