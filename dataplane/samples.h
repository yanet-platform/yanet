#pragma once

#include <rte_mbuf.h>
#include <rte_tcp.h>

#include "metadata.h"
#include "type.h"

#include "common/type.h"

namespace samples
{

struct sample_base_t
{
	common::globalBase::eFlowType action;
	uint8_t flags : 2;
	uint32_t counter_id : 22;
	uint32_t serial;

	uint8_t is_ipv6; // 0 - ipv4, 1 - ipv6
	uint8_t proto;
	uint16_t acl_id;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t in_logicalport_id;
	uint32_t out_logicalport_id;
};

struct sample4_t : public sample_base_t
{
	ipv4_address_t src_addr;
	ipv4_address_t dst_addr;
};

struct sample6_t : public sample_base_t
{
	ipv6_address_t src_addr;
	ipv6_address_t dst_addr;
};

struct sample_t : public sample_base_t
{
	union
	{
		struct
		{
			ipv4_address_t ipv4_src_addr;
			ipv4_address_t ipv4_dst_addr;
		};
		struct
		{
			ipv6_address_t ipv6_src_addr;
			ipv6_address_t ipv6_dst_addr;
		};
	};
};

class Sampler
{
public:
	Sampler()
	{
	}

	void add(rte_mbuf** mbufs, unsigned int mbufsCount)
	{
		if (is_full())
		{
			drops += mbufsCount;
			return;
		}

		for (unsigned int mbuf_i = 0;
		     mbuf_i < mbufsCount;
		     mbuf_i++)
		{
			rte_mbuf* mbuf = mbufs[mbuf_i];
			dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

			add(mbuf, metadata->flow);
		}
	}

	void add(rte_mbuf* mbuf, const common::globalBase::tFlow& flow)
	{
		dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

		if (is_full())
		{
			drops++;
			return;
		}

		if (!wanted(mbuf))
		{
			return;
		}

		sample_base_t* sample;

		if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		{
			auto* sample4 = new_sample4();

			rte_ipv4_hdr* ipv4Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
			sample4->src_addr.address = ipv4Header->src_addr;
			sample4->dst_addr.address = ipv4Header->dst_addr;
			sample4->is_ipv6 = 0;
			sample = sample4;
		}
		else if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
		{
			auto* sample6 = new_sample6();

			rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);
			rte_memcpy(sample6->src_addr.bytes, ipv6Header->src_addr, 16);
			rte_memcpy(sample6->dst_addr.bytes, ipv6Header->dst_addr, 16);
			sample6->is_ipv6 = 1;

			sample = sample6;
		}
		else
		{
			return;
		}

		sample->action = flow.type;
		sample->flags = flow.flags;
		sample->counter_id = flow.counter_id;

		if (metadata->transport_headerType == IPPROTO_TCP)
		{
			rte_tcp_hdr* tcpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);

			sample->src_port = rte_be_to_cpu_16(tcpHeader->src_port);
			sample->dst_port = rte_be_to_cpu_16(tcpHeader->dst_port);
		}
		else if (metadata->transport_headerType == IPPROTO_UDP)
		{
			rte_udp_hdr* udpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_udp_hdr*, metadata->transport_headerOffset);

			sample->src_port = rte_be_to_cpu_16(udpHeader->src_port);
			sample->dst_port = rte_be_to_cpu_16(udpHeader->dst_port);
		}
		else
		{
			sample->src_port = 0;
			sample->dst_port = 0;
		}

		sample->proto = metadata->transport_headerType;
		sample->in_logicalport_id = metadata->in_logicalport_id;
		sample->out_logicalport_id = metadata->out_logicalport_id;
	}

	void clear()
	{
		free6 = samples6;
		free4 = samples4 + sample4_size - 1;
	}

	uint64_t get_drops() const
	{
		return drops;
	}

	template<typename F>
	void visit6(F f) const
	{
		for (auto p = samples6; p < free6 - 1; p++)
		{
			f(*p);
		}
	}

	template<typename F>
	void visit4(F f) const
	{
		for (auto p = free4 + 2; p < samples4 + sample4_size; p++)
		{
			f(*p);
		}
	}

private:
	bool wanted(rte_mbuf* mbuf) const
	{
		dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

		if (metadata->network_headerType != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) &&
		    metadata->network_headerType != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
		{
			return false;
		}

		if (metadata->transport_headerType != IPPROTO_TCP)
		{
			return false;
		}

		if (metadata->network_flags & YANET_NETWORK_FLAG_NOT_FIRST_FRAGMENT)
		{
			return false;
		}

		rte_tcp_hdr* tcpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);

		return (tcpHeader->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG)) == RTE_TCP_SYN_FLAG;
	}

	bool is_full() const
	{
		return (void*)(free6 + 1) > (void*)free4;
	}

	sample6_t* new_sample6()
	{
		return free6++;
	}

	sample4_t* new_sample4()
	{
		return free4--;
	}

	uint64_t drops = 0;

	constexpr static size_t sample4_size = YANET_CONFIG_SAMPLES_SIZE * sizeof(sample6_t) / sizeof(sample4_t);

	sample6_t* free6 = samples6;
	sample4_t* free4 = samples4 + sample4_size - 1;

	union
	{
		sample6_t samples6[YANET_CONFIG_SAMPLES_SIZE];
		sample4_t samples4[sample4_size];
	};
};

} // namespace samples
