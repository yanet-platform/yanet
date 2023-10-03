#pragma once

#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_gre.h>

#include "common/result.h"

#include "type.h"

namespace dataplane::base
{

class permanently
{
public:
	permanently() :
	        globalBaseAtomic(nullptr),
	        workerPortsCount(0),
	        ports_count(0),
	        nat64stateful_numa_mask(0xFFFFu),
	        nat64stateful_numa_reverse_mask(0),
	        nat64stateful_numa_id(0)
	{
		memset(globalBaseAtomics, 0, sizeof(globalBaseAtomics));

		memset(transportSizes, 0, sizeof(transportSizes));

		transportSizes[IPPROTO_TCP] = sizeof(rte_tcp_hdr);
		transportSizes[IPPROTO_UDP] = sizeof(rte_udp_hdr);
		transportSizes[IPPROTO_ICMP] = sizeof(icmp_header_t);
		transportSizes[IPPROTO_ICMPV6] = sizeof(icmpv6_header_t);
		transportSizes[IPPROTO_GRE] = sizeof(rte_gre_hdr);
	}

	dataplane::globalBase::atomic* globalBaseAtomic;
	/// Pointers to all globalBaseAtomic for each CPU socket.
	///
	/// Used to distribute firewall states.
	dataplane::globalBase::atomic* globalBaseAtomics[YANET_CONFIG_NUMA_SIZE];

	unsigned int workerPortsCount;
	struct
	{
		tPortId inPortId;
		tQueueId inQueueId;
	} workerPorts[CONFIG_YADECAP_WORKER_PORTS_SIZE];

	unsigned int ports_count;
	tQueueId outQueueId;

 	uint32_t SWNormalPriorityRateLimitPerWorker;
	uint8_t transportSizes[256];

	uint16_t nat64stateful_numa_mask;
	uint16_t nat64stateful_numa_reverse_mask;
	uint16_t nat64stateful_numa_id;
};

class generation
{
public:
	generation() :
	        globalBase(nullptr)
	{
	}

	dataplane::globalBase::generation* globalBase;
} __rte_aligned(2 * RTE_CACHE_LINE_SIZE);

}
