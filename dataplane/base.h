#pragma once

#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_gre.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "common/static_vector.h"
#include "dpdk.h"
#include "neighbor.h"
#include "type.h"

namespace dataplane::base
{

class PortMapper
{
	static constexpr tPortId INVALID_PORT_ID = std::numeric_limits<tPortId>::max();
	uint16_t ports_count_ = 0;
	tPortId dpdk_ports_[std::numeric_limits<tPortId>::max() + 1]; // logical to dpdk
	tPortId logical_ports_[std::numeric_limits<tPortId>::max() + 1]; // dpdk to logical

public:
	PortMapper()
	{
		std::fill(std::begin(dpdk_ports_), std::end(dpdk_ports_), INVALID_PORT_ID);
		std::fill(std::begin(logical_ports_), std::end(logical_ports_), INVALID_PORT_ID);
	}

	PortMapper(const PortMapper& other)
	{
		*this = other;
	}

	PortMapper& operator=(const PortMapper& other)
	{
		ports_count_ = other.ports_count_;
		std::copy(std::begin(other.dpdk_ports_),
		          std::end(other.dpdk_ports_),
		          std::begin(dpdk_ports_));
		std::copy(std::begin(other.logical_ports_),
		          std::end(other.logical_ports_),
		          std::begin(logical_ports_));
		return *this;
	}

	[[nodiscard]] uint16_t size() const { return ports_count_; }

	[[nodiscard]] std::optional<tPortId> Register(tPortId dpdk_port)
	{
		if (ports_count_ < CONFIG_YADECAP_PORTS_SIZE)
		{
			if (logical_ports_[dpdk_port] == INVALID_PORT_ID)
			{
				logical_ports_[dpdk_port] = ports_count_;
				dpdk_ports_[ports_count_] = dpdk_port;
				return std::optional<tPortId>{ports_count_++};
			}
			else
			{
				YANET_LOG_ERROR("Duplicate dpdk port id provided to PortMapper");
				return {};
			}
		}
		else
		{
			YANET_LOG_ERROR("CONFIG_YADECAP_PORTS_SIZE exceeded");
			return {};
		}
	}

	[[nodiscard]] tPortId ToDpdk(tPortId logical) const { return dpdk_ports_[logical]; }
	[[nodiscard]] tPortId ToLogical(tPortId dpdk) const { return logical_ports_[dpdk]; }
	[[nodiscard]] bool ValidDpdk(tPortId dpdk) const { return logical_ports_[dpdk] != INVALID_PORT_ID; }
	[[nodiscard]] bool ValidLogical(tPortId logical) const { return logical < INVALID_PORT_ID; }
};

class permanently
{
public:
	permanently()
	{
		memset(globalBaseAtomics, 0, sizeof(globalBaseAtomics));

		memset(transportSizes, 0, sizeof(transportSizes));

		transportSizes[IPPROTO_TCP] = sizeof(rte_tcp_hdr);
		transportSizes[IPPROTO_UDP] = sizeof(rte_udp_hdr);
		transportSizes[IPPROTO_ICMP] = sizeof(icmp_header_t);
		transportSizes[IPPROTO_ICMPV6] = sizeof(icmpv6_header_t);
		transportSizes[IPPROTO_GRE] = sizeof(rte_gre_hdr);
	}

	bool add_worker_port(const tPortId port_id,
	                     tQueueId queue_id)
	{
		if (rx_points.Full())
		{
			return false;
		}
		rx_points.emplace_back(port_id, queue_id);
		return true;
	}

	dataplane::globalBase::atomic* globalBaseAtomic{};
	/// Pointers to all globalBaseAtomic for each CPU socket.
	///
	/// Used to distribute firewall states.
	dataplane::globalBase::atomic* globalBaseAtomics[YANET_CONFIG_NUMA_SIZE];

	utils::StaticVector<dpdk::Endpoint, CONFIG_YADECAP_WORKER_PORTS_SIZE> rx_points;

	PortMapper ports;
	tQueueId outQueueId;

	uint32_t SWNormalPriorityRateLimitPerWorker;
	uint8_t transportSizes[256];

	uint16_t nat64stateful_numa_mask{0xFFFFu};
	uint16_t nat64stateful_numa_reverse_mask{};
	uint16_t nat64stateful_numa_id{};
};

class generation
{
public:
	dataplane::globalBase::generation* globalBase{};
	dataplane::neighbor::hashtable const* neighbor_hashtable{};
} __rte_aligned(2 * RTE_CACHE_LINE_SIZE);

}
