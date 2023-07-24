#pragma once

#include <inttypes.h>

#include <tuple>
#include <map>
#include <atomic>
#include <variant>

#include <rte_mbuf.h>

#include "common/result.h"
#include "common/type.h"

#include "type.h"

namespace fragmentation
{

using key_ipv4_t = std::tuple<common::globalBase::eFlowType, ///< @todo
                              uint64_t, ///< @todo
                              common::ipv4_address_t,
                              common::ipv4_address_t,
                              uint16_t>; ///< packet_id

using key_ipv6_t = std::tuple<common::globalBase::eFlowType, ///< @todo
                              uint64_t, ///< @todo
                              common::ipv6_address_t,
                              common::ipv6_address_t,
                              uint32_t>; ///< identification

using key_t = std::variant<key_ipv4_t,
                           key_ipv6_t>;

using value_t = std::tuple<std::map<uint32_t, ///< range_from
                                    std::tuple<uint32_t, ///< range_to
                                               rte_mbuf*>>,
                           uint16_t, ///< first packet time
                           uint16_t>; ///< last packet time

}

class fragmentation_t
{
public:
	fragmentation_t(cControlPlane* controlPlane, cDataPlane* dataPlane);
	~fragmentation_t();

public:
	common::fragmentation::stats_t getStats();

	void insert(rte_mbuf* mbuf);
	void handle();

protected:
	bool isTimeout(const fragmentation::value_t& value);
	bool isCollected(const fragmentation::value_t& value);
	bool isIntersect(const fragmentation::value_t& value, const uint32_t& range_from, const uint32_t& range_to);

protected:
	cControlPlane* controlPlane;
	cDataPlane* dataPlane;

	common::fragmentation::stats_t stats;

	std::map<fragmentation::key_t, fragmentation::value_t> fragments;
};
