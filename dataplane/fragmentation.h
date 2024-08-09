#pragma once

#include <cinttypes>

#include <atomic>
#include <map>
#include <tuple>
#include <variant>

#include <rte_mbuf.h>

#include "common/type.h"

#include "config_values.h"
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

class Fragmentation
{
public:
	using OnCollected = std::function<void(rte_mbuf*, const common::globalBase::tFlow&)>;
	Fragmentation(OnCollected callback);
	Fragmentation(OnCollected callback, const FragmentationConfig& cfg);
	Fragmentation(Fragmentation&& other);
	~Fragmentation();

	Fragmentation& operator=(Fragmentation&& other) = default;

public:
	common::fragmentation::stats_t getStats() const;
	OnCollected& Callback() { return callback_; }
	void Configure(const FragmentationConfig& cfg) { config_ = cfg; }

	void insert(rte_mbuf* mbuf);
	void handle();

protected:
	bool isTimeout(const value_t& value) const;
	bool isCollected(const value_t& value) const;
	bool isIntersect(const value_t& value, const uint32_t& range_from, const uint32_t& range_to) const;

protected:
	OnCollected callback_;

	FragmentationConfig config_;

	common::fragmentation::stats_t stats_;

	std::map<key_t, value_t> fragments_;
};

} // namespace fragmentation