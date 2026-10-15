#pragma once

#include <cstdint>
#include <optional>
#include <tuple>
#include <utility>

#include "common/idp.h"

namespace dataplane::balancer_gc
{
using real_connections = common::idp::balancer_real_connections::connections;
using service_connections = common::idp::balancer_service_connections::connections;

// Input real rows are ordered by their service prefix. Bound work by input rows,
// including when one service spans several chunks; the caller owns publication.
inline real_connections::const_iterator accumulate_service_counts(
        real_connections::const_iterator next_real_entry,
        real_connections::const_iterator real_entries_end,
        service_connections& service_counts,
        uint32_t real_entry_budget)
{
	while (next_real_entry != real_entries_end && real_entry_budget)
	{
		const auto& key = next_real_entry->first;
		service_connections::key_type service_key{
		        std::get<0>(key), std::get<1>(key), std::get<2>(key), std::optional<uint16_t>{std::get<3>(key)}};
		common::uint32 count;
		do
		{
			count += next_real_entry->second;
			++next_real_entry;
			--real_entry_budget;
		} while (next_real_entry != real_entries_end && real_entry_budget &&
		         std::get<0>(next_real_entry->first) == std::get<0>(key) &&
		         std::get<1>(next_real_entry->first) == std::get<1>(key) &&
		         std::get<2>(next_real_entry->first) == std::get<2>(key) &&
		         std::get<3>(next_real_entry->first) == std::get<3>(key));
		service_counts.try_emplace(service_counts.end(), std::move(service_key))->second += count;
	}
	return next_real_entry;
}
}
