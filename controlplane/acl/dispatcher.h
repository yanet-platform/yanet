#pragma once

#include <algorithm>
#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

#include "rule.h"

namespace acl
{

// Ordinals refer to the authoritative rules, including IDs assigned after indexing.
class dispatcher_index_t
{
	using host_t = std::pair<uint128_t, size_t>;
	using interval_t = std::pair<uint128_t, uint128_t>;

	size_t rules_size;
	std::vector<size_t> fallback;
	std::vector<host_t> ipv4;
	std::vector<host_t> ipv6;

	static std::optional<uint128_t> full_mask(uint8_t family)
	{
		if (family == 4)
		{
			return uint32_t(-1);
		}
		if (family == 6)
		{
			return uint128_t(-1);
		}
		return std::nullopt;
	}

	static void merge_intervals(std::vector<interval_t>& intervals)
	{
		std::sort(intervals.begin(), intervals.end());
		size_t count = 0;
		for (const auto& interval : intervals)
		{
			if (count && interval.first <= intervals[count - 1].second)
			{
				intervals[count - 1].second = std::max(intervals[count - 1].second, interval.second);
			}
			else
			{
				intervals[count++] = interval;
			}
		}
		intervals.resize(count);
	}

	// A subset covering at least half the rules is not worth the indirection.
	bool prefer_full_scan(size_t count) const
	{
		return count >= (rules_size + 1) / 2;
	}

	bool try_collect_hosts(const std::vector<host_t>& hosts,
	                       std::vector<interval_t>& intervals,
	                       std::vector<size_t>& ordinals) const
	{
		const auto below = [](const host_t& host, uint128_t address) { return host.first < address; };
		merge_intervals(intervals);
		for (const auto& [low, high] : intervals)
		{
			auto it = std::lower_bound(hosts.begin(), hosts.end(), low, below);
			for (; it != hosts.end() && it->first <= high; ++it)
			{
				ordinals.push_back(it->second);
				if (prefer_full_scan(ordinals.size()))
				{
					return false;
				}
			}
		}
		return true;
	}

public:
	explicit dispatcher_index_t(const std::vector<rule_t>& rules) :
	        rules_size(rules.size())
	{
		for (size_t ordinal = 0; ordinal < rules.size(); ++ordinal)
		{
			const auto& filter = rules[ordinal].filter;
			if (filter && filter->dir && filter->dir->val == 0 && filter->dst && filter->dst->networks.size() == 1)
			{
				const auto& network = filter->dst->networks.front();
				if (network.mask == full_mask(network.family))
				{
					(network.family == 4 ? ipv4 : ipv6).emplace_back(network.addr & network.mask, ordinal);
					continue;
				}
			}
			fallback.push_back(ordinal);
		}
		std::sort(ipv4.begin(), ipv4.end());
		std::sort(ipv6.begin(), ipv6.end());
	}

	// nullopt means full scan; an empty vector means no candidates.
	std::optional<std::vector<size_t>> candidates(const ref_t<filter_t>& filter) const
	{
		if (!filter)
		{
			return std::nullopt;
		}
		if (filter->dst && filter->dst->networks.empty())
		{
			return std::vector<size_t>();
		}
		if (filter->dir && filter->dir->val != 0)
		{
			return prefer_full_scan(fallback.size()) ? std::nullopt : std::make_optional(fallback);
		}
		if (!filter->dst || prefer_full_scan(fallback.size()))
		{
			return std::nullopt;
		}

		std::vector<interval_t> intervals4;
		std::vector<interval_t> intervals6;
		for (const auto& network : filter->dst->networks)
		{
			const auto mask = full_mask(network.family);
			if (!mask || (network.mask & ~*mask) != 0)
			{
				return std::nullopt;
			}
			const auto low = network.addr & network.mask;
			// Gapped masks deliberately select an enclosing interval; compatibility
			// and intersection still perform the authoritative bitwise match.
			(network.family == 4 ? intervals4 : intervals6).emplace_back(low, low | (*mask ^ network.mask));
		}

		auto ordinals = fallback;
		if (!try_collect_hosts(ipv4, intervals4, ordinals) || !try_collect_hosts(ipv6, intervals6, ordinals))
		{
			return std::nullopt;
		}
		const auto hosts = ordinals.begin() + fallback.size();
		std::sort(hosts, ordinals.end());
		std::inplace_merge(ordinals.begin(), hosts, ordinals.end());
		return ordinals;
	}
};

} // namespace acl
