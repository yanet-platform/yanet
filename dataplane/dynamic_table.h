#pragma once

#include <inttypes.h>

#include "common/config.h"
#include "common/define.h"
#include "common/result.h"

namespace dataplane
{

template<typename value_t>
class dynamic_table
{
public:
	using table_t = dynamic_table<value_t>;

	constexpr static uint32_t keys_size_min = 8;

	struct stats_t
	{
		uint32_t keys_count;
		uint32_t keys_size;
	};

	static uint64_t calculate_sizeof(const uint32_t size)
	{
		if (!size)
		{
			YANET_LOG_ERROR("wrong size: %u\n", size);
			return 0;
		}

		return sizeof(table_t) + (size_t)size * sizeof(value_t);
	}

public:
	dynamic_table() :
	        width_bits(0)
	{
	}

	template<unsigned int burst_size = YANET_CONFIG_BURST_SIZE>
	inline void lookup(const uint32_t (&k1s)[burst_size],
	                   const uint32_t (&k2s)[burst_size],
	                   value_t (&group_ids)[burst_size],
	                   const unsigned int count) const
	{
		for (unsigned int i = 0;
		     i < count;
		     i++)
		{
			group_ids[i] = values[(k1s[i] << width_bits) + k2s[i]];
		}
	}

	inline const value_t& lookup(const uint32_t k1, const uint32_t k2) const
	{
		return values[(k1 << width_bits) + k2];
	}

	inline value_t& lookup(const uint32_t k1, const uint32_t k2)
	{
		return values[(k1 << width_bits) + k2];
	}

	eResult fill(stats_t& stats,
	             const uint32_t width,
	             const std::vector<value_t>& values)
	{
		stats.keys_count = 0;

		if (width == 0)
		{
			width_bits = 0;
			return eResult::success;
		}

		if (__builtin_popcount(width) != 1)
		{
			YANET_LOG_ERROR("wrong width: %u\n", width);
			return eResult::invalidCount;
		}

		if (values.size() > stats.keys_size)
		{
			YANET_LOG_ERROR("wrong size: %lu\n", values.size());
			return eResult::invalidCount;
		}

		width_bits = __builtin_popcount(width - 1);
		memcpy(this->values, values.data(), values.size() * sizeof(value_t));

		stats.keys_count = values.size();

		return eResult::success;
	}

protected:
	uint32_t width_bits;
	value_t values[];
};

}
