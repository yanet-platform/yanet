#pragma once

#include <inttypes.h>

#include <vector>

#include "common/config.h"
#include "common/define.h"
#include "common/result.h"
#include "common/type.h"

namespace dataplane
{

template<typename value_t>
class dynamic_table
{
public:
	using table_t = dynamic_table<value_t>;

	class updater
	{
	public:
		updater()
		{
		}

		void update_pointer(table_t* table,
		                    const tSocketId socket_id,
		                    const uint32_t size)
		{
			this->table = table;
			this->socket_id = socket_id;
			this->size = size;
		}

		eResult update(const uint32_t width,
		               const std::vector<value_t>& values)
		{
			keys_count = 0;

			if (width == 0)
			{
				table->width_bits = 0;
				return eResult::success;
			}

			if (__builtin_popcount(width) != 1)
			{
				YANET_LOG_ERROR("wrong width: %u\n", width);
				return eResult::invalidCount;
			}

			if (values.size() > size)
			{
				YANET_LOG_ERROR("wrong size: %lu\n", values.size());
				return eResult::invalidCount;
			}

			table->width_bits = __builtin_popcount(width - 1);
			memcpy(table->values, values.data(), values.size() * sizeof(value_t));

			keys_count = values.size();

			return eResult::success;
		}

	public:
		template<typename list_T> ///< @todo: common::idp::limits::response
		void limits(list_T& list,
		            const std::string& name) const
		{
			list.emplace_back(name + ".keys",
			                  socket_id,
			                  keys_count,
			                  size);
		}

		template<typename json_t> ///< @todo: nlohmann::json
		void report(json_t& json) const
		{
			json["keys_count"] = keys_count;
			json["width"] = 1u << table->width_bits;
		}

	public:
		table_t* table;
		tSocketId socket_id;
		uint32_t size;
		unsigned int keys_count;
	};

public:
	dynamic_table() :
	        width_bits(0)
	{
	}

	static size_t calculate_sizeof(const uint32_t size)
	{
		if (!size)
		{
			YANET_LOG_ERROR("wrong size: %u\n", size);
			return 0;
		}

		return sizeof(table_t) + (size_t)size * sizeof(value_t);
	}

public:

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

public:
	uint32_t width_bits;
	value_t values[];
};

}
