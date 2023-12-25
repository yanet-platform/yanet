#pragma once

#include <atomic>

#include "refarray.h"

namespace common
{

template<uint32_t size_T,
         typename index_type_T = uint8_t,
         uint32_t fallback_size_T = 256> ///< @todo
class weight_t
{
	static_assert(size_T > 256, "invalid size_T");

public:
	weight_t() :
	        size(0),
	        current(0)
	{
		base.resize(size_T, 0);

		{
			/// fallback
			std::vector<uint32_t> weights(256, 1);
			insert(weights);
		}
	}

public:
	std::tuple<uint32_t, uint32_t, bool> insert(const std::vector<uint32_t>& weights)
	{
		/// @todo: check weights.size()

		if (values.exist_value(weights))
		{
			values.update(weights);
		}
		else
		{
			uint32_t weight_total = 0;
			for (const auto& weight : weights)
			{
				weight_total += weight;
			}
			if (size + weight_total > size_T)
			{
				YANET_LOG_WARNING("not enough weights\n");
				return {0, std::min((uint32_t)weights.size(), (uint32_t)256), true}; ///< fallback
			}

			auto id = values.insert(weights);
			if (!id)
			{
				return {0, std::min((uint32_t)weights.size(), (uint32_t)256), true}; ///< fallback
			}

			auto& [range_start, range_size] = ranges[*id];

			range_start = size;

			index_type_T item_i = 0;
			for (const auto& weight : weights)
			{
				std::fill_n(base.begin() + size, weight, item_i);

				item_i++;
				size += weight;
			}

			range_size = size - range_start;
		}

		return std::tuple_cat(ranges[values.get_id(weights)], std::make_tuple(false));
	}

	void clear()
	{
		values.clear();
		ranges.clear();
		size = 0;
		base.resize(size_T, 0);

		{
			/// fallback
			std::vector<uint32_t> weights(256, 1);
			insert(weights);
		}
	}

	/// after call data() this class switches to read only mode
	/// use clear() to reset
	const std::vector<index_type_T>& data() const
	{
		base.resize(size);
		current = size;
		return base;
	}

	const std::tuple<uint32_t, uint32_t> stats() const
	{
		return {current, size_T};
	}

protected:
	refarray_t<std::vector<uint32_t>,
	           size_T>
	        values;

	std::map<uint64_t, ///< refarray_t::id_t
	         std::tuple<uint32_t, uint32_t>>
	        ranges;

	mutable std::vector<index_type_T> base;

	uint32_t size;
	mutable std::atomic<uint32_t> current;
};

}
