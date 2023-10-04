#pragma once

#include <functional>

#include "acl/bitset.h"
#include "acl_base.h"

#include "common/acl.h"

namespace acl::compiler
{

template<unsigned int dimension>
class table_t
{
public:
	static_assert(dimension > 0);

	table_t()
	{
		clear();
	}

public:
	void clear()
	{
		values.clear();
		sizes.fill(0);
	}

	template<typename... sizes_t>
	void prepare(const sizes_t&... sizes)
	{
		this->sizes = {sizes...};

		size_t total_size = 1;
		for (const auto& size : this->sizes)
		{
			total_size *= size;
		}

		if (total_size)
		{
			YANET_LOG_DEBUG("acl::compile: allocating %lu bytes\n", total_size * sizeof(tAclGroupId));
		}

		values.resize(total_size, 0);
	}

	inline size_t get_index(unsigned int dimension_i,
	                        unsigned int id)
	{
		size_t result = id;
		for (unsigned int i = dimension_i + 1;
		     i < dimension;
		     i++)
		{
			result *= sizes[i];
		}
		return result;
	}

	inline tAclGroupId& get_value(const std::array<size_t, dimension>& indexes)
	{
		size_t total_index = 0;
		for (const auto index : indexes)
		{
			total_index += index;
		}
		return values[total_index];
	}

	template<typename callback_t>
	void for_each(const callback_t& callback) const
	{
		std::array<unsigned int, dimension> keys;

		for (size_t index = 0;
		     index < values.size();
		     index++)
		{
			if (values[index])
			{
				fill_keys<dimension - 1>(keys, index);
				callback(keys, values[index]);
			}
		}
	}

protected:
	/*
	 * keys[0] = (index / (sizes[1] * sizes[2] * sizes[3] * sizes[4] * sizes[5]));
	 * keys[1] = (index / (sizes[2] * sizes[3] * sizes[4] * sizes[5])) % sizes[1];
	 * keys[2] = (index / (sizes[3] * sizes[4] * sizes[5])) % sizes[2];
	 * keys[3] = (index / (sizes[4] * sizes[5])) % sizes[3];
	 * keys[4] = (index / sizes[5]) % sizes[4];
	 * keys[5] = index % sizes[5];
	 */
	template<unsigned int i>
	inline void fill_keys(std::array<unsigned int, dimension>& keys,
	                      const size_t index,
	                      const size_t divider = 1) const
	{
		if constexpr (i == 0)
		{
			keys[i] = index / divider;
		}
		else
		{
			keys[i] = (index / divider) % sizes[i];
			fill_keys<i - 1>(keys, index, divider * sizes[i]);
		}
	}

public:
	std::vector<tAclGroupId> values;
	std::array<size_t, dimension> sizes;
};

}
