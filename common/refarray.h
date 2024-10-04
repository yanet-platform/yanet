#pragma once

#include <atomic>
#include <cstdio>
#include <optional>

#include "define.h"

namespace common
{

template<typename value_T,
         uint64_t size_T>
class refarray_t
{
public:
	using id_t = uint64_t;

public:
	refarray_t() :
	        ids_unused_size(size_T) ///< @todo: fallback value?
	{
	}

	bool exist_id(const id_t& id)
	{
		return ids.find(id) != ids.end();
	}

	bool exist_value(const value_T& value)
	{
		return values.find(value) != values.end();
	}

	bool update(const value_T& value)
	{
		auto it = values.find(value);
		if (it == values.end())
		{
			return false;
		}

		auto& [refcount, id] = it->second;
		YANET_GCC_BUG_UNUSED(id);

		refcount++;

		return true;
	}

	std::optional<id_t> insert(const value_T& value)
	{
		/// @todo: exist?

		if (ids_unused.empty() && ids_unused_watermark == size_T)
		{
			YANET_LOG_WARNING("not enough ids\n");
			return std::nullopt;
		}

		id_t id = 0;
		ids_unused_size--;
		if (ids_unused.size())
		{
			id = ids_unused.back();
			ids_unused.pop_back();
		}
		else
		{
			id = ids_unused_watermark++;
		}

		values[value] = {1, id};
		ids[id] = value;

		return id;
	}

	std::optional<id_t> update_or_insert(const value_T& value)
	{
		auto it = values.find(value);
		if (it != values.end())
		{
			auto& [refcount, id] = it->second;
			refcount++;

			return id;
		}
		else
		{
			return insert(value);
		}
	}

	std::optional<value_T> remove_id(const id_t& id)
	{
		auto it = ids.find(id);
		if (it == ids.end())
		{
			YANET_LOG_WARNING("unknown id\n");
#ifdef CONFIG_YADECAP_AUTOTEST
			std::abort();
#endif // CONFIG_YADECAP_AUTOTEST
			return std::nullopt;
		}

		const auto& value = it->second;
		auto& [refcount, values_id] = values[value];
		YANET_GCC_BUG_UNUSED(values_id);

		refcount--;
		if (refcount)
		{
			return std::nullopt;
		}

		const std::optional<value_T> result = value;

		ids_unused_size++;
		ids_unused.emplace_back(id);

		values.erase(value);
		ids.erase(id);

		return result;
	}

	std::optional<id_t> remove_value(const value_T& value)
	{
		auto it = values.find(value);
		if (it == values.end())
		{
			YANET_LOG_WARNING("unknown value\n");
#ifdef CONFIG_YADECAP_AUTOTEST
			std::abort();
#endif // CONFIG_YADECAP_AUTOTEST
			return std::nullopt;
		}

		auto& [refcount, id] = it->second;

		refcount--;
		if (refcount)
		{
			return std::nullopt;
		}

		const std::optional<id_t> result = id;

		ids_unused_size++;
		ids_unused.emplace_back(id);

		ids.erase(id);
		values.erase(value);

		return result;
	}

	id_t get_id(const value_T& value)
	{
		/// @todo: exist?

		auto it = values.find(value);
		const auto& [refcount, id] = it->second;
		YANET_GCC_BUG_UNUSED(refcount);

		return id;
	}

	const value_T& get_value(const id_t& id)
	{
		/// @todo: exist?

		auto it = ids.find(id);
		return it->second;
	}

	void clear()
	{
		ids_unused.clear();
		ids_unused_size = size_T;
		ids_unused_watermark = 0;

		values.clear();
		ids.clear();
	}

	[[nodiscard]] std::tuple<uint64_t, uint64_t> stats() const
	{
		return {size_T - ids_unused_size, size_T};
	}

	auto begin() const
	{
		return ids.begin();
	}

	auto end() const
	{
		return ids.end();
	}

protected:
	std::vector<id_t> ids_unused;
	std::atomic<id_t> ids_unused_watermark{0};

	std::map<value_T,
	         std::tuple<uint64_t, ///< refcount
	                    id_t>>
	        values;

	std::map<id_t, value_T> ids;

	std::atomic<uint64_t> ids_unused_size;
};

}
