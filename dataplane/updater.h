#pragma once

#include <mutex>
#include <nlohmann/json.hpp>
#include <rte_malloc.h>

#include "common.h"
#include "common/idp.h"
#include "dynamic_table.h"
#include "hashtable.h"
#include "lpm.h"
#include "memory_manager.h"

namespace dataplane
{

[[maybe_unused]] static uint32_t upper_power_of_two(const uint32_t value)
{
	/// @todo: use __builtin_clz

	uint32_t result = 1;
	while (result < value)
	{
		result <<= 1;
		if (!result)
		{
			return 0;
		}
	}
	return result;
}

[[maybe_unused]] static std::string to_hex(const void* pointer)
{
	char buffer[128];
	snprintf(buffer, 128, "%p", pointer);
	return buffer;
}

class updater_lpm4_24bit_8bit_id32
{
public:
	using object_type = lpm4_24bit_8bit_id32_dynamic;

	updater_lpm4_24bit_8bit_id32(const char* name,
	                             dataplane::memory_manager* memory_manager,
	                             const tSocketId socket_id) :
	        name(name),
	        memory_manager(memory_manager),
	        socket_id(socket_id),
	        pointer(nullptr)
	{
	}

	eResult init()
	{
		return update({});
	}

	eResult update(const std::vector<common::acl::tree_chunk_8bit_t>& values)
	{
		stats.extended_chunks_size = std::max((uint64_t)object_type::extended_chunks_size_min,
		                                      values.size() / 2);

		/// destroy pointer if exist
		clear();

		for (;;)
		{
			pointer = memory_manager->create<object_type>(name.data(),
			                                              socket_id,
			                                              object_type::calculate_sizeof(stats.extended_chunks_size));
			if (pointer == nullptr)
			{
				return eResult::errorAllocatingMemory;
			}

			eResult result = pointer->fill(stats, values);
			if (result != eResult::success)
			{
				/// try again
				memory_manager->destroy(pointer);
				stats.extended_chunks_size *= 2;
				continue;
			}

			break;
		}

		return eResult::success;
	}

	void clear()
	{
		if (pointer)
		{
			memory_manager->destroy(pointer);
			pointer = nullptr;
		}
	}

	void limits(common::idp::limits::response& limits) const
	{
		limits.emplace_back(name + ".extended_chunks",
		                    socket_id,
		                    stats.extended_chunks_count,
		                    stats.extended_chunks_size);
	}

	void report(nlohmann::json& report) const
	{
		report["pointer"] = to_hex(pointer);
		report["extended_chunks_count"] = stats.extended_chunks_count;
		report["extended_chunks_size"] = stats.extended_chunks_size;
	}

protected:
	std::string name;
	dataplane::memory_manager* memory_manager;
	tSocketId socket_id;

	object_type::stats_t stats;

public:
	object_type* pointer;
};

//

class updater_lpm6_16x8bit_id32
{
public:
	using object_type = lpm6_16x8bit_id32_dynamic;

	updater_lpm6_16x8bit_id32(const char* name,
	                          dataplane::memory_manager* memory_manager,
	                          const tSocketId socket_id) :
	        name(name),
	        memory_manager(memory_manager),
	        socket_id(socket_id),
	        pointer(nullptr)
	{
	}

	eResult init()
	{
		return update({});
	}

	eResult update(const std::vector<common::acl::tree_chunk_8bit_t>& values)
	{
		stats.extended_chunks_size = std::max((uint64_t)object_type::extended_chunks_size_min,
		                                      values.size());

		for (;;)
		{
			pointer = memory_manager->create<object_type>(name.data(),
			                                              socket_id,
			                                              object_type::calculate_sizeof(stats.extended_chunks_size));
			if (pointer == nullptr)
			{
				return eResult::errorAllocatingMemory;
			}

			eResult result = pointer->fill(stats, values);
			if (result != eResult::success)
			{
				/// try again
				memory_manager->destroy(pointer);
				stats.extended_chunks_size *= 2;
				continue;
			}

			break;
		}

		return eResult::success;
	}

	void clear()
	{
		if (pointer)
		{
			memory_manager->destroy(pointer);
			pointer = nullptr;
		}
	}

	void limits(common::idp::limits::response& limits) const
	{
		limits.emplace_back(name + ".extended_chunks",
		                    socket_id,
		                    stats.extended_chunks_count,
		                    stats.extended_chunks_size);
	}

	void report(nlohmann::json& report) const
	{
		report["pointer"] = to_hex(pointer);
		report["extended_chunks_count"] = stats.extended_chunks_count;
		report["extended_chunks_size"] = stats.extended_chunks_size;
	}

protected:
	std::string name;
	dataplane::memory_manager* memory_manager;
	tSocketId socket_id;

	object_type::stats_t stats;

public:
	object_type* pointer;
};

//

template<typename key_t,
         uint32_t chunk_size,
         unsigned int valid_bit_offset = 0,
         hash_function_t<key_t> calculate_hash = calculate_hash_crc<key_t>>
class updater_hashtable_mod_id32
{
public:
	using object_type = hashtable_mod_id32_dynamic<key_t, chunk_size, valid_bit_offset, calculate_hash>;

	updater_hashtable_mod_id32(const char* name,
	                           dataplane::memory_manager* memory_manager,
	                           const tSocketId socket_id) :
	        name(name),
	        memory_manager(memory_manager),
	        socket_id(socket_id),
	        pointer(nullptr)
	{
	}

	eResult init()
	{
		return update({});
	}

	eResult update(const std::vector<std::tuple<key_t, uint32_t>>& values, bool retry = true)
	{
		stats.pairs_size = upper_power_of_two(std::max(object_type::pairs_size_min,
		                                               (uint32_t)(4ull * values.size())));

		/// destroy pointer if exist
		clear();

		eResult result = eResult::success;
		for (;;)
		{
			pointer = memory_manager->create<object_type>(name.data(),
			                                              socket_id,
			                                              object_type::calculate_sizeof(stats.pairs_size),
			                                              stats.pairs_size);
			if (pointer == nullptr)
			{
				return eResult::errorAllocatingMemory;
			}

			result = pointer->fill(stats, values);
			if (result != eResult::success)
			{
				if (retry)
				{
					/// try again
					memory_manager->destroy(pointer);
					stats.pairs_size *= 2;
					continue;
				}
			}

			break;
		}

		return result;
	}

	void clear()
	{
		if (pointer)
		{
			memory_manager->destroy(pointer);
			pointer = nullptr;
		}
	}

	void limits(common::idp::limits::response& limits) const
	{
		limits.emplace_back(name + ".keys",
		                    socket_id,
		                    stats.pairs_count,
		                    stats.pairs_size);
		limits.emplace_back(name + ".longest_collision",
		                    socket_id,
		                    stats.longest_chain,
		                    chunk_size);
	}

	void report(nlohmann::json& report) const
	{
		report["pointer"] = to_hex(pointer);
		report["pairs_count"] = stats.pairs_count;
		report["pairs_size"] = stats.pairs_size;
		for (unsigned int i = 0;
		     i < stats.pairs_in_chunks.size();
		     i++)
		{
			report["pairs_in_chunks"][i] = stats.pairs_in_chunks[i];
		}
		report["longest_chain"] = stats.longest_chain;
		report["insert_failed"] = stats.insert_failed;
		report["rewrites"] = stats.rewrites;
	}

protected:
	std::string name;
	dataplane::memory_manager* memory_manager;
	tSocketId socket_id;

	typename object_type::stats_t stats;

public:
	object_type* pointer;
};

//

template<typename value_t>
class updater_dynamic_table
{
public:
	using object_type = dynamic_table<value_t>;

	updater_dynamic_table(const char* name,
	                      dataplane::memory_manager* memory_manager,
	                      const tSocketId socket_id) :
	        name(name),
	        memory_manager(memory_manager),
	        socket_id(socket_id),
	        pointer(nullptr)
	{
	}

	eResult init()
	{
		return update(0, {});
	}

	eResult update(const uint32_t width,
	               const std::vector<value_t>& values)
	{
		stats.keys_size = std::max(object_type::keys_size_min,
		                           (uint32_t)values.size());

		for (;;)
		{
			pointer = memory_manager->create<object_type>(name.data(),
			                                              socket_id,
			                                              object_type::calculate_sizeof(stats.keys_size));
			if (pointer == nullptr)
			{
				return eResult::errorAllocatingMemory;
			}

			eResult result = pointer->fill(stats, width, values);
			if (result != eResult::success)
			{
				/// try again
				memory_manager->destroy(pointer);
				stats.keys_size *= 2;
				continue;
			}

			break;
		}

		return eResult::success;
	}

	eResult update(const std::tuple<uint32_t, std::vector<value_t>>& request)
	{
		const auto& [width, values] = request;
		return update(width, values);
	}

	void clear()
	{
		if (pointer)
		{
			memory_manager->destroy(pointer);
			pointer = nullptr;
		}
	}

	void limits(common::idp::limits::response& limits) const
	{
		limits.emplace_back(name + ".keys",
		                    socket_id,
		                    stats.keys_count,
		                    stats.keys_size);
	}

	void report(nlohmann::json& report) const
	{
		report["pointer"] = to_hex(pointer);
		report["keys_count"] = stats.keys_count;
		report["keys_size"] = stats.keys_size;
	}

protected:
	std::string name;
	dataplane::memory_manager* memory_manager;
	tSocketId socket_id;

	typename object_type::stats_t stats;

public:
	object_type* pointer;
};

}
