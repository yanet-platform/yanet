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

//
template<typename Address, typename ObjectType>
class updater_lpm
{
	[[nodiscard]] memory_manager::unique_ptr<ObjectType> Allocate(std::size_t size)
	{
		return memory_manager_->create_unique<ObjectType>(name_.c_str(),
		                                                  socket_id_,
		                                                  ObjectType::calculate_sizeof(size));
	}

public:
	using stats_t = typename ObjectType::stats_t;
	updater_lpm(const char* name,
	            dataplane::memory_manager* memory_manager,
	            tSocketId socket_id) :
	        name_(name),
	        memory_manager_(memory_manager),
	        socket_id_(socket_id),
	        pointer_{nullptr, memory_manager_->deleter()}
	{
		stats_.extended_chunks_count = 0;
		stats_.max_used_chunk_id = 0;
		stats_.free_chunk_cache.flags = 0;
	}

	eResult init()
	{
		auto default_chunks_size = 2 * ObjectType::extended_chunks_size_min;
		pointer_ = Allocate(default_chunks_size);
		if (!pointer_)
		{
			return eResult::errorAllocatingMemory;
		}
		stats_.extended_chunks_size = default_chunks_size;
		return eResult::success;
	}

	eResult insert(const Address& ip_address,
	               const uint8_t& mask,
	               const uint32_t& value_id)
	{
		if (NeedToGrow())
		{
			eResult result = Resize(GrowSize());
			if (result != eResult::success)
			{
				return result;
			}
		}

		return pointer_->insert(stats_, ip_address, mask, value_id);
	}

	eResult remove(const Address& ip_address,
	               const uint8_t& mask)
	{
		if (NeedToGrow())
		{
			eResult result = Resize(GrowSize());
			if (result != eResult::success)
			{
				return result;
			}
		}

		eResult result = pointer_->remove(stats_, ip_address, mask);
		if (result != eResult::success)
		{
			return result;
		}

		if (NeedToShrink())
		{
			eResult result = Resize(ShrinkSize());
			if (result != eResult::success)
			{
				return result;
			}
		}

		return result;
	}

	void clear()
	{
		if (pointer_)
		{
			pointer_->clear();
			stats_.clear();
			if (NeedToShrink())
			{
				Resize(2 * ObjectType::extended_chunks_size_min);
			}
		}
	}

	void limits(common::idp::limits::response& limits) const
	{
		limits.emplace_back(name_ + ".extended_chunks",
		                    socket_id_,
		                    stats_.extended_chunks_count,
		                    stats_.extended_chunks_size);
	}

	void report(nlohmann::json& report) const
	{
		report["pointer"] = to_hex(pointer_.get());
		report["extended_chunks_count"] = stats_.extended_chunks_count;
		report["extended_chunks_size"] = stats_.extended_chunks_size;
	}

	ObjectType* pointer()
	{
		return pointer_.get();
	}

private:
	std::string name_;
	dataplane::memory_manager* memory_manager_;
	tSocketId socket_id_;
	stats_t stats_;
	dataplane::memory_manager::unique_ptr<ObjectType> pointer_;

	eResult Resize(const std::size_t size)
	{
		memory_manager::unique_ptr<ObjectType> next = Allocate(size);
		if (!next)
		{
			return eResult::errorAllocatingMemory;
		}

		stats_t next_stats;
		next_stats.extended_chunks_count = 0;
		next_stats.extended_chunks_size = size;
		next_stats.max_used_chunk_id = 0;
		next_stats.free_chunk_cache.flags = 0;

		next->copy(next_stats, stats_, *pointer_);
		stats_ = next_stats;
		std::swap(pointer_, next);
		return eResult::success;
	}

	bool NeedToGrow() const
	{
		return stats_.extended_chunks_size - stats_.extended_chunks_count < ObjectType::extended_chunks_size_min;
	}

	std::size_t GrowSize() const
	{
		return stats_.extended_chunks_size * 2;
	}

	std::size_t ShrinkSize() const
	{
		return stats_.extended_chunks_size / 2;
	}

	bool NeedToShrink() const
	{
		return ShrinkSize() > std::max(ObjectType::extended_chunks_size_min, GrowSize());
	}
};

using updater_lpm4_24bit_8bit = updater_lpm<uint32_t, lpm4_24bit_8bit_atomic>;
using updater_lpm6_8x16bit = updater_lpm<std::array<uint8_t, 16>, lpm6_8x16bit_atomic>;
//

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

template<typename key_t,
         uint32_t chunk_size,
         unsigned int valid_bit_offset = 0,
         hash_function_t<key_t> calculate_hash = calculate_hash_crc<key_t>>
class updater_hashtable_mod_id32
{
public:
	using object_type = hashtable_mod_id32_dynamic<key_t, chunk_size, valid_bit_offset, calculate_hash>;
	using pair = typename object_type::pair;

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
		// 4x is the sizing policy to reduce load factor
		stats.pairs_size = upper_power_of_two(std::max(object_type::pairs_size_min,
		                                               (uint32_t)(4ull * values.size())));

		clear();

		eResult result = eResult::success;
		for (;;)
		{
			constexpr uint64_t chunk_bytes = 256ull << 20; // 256 megabytes
			constexpr uint64_t pairs_in_chunk_raw = std::max<uint64_t>(1, chunk_bytes / sizeof(pair));
			constexpr uint32_t ppc_shift = (pairs_in_chunk_raw > 0) ? (63u - __builtin_clzll(pairs_in_chunk_raw)) : 0;

			pointer = memory_manager->create<object_type>(name.data(),
			                                              socket_id,
			                                              object_type::calculate_sizeof(stats.pairs_size),
			                                              stats.pairs_size,
			                                              ppc_shift);
			if (pointer == nullptr)
			{
				return eResult::errorAllocatingMemory;
			}

			// Allocate the array of chunk pointers.
			const uint32_t num_chunks = pointer->num_chunks();
			const uint64_t chunks_array_bytes = (uint64_t)num_chunks * sizeof(pair*);
			auto* chunks_ptr_array = reinterpret_cast<pair**>(
			        memory_manager->alloc((name + ".chunks").c_str(), socket_id, chunks_array_bytes));

			if (!chunks_ptr_array)
			{
				memory_manager->destroy(pointer);
				pointer = nullptr;
				return eResult::errorAllocatingMemory;
			}
			std::memset(chunks_ptr_array, 0, chunks_array_bytes);

			// Allocate each individual chunk.
			const uint32_t pairs_per_chunk = pointer->pairs_per_chunk();
			bool allocation_ok = true;
			for (uint32_t i = 0; i < num_chunks; ++i)
			{
				const uint64_t chunk_mem_size = (uint64_t)pairs_per_chunk * sizeof(pair);
				chunks_ptr_array[i] = reinterpret_cast<pair*>(
				        memory_manager->alloc((name + ".chunk." + std::to_string(i)).c_str(),
				                              socket_id,
				                              chunk_mem_size));

				if (chunks_ptr_array[i] == nullptr)
				{
					allocation_ok = false;
					break;
				}
				// Zero-out chunk memory to mark all slots as invalid.
				std::memset(chunks_ptr_array[i], 0, chunk_mem_size);
			}

			if (!allocation_ok)
			{
				for (uint32_t i = 0; i < num_chunks; ++i)
				{
					if (chunks_ptr_array[i])
					{
						memory_manager->destroy(chunks_ptr_array[i]);
					}
				}
				memory_manager->destroy(chunks_ptr_array);
				memory_manager->destroy(pointer);
				pointer = nullptr;
				return eResult::errorAllocatingMemory;
			}

			// Attach the fully allocated chunks to the hashtable object.
			pointer->attach_chunks(chunks_ptr_array);

			result = pointer->fill(stats, values);
			if (result == eResult::success || !retry)
			{
				break;
			}

			clear();
			// Double the size for the next attempt.
			stats.pairs_size *= 2;
		}

		return result;
	}

	void clear()
	{
		if (!pointer)
		{
			return;
		}

		pair** chunks_ptr_array = pointer->chunks();
		if (chunks_ptr_array)
		{
			const uint32_t num_chunks = pointer->num_chunks();
			for (uint32_t i = 0; i < num_chunks; ++i)
			{
				if (chunks_ptr_array[i])
				{
					memory_manager->destroy(chunks_ptr_array[i]);
				}
			}
			memory_manager->destroy(chunks_ptr_array);
		}

		memory_manager->destroy(pointer);
		pointer = nullptr;
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
		for (unsigned int i = 0; i < stats.pairs_in_chunks.size(); i++)
		{
			report["pairs_in_chunks"][i] = stats.pairs_in_chunks[i];
		}
		report["longest_chain"] = stats.longest_chain;
		report["insert_failed"] = stats.insert_failed;
		report["rewrites"] = stats.rewrites;
		if (pointer)
		{
			report["num_chunks"] = pointer->num_chunks();
			report["pairs_per_chunk"] = pointer->pairs_per_chunk();
		}
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

		/// destroy pointer if exist
		clear();

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

//

template<typename type>
class updater_array
{
public:
	using object_type = type;

	updater_array(const char* name,
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
		return create(0);
	}

	eResult create(uint64_t count)
	{
		if (!count)
		{
			count = 1;
		}

		/// destroy pointer if exist
		clear();

		pointer = memory_manager->create_static_array<object_type>(name.data(),
		                                                           count,
		                                                           socket_id);
		if (pointer == nullptr)
		{
			return eResult::errorAllocatingMemory;
		}

		this->count = count;

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
		limits.emplace_back(name,
		                    socket_id,
		                    count,
		                    count);
	}

	void report(nlohmann::json& report) const
	{
		report["pointer"] = to_hex(pointer);
	}

protected:
	std::string name;
	dataplane::memory_manager* memory_manager;
	tSocketId socket_id;
	uint64_t count;

public:
	object_type* pointer;
};

}
