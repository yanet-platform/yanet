#pragma once

#include <nlohmann/json.hpp>
#include <rte_malloc.h>

#include "common.h"
#include "common/idp.h"
#include "dynamic_table.h"
#include "hashtable.h"
#include "lpm.h"
#include "memory_manager.h"
#include "vrf.h"

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

	[[nodiscard]] bool NeedToGrow() const
	{
		return stats_.extended_chunks_size - stats_.extended_chunks_count < ObjectType::extended_chunks_size_min;
	}

	[[nodiscard]] std::size_t GrowSize() const
	{
		return stats_.extended_chunks_size * 2;
	}

	[[nodiscard]] std::size_t ShrinkSize() const
	{
		return stats_.extended_chunks_size / 2;
	}

	[[nodiscard]] bool NeedToShrink() const
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
	        socket_id(socket_id)
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
	object_type* pointer{};
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
	        socket_id(socket_id)
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
	object_type* pointer{};
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

template<typename Address, typename InnerLpmType>
class updater_vrf_lpm
{
public:
	using stats_t = typename InnerLpmType::stats_t;
	using UpdaterType = updater_lpm<Address, InnerLpmType>;

	updater_vrf_lpm(const char* name,
	                dataplane::memory_manager* memory_manager,
	                tSocketId socket_id) :
	        name_(name),
	        memory_manager_(memory_manager),
	        socket_id_(socket_id)
	{
	}

	eResult init()
	{
		return eResult::success;
	}

	eResult insert(tVrfId vrf,
	               const Address& ip_address,
	               const uint8_t& mask,
	               const uint32_t& value_id)
	{
		if (vrf >= YANET_RIB_VRF_MAX_NUMBER)
		{
			return eResult::invalidId;
		}
		if (updaters_[vrf] == nullptr)
		{
			std::string name = std::string(name_) + ".vrf" + std::to_string(vrf);
			updaters_[vrf] = std::make_unique<UpdaterType>(name.c_str(), memory_manager_, socket_id_);
			if (updaters_[vrf] == nullptr)
			{
				return eResult::errorAllocatingMemory;
			}
			eResult result = updaters_[vrf]->init();
			if (result != eResult::success)
			{
				return result;
			}
		}

		return updaters_[vrf]->insert(ip_address, mask, value_id);
	}

	eResult remove(tVrfId vrf,
	               const Address& ip_address,
	               const uint8_t& mask)
	{
		if (vrf >= YANET_RIB_VRF_MAX_NUMBER)
		{
			return eResult::invalidId;
		}
		else if (updaters_[vrf] == nullptr)
		{
			return eResult::success;
		}
		return updaters_[vrf]->remove(ip_address, mask);
	}

	void limits(common::idp::limits::response& limits) const
	{
		for (size_t index = 0; index < YANET_RIB_VRF_MAX_NUMBER; index++)
		{
			if (updaters_[index])
			{
				updaters_[index]->limits(limits);
			}
		}
	}

	void report(nlohmann::json& report) const
	{
		for (size_t index = 0; index < YANET_RIB_VRF_MAX_NUMBER; index++)
		{
			if (updaters_[index])
			{
				updaters_[index]->report(report);
			}
		}
	}

	void clear()
	{
		for (size_t index = 0; index < YANET_RIB_VRF_MAX_NUMBER; index++)
		{
			if (updaters_[index])
			{
				updaters_[index]->clear();
				updaters_[index] = nullptr;
			}
		}
	}

	std::array<InnerLpmType*, YANET_RIB_VRF_MAX_NUMBER> GetLpms() const
	{
		std::array<InnerLpmType*, YANET_RIB_VRF_MAX_NUMBER> result;
		for (size_t index = 0; index < YANET_RIB_VRF_MAX_NUMBER; index++)
		{
			result[index] = (updaters_[index] == nullptr ? nullptr : updaters_[index]->pointer());
		}
		return result;
	}

private:
	std::string name_;
	dataplane::memory_manager* memory_manager_;
	tSocketId socket_id_;
	std::array<std::unique_ptr<UpdaterType>, YANET_RIB_VRF_MAX_NUMBER> updaters_;
};

}
