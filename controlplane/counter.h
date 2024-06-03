#pragma once

#include <mutex>
#include <set>

#include "segment_allocator.h"
#include "type.h"

#include "common/icp.h"
#include "common/idataplane.h"
#include "common/refarray.h"

class counter_manager_t
{
public:
	static_assert((uint32_t)common::globalBase::static_counter_type::size <= YANET_CONFIG_COUNTERS_SIZE);

	counter_manager_t() :
	        counter_shifts(YANET_CONFIG_COUNTERS_SIZE, 0)
	{
	}

	std::tuple<uint64_t, uint64_t> stats() const
	{
		std::lock_guard<std::mutex> guard(counter_mutex);
		return {YANET_CONFIG_COUNTERS_SIZE - allocator.Size(), YANET_CONFIG_COUNTERS_SIZE};
	}

	common::icp::counters_stat::response full_stat() const
	{
		std::lock_guard<std::mutex> guard(counter_mutex);

		const auto* blocks_stat = allocator.GetBlocksStat();
		std::vector<common::icp::counters_stat::one_size_info> sizes_info;
		for (uint16_t size = 1; size <= max_buffer_size; size++)
		{
			const auto& block = blocks_stat[size];
			if ((block.used_blocks != 0) || (block.busy_blocks != 0) || (block.used_segments != 0))
			{
				sizes_info.emplace_back(size, block.used_blocks, block.busy_blocks, block.used_segments);
			}
		}

		auto [errors_external, errors_internal] = allocator.GetErrors();
		common::icp::counters_stat::common_info common_info(blocks_stat[0].used_blocks, ///< free_blocks
		                                                    allocator.Size(), ///< free_cells_
		                                                    errors_external, ///< errors_external_
		                                                    errors_internal); ///< errors_internal_

		return {common_info, sizes_info};
	}

protected:
	template<typename key_T,
	         size_t size_T>
	friend class counter_t;

	tCounterId counter_reserve(size_t size)
	{
		std::lock_guard<std::mutex> guard(counter_mutex);
		return allocator.Allocate(size);
	}

	void counter_allocate(const std::vector<tCounterId>& counter_ids)
	{
		/// @todo: check counter_ids are reserved

		const auto getCountersResponse = counter_dataplane.getCounters(counter_ids);

		std::lock_guard<std::mutex> guard(counter_mutex);
		for (unsigned int i = 0;
		     i < counter_ids.size();
		     i++)
		{
			const auto& counter_id = counter_ids[i];

			counter_shifts[counter_id] = getCountersResponse[i];
		}
	}

	std::vector<uint64_t> counter_get(const std::vector<tCounterId>& counter_ids)
	{
		std::vector<uint64_t> result(counter_ids.size());

		const auto getCountersResponse = counter_dataplane.getCounters(counter_ids);

		std::lock_guard<std::mutex> guard(counter_mutex);
		for (unsigned int i = 0;
		     i < counter_ids.size();
		     i++)
		{
			const auto& counter_id = counter_ids[i];

			result[i] = getCountersResponse[i] - counter_shifts[counter_id];
		}

		return result;
	}

	void counter_release(tCounterId counter_id, size_t size)
	{
		std::lock_guard<std::mutex> guard(counter_mutex);
		allocator.Free(counter_id, size);
	}

protected:
	static constexpr uint32_t counter_index_begin = (((uint32_t)common::globalBase::static_counter_type::size + 63) / 64) * 64;
	static constexpr uint32_t max_buffer_size = 64;

	mutable std::mutex counter_mutex;
	interface::dataPlane counter_dataplane;
	std::vector<uint64_t> counter_shifts;
	SegmentAllocator<counter_index_begin, YANET_CONFIG_COUNTERS_SIZE, 64 * 64, max_buffer_size, 0> allocator;
};

template<typename key_T,
         size_t size_T>
class counter_t
{
public:
	static_assert(size_T <= YANET_CONFIG_COUNTER_FALLBACK_SIZE);

	counter_t() :
	        manager(nullptr)
	{
	}

	void init(counter_manager_t* manager)
	{
		this->manager = manager;
	}

	template<typename callback_T>
	void allocate(const callback_T& callback)
	{
		std::lock_guard<std::mutex> guard(mutex);

		std::vector<tCounterId> counter_ids;
		counter_ids.reserve(counters_inserted.size() * size_T);
		for (const auto& [key, counter_id] : counters_inserted)
		{
			for (size_t index = 0; index < size_T; index++)
			{
				counter_ids.push_back(counter_id + index);
			}

			counters_allocated.emplace(key, counter_id);
			callback(key);
		}
		counters_inserted.clear();

		manager->counter_allocate(counter_ids);
	}

	void allocate()
	{
		allocate([](const key_T& key) { (void)key; });
	}

	template<typename callback_T>
	void release(const callback_T& callback)
	{
		std::lock_guard<std::mutex> guard(mutex);

		for (const auto& [key, counter_id] : counters_gc_removed)
		{
			callback(key);
			counters.erase(key);
			counters_allocated.erase(key);
			manager->counter_release(counter_id, size_T);
		}
		counters_gc_removed.clear();
	}

	void release()
	{
		release([](const key_T& key) { (void)key; });
	}

	void insert(const key_T& key)
	{
		std::lock_guard<std::mutex> guard(mutex);

		auto counters_it = counters.find(key);
		if (counters_it != counters.end())
		{
			auto& [counter_id, refcount] = counters_it->second;
			(void)counter_id;

			if (!refcount)
			{
				counters_removed.erase(key);
				counters_gc_removed.erase(key);
			}

			refcount++;
		}
		else
		{
			const auto counter_id = manager->counter_reserve(size_T);

			counters.emplace_hint(counters_it,
			                      key,
			                      std::tuple<tCounterId, uint32_t>(counter_id, 1));
			counters_inserted.emplace(key, counter_id);
		}
	}

	void remove(const key_T& key,
	            const uint32_t timeout = 0)
	{
		std::lock_guard<std::mutex> guard(mutex);

		auto counters_it = counters.find(key);
		if (counters_it != counters.end())
		{
			auto& [counter_id, refcount] = counters_it->second;

			if (!refcount)
			{
				/// @todo: delete
				YANET_LOG_WARNING("wrong refcount\n");
			}

			refcount--;

			if (!refcount)
			{
				auto counters_inserted_it = counters_inserted.find(key);
				if (counters_inserted_it != counters_inserted.end())
				{
					manager->counter_release(counters_inserted_it->second, size_T);

					if (counters_allocated.count(key))
					{
						YANET_LOG_WARNING("was allocated\n");
					}

					counters_inserted.erase(counters_inserted_it);
					counters.erase(counters_it);
				}
				else
				{
					uint32_t timestamp = time(nullptr);
					timestamp += timeout;

					counters_removed.emplace(key, std::tuple<tCounterId, uint32_t>(counter_id, timestamp));
				}
			}
		}
		else
		{
			/// @todo: delete
			YANET_LOG_WARNING("unknown counter\n");
		}
	}

	tCounterId get_id(const key_T& key)
	{
		std::lock_guard<std::mutex> guard(mutex);

		auto iter = counters.find(key);
		if (iter == counters.end())
		{
			/// fallback
			return 0;
		}

		const auto& [counter_id, refcount] = iter->second;
		(void)refcount;

		return counter_id;
	}

	std::map<key_T, std::array<uint64_t, size_T>> get_counters() const ///< get_values
	{
		std::lock_guard<std::mutex> guard(mutex);

		/// @todo: opt
		std::vector<tCounterId> manager_counter_ids;
		for (const auto& [key, counter_id] : counters_allocated)
		{
			(void)key;

			for (size_t index = 0; index < size_T; index++)
			{
				manager_counter_ids.emplace_back(counter_id + index);
			}
		}

		auto manager_counters = manager->counter_get(manager_counter_ids);

		std::map<key_T, std::array<uint64_t, size_T>> result;

		size_t i = 0;
		for (const auto& [key, counter_id] : counters_allocated)
		{
			(void)counter_id;

			std::array<uint64_t, size_T> array;
			for (size_t array_i = 0;
			     array_i < size_T;
			     array_i++)
			{
				array[array_i] = manager_counters[i * size_T + array_i];
			}

			result[key] = array;
			i++;
		}

		return result;
	}

	size_t size() const
	{
		std::lock_guard<std::mutex> guard(mutex);
		return counters_allocated.size();
	}

	void gc()
	{
		std::lock_guard<std::mutex> guard(mutex);

		if (counters_removed.size())
		{
			uint32_t current_time = time(nullptr);

			for (auto counters_removed_it = counters_removed.begin();
			     counters_removed_it != counters_removed.end();)
			{
				const auto& [key, ids_timestamp] = *counters_removed_it;
				const auto& [counter_id, timestamp] = ids_timestamp;

				if (current_time >= timestamp)
				{
					counters_gc_removed.emplace(key, counter_id);

					counters_removed_it = counters_removed.erase(counters_removed_it);
					continue;
				}

				counters_removed_it++;
			}
		}
	}

protected:
	counter_manager_t* manager;

	mutable std::mutex mutex;

	std::map<key_T, std::tuple<tCounterId, uint32_t>> counters; ///< refcount
	std::map<key_T, tCounterId> counters_inserted;
	std::map<key_T, std::tuple<tCounterId, uint32_t>> counters_removed; ///< timestamp
	std::map<key_T, tCounterId> counters_gc_removed;
	std::map<key_T, tCounterId> counters_allocated;
};
