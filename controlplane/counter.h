#pragma once

#include <mutex>

#include "type.h"

#include "common/idataplane.h"
#include "common/refarray.h"

class counter_manager_t
{
public:
	static_assert ((uint32_t)common::globalBase::static_counter_type::size <= YANET_CONFIG_COUNTERS_SIZE);

	counter_manager_t()
	{
		for (unsigned int counter_id = (uint32_t)common::globalBase::static_counter_type::size;
		     counter_id < YANET_CONFIG_COUNTERS_SIZE;
		     counter_id++)
		{
			counter_unused_ids.emplace(counter_id);
		}
		counter_unused_ids_size = counter_unused_ids.size();
		counter_shifts.resize(YANET_CONFIG_COUNTERS_SIZE, 0);
	}

	std::tuple<uint64_t, uint64_t> stats() const
	{
		return {YANET_CONFIG_COUNTERS_SIZE - counter_unused_ids_size, YANET_CONFIG_COUNTERS_SIZE};
	}

protected:
	template<typename key_T,
	         size_t size_T>
	friend class counter_t;

	template<size_t size_T>
	std::array<tCounterId, size_T> counter_reserve()
	{
		static_assert (size_T <= YANET_CONFIG_COUNTER_FALLBACK_SIZE);

		std::lock_guard<std::mutex> guard(counter_mutex);

		/// @todo: opt std::array<tCounterId, size_T> reserve_ids;
		std::vector<tCounterId> reserve_ids;
		reserve_ids.reserve(size_T);
		std::set<tCounterId> bad_counter_ids;
		while (counter_unused_ids.size())
		{
			const uint32_t counter_id = *counter_unused_ids.begin();
			counter_unused_ids.erase(counter_id);

			if (reserve_ids.size())
			{
				if (reserve_ids.back() + 1 != counter_id)
				{
					for (const auto& counter_id : reserve_ids)
					{
						bad_counter_ids.emplace(counter_id);
					}

					reserve_ids.clear();
				}
			}

			reserve_ids.emplace_back(counter_id);

			if (reserve_ids.size() == size_T)
			{
				for (const auto& counter_id : bad_counter_ids)
				{
					counter_unused_ids.emplace(counter_id);
				}
				bad_counter_ids.clear();

				counter_unused_ids_size = counter_unused_ids.size();

				std::array<tCounterId, size_T> result;
				std::copy_n(reserve_ids.begin(), size_T, result.begin());
				return result;
			}
		}

		for (const auto& counter_id : reserve_ids)
		{
			counter_unused_ids.emplace(counter_id);
		}

		for (const auto& counter_id : bad_counter_ids)
		{
			counter_unused_ids.emplace(counter_id);
		}
		bad_counter_ids.clear();

		YANET_LOG_WARNING("not enough counters\n");

		/// fallback
		std::array<tCounterId, size_T> result;
		for (size_t i = 0;
		     i < size_T;
		     i++)
		{
			result[i] = i;
		}
		return result;
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

	void counter_release(const std::vector<tCounterId>& counter_ids)
	{
		std::lock_guard<std::mutex> guard(counter_mutex);
		for (const auto& counter_id : counter_ids)
		{
			counter_unused_ids.emplace(counter_id);
		}
		counter_unused_ids_size = counter_unused_ids.size();
	}

protected:
	mutable std::mutex counter_mutex;
	interface::dataPlane counter_dataplane;
	std::set<tCounterId> counter_unused_ids;
	std::atomic<uint64_t> counter_unused_ids_size;
	std::vector<uint64_t> counter_shifts;
};

template<typename key_T,
         size_t size_T>
class counter_t
{
public:
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
		for (const auto& [key, counter_ids_array] : counters_inserted)
		{
			for (const auto& counter_id : counter_ids_array)
			{
				counter_ids.emplace_back(counter_id);
			}

			counters_allocated.emplace(key, counter_ids_array);
			callback(key);
		}
		counters_inserted.clear();

		manager->counter_allocate(counter_ids);
	}

	void allocate()
	{
		allocate([](const key_T& key){(void)key;});
	}

	template<typename callback_T>
	void release(const callback_T& callback)
	{
		std::lock_guard<std::mutex> guard(mutex);

		std::vector<tCounterId> counter_ids;
		counter_ids.reserve(counters_gc_removed.size() * size_T);
		for (const auto& [key, counter_ids_array] : counters_gc_removed)
		{
			for (const auto& counter_id : counter_ids_array)
			{
				counter_ids.emplace_back(counter_id);
			}

			callback(key);
			counters.erase(key);
			counters_allocated.erase(key);
		}
		counters_gc_removed.clear();

		manager->counter_release(counter_ids);
	}

	void release()
	{
		release([](const key_T& key){(void)key;});
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
			const auto counter_ids = manager->counter_reserve<size_T>();

			counters.emplace_hint(counters_it,
			                      key,
			                      std::tuple<std::array<tCounterId, size_T>,
			                                 uint32_t>(counter_ids,
			                                           1));
			counters_inserted.emplace(key, counter_ids);
		}
	}

	void remove(const key_T& key,
	            const uint32_t timeout = 0)
	{
		std::lock_guard<std::mutex> guard(mutex);

		auto counters_it = counters.find(key);
		if (counters_it != counters.end())
		{
			auto& [counter_ids_array, refcount] = counters_it->second;

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
					std::vector<tCounterId> counter_ids_removed;
					for (const auto& counter_id : counters_inserted_it->second)
					{
						counter_ids_removed.emplace_back(counter_id);
					}
					manager->counter_release(counter_ids_removed);

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

					counters_removed.emplace(key, std::tuple<std::array<tCounterId, size_T>,
					                                                    uint32_t>(counter_ids_array, timestamp));
				}
			}
		}
		else
		{
			/// @todo: delete
			YANET_LOG_WARNING("unknown counter\n");
		}
	}

	std::array<tCounterId, size_T> get_ids(const key_T& key)
	{
		std::lock_guard<std::mutex> guard(mutex);

		auto iter = counters.find(key);
		if (iter == counters.end())
		{
			/// fallback
			std::array<tCounterId, size_T> result;
			for (size_t i = 0;
			     i < size_T;
			     i++)
			{
				result[i] = i;
			}

			return result;
		}

		const auto& [counter_ids, refcount] = iter->second;
		(void)refcount;

		return counter_ids;
	}

	tCounterId get_id(const key_T& key)
	{
		return get_ids(key)[0];
	}

	std::map<key_T, std::array<uint64_t, size_T>> get_counters() const ///< get_values
	{
		std::lock_guard<std::mutex> guard(mutex);

		/// @todo: opt
		std::vector<tCounterId> manager_counter_ids;
		for (const auto& [key, counter_ids_array] : counters_allocated)
		{
			(void)key;

			for (const auto& counter_id : counter_ids_array)
			{
				manager_counter_ids.emplace_back(counter_id);
			}
		}

		auto manager_counters = manager->counter_get(manager_counter_ids);

		std::map<key_T, std::array<uint64_t, size_T>> result;

		size_t i = 0;
		for (const auto& [key, counter_ids_array] : counters_allocated)
		{
			(void)counter_ids_array;

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

	void gc()
	{
		std::lock_guard<std::mutex> guard(mutex);

		if (counters_removed.size())
		{
			uint32_t current_time = time(nullptr);

			for (auto counters_removed_it = counters_removed.begin();
			     counters_removed_it != counters_removed.end();
			     )
			{
				const auto& [key, ids_timestamp] = *counters_removed_it;
				const auto& [counter_ids_array, timestamp] = ids_timestamp;

				if (current_time >= timestamp)
				{
					counters_gc_removed.emplace(key, counter_ids_array);

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

	std::map<key_T,
	         std::tuple<std::array<tCounterId, size_T>,
	                    uint32_t>> counters; ///< refcount

	std::map<key_T,
	         std::array<tCounterId, size_T>> counters_inserted;

	std::map<key_T,
	         std::tuple<std::array<tCounterId, size_T>,
	                    uint32_t>> counters_removed; ///< timestamp

	std::map<key_T,
	         std::array<tCounterId, size_T>> counters_gc_removed;

	std::map<key_T,
	         std::array<tCounterId, size_T>> counters_allocated;
};
