#include "memory_manager.h"

using namespace dataplane;

memory_pointer::memory_pointer(const char* name,
                               const tSocketId socket_id,
                               const size_t size,
                               void* pointer,
                               const std::function<void(void*)>& destructor) :
        name(name),
        socket_id(socket_id),
        size(size),
        pointer(pointer),
        destructor(destructor)
{
}

memory_pointer::~memory_pointer()
{
	YANET_LOG_INFO("yanet_free(name: '%s', socket: %u, size: %lu)\n",
	               name.data(),
	               socket_id,
	               size);
	destructor(pointer);
}

memory_manager::memory_manager() :
        dataplane(nullptr)
{
}

eResult memory_manager::init(cDataPlane* dataplane)
{
	this->dataplane = dataplane;
	return eResult::success;
}

inline std::string to_hex(const void* pointer)
{
	char buffer[128];
	snprintf(buffer, 128, "%p", pointer);
	return buffer;
}

void memory_manager::report(nlohmann::json& json)
{
	std::lock_guard<std::mutex> guard(mutex);
	for (const auto& [pointer, memory_pointer] : pointers)
	{
		nlohmann::json json_object;
		json_object["pointer"] = to_hex(pointer);
		json_object["name"] = memory_pointer.name;
		json_object["socket_id"] = memory_pointer.socket_id;
		json_object["size"] = memory_pointer.size;
		json["memory_manager"].emplace_back(json_object);
	}
}

eResult memory_manager::memory_manager_update(const common::idp::memory_manager_update::request& request)
{
	std::lock_guard<std::mutex> guard(mutex);
	root_memory_group = request;
	return eResult::success;
}

common::idp::memory_manager_stats::response memory_manager::memory_manager_stats()
{
	common::idp::memory_manager_stats::response response;
	auto& [response_memory_group, response_objects] = response;

	{
		std::lock_guard<std::mutex> guard(mutex);

		response_memory_group = root_memory_group;
		for (const auto& [pointer, memory_pointer] : pointers)
		{
			(void)pointer;
			response_objects.emplace_back(memory_pointer.name,
			                              memory_pointer.socket_id,
			                              memory_pointer.size);
		}
	}

	return response;
}

void* memory_manager::alloc(const char* name,
                            const tSocketId socket_id,
                            uint64_t size,
                            const std::function<void(void*)>& destructor)
{
	if (!size)
	{
		YANET_LOG_ERROR("error allocation memory (name: '%s', socket: %u, size: %lu)\n",
		                name,
		                socket_id,
		                size);
		return nullptr;
	}

	size += 2 * RTE_CACHE_LINE_SIZE;

	void* pointer = nullptr;
	{
		std::lock_guard<std::mutex> guard(mutex);

		YANET_LOG_INFO("yanet_alloc(name: '%s', socket: %u, size: %lu)\n",
		               name,
		               socket_id,
		               size);

		if (!check_memory_limit(name, size))
		{
			return nullptr;
		}

		pointer = rte_malloc_socket(nullptr,
		                            size,
		                            RTE_CACHE_LINE_SIZE,
		                            socket_id);
		if (pointer == nullptr)
		{
			YANET_LOG_ERROR("error allocation memory (name: '%s', socket: %u, size: %lu)\n",
			                name,
			                socket_id,
			                size);
			debug(socket_id);
			return nullptr;
		}

		pointers.try_emplace(pointer, name, socket_id, size, pointer, [destructor](void* pointer) {
			destructor(pointer);
			rte_free(pointer);
		});
	}

	return pointer;
}

void memory_manager::destroy(void* pointer)
{
	std::lock_guard<std::mutex> guard(mutex);

	auto it = pointers.find(pointer);
	if (it == pointers.end())
	{
		YANET_LOG_ERROR("unknown pointer: %p\n", pointer);
		return;
	}

	pointers.erase(it);
}

void memory_manager::debug(tSocketId socket_id)
{
	rte_malloc_socket_stats stats;
	if (rte_malloc_get_socket_stats(socket_id, &stats) == 0)
	{
		YANET_LOG_INFO("heap_totalsz_bytes: %lu MB\n", stats.heap_totalsz_bytes / (1024 * 1024));
		YANET_LOG_INFO("heap_freesz_bytes: %lu MB\n", stats.heap_freesz_bytes / (1024 * 1024));
		YANET_LOG_INFO("greatest_free_size: %lu MB\n", stats.greatest_free_size / (1024 * 1024));
		YANET_LOG_INFO("free_count: %u\n", stats.free_count);
		YANET_LOG_INFO("alloc_count: %u\n", stats.alloc_count);
		YANET_LOG_INFO("heap_allocsz_bytes: %lu MB\n", stats.heap_allocsz_bytes / (1024 * 1024));
	}
}

bool memory_manager::check_memory_limit(const std::string& name,
                                        const uint64_t size)
{
	bool result = true;
	std::map<std::string, ///< object_name
	         common::uint64> ///< current
	        currents;

	for (const auto& [pointer, memory_pointer] : pointers)
	{
		(void)pointer;

		uint64_t object_size = memory_pointer.size;
		if (memory_pointer.name == name)
		{
			object_size = size;
		}

		currents[memory_pointer.name] = std::max(currents[memory_pointer.name].value,
		                                         object_size);
	}

	root_memory_group.for_each([&](const auto& memory_group,
	                               const std::set<std::string>& object_names) {
		bool check = false;
		uint64_t group_total = 0;
		for (const auto& object_name : object_names)
		{
			group_total += currents[object_name];

			if (object_name == name)
			{
				check = true;
			}
		}

		if (check && memory_group.limit)
		{
			if (group_total > memory_group.limit)
			{
				YANET_LOG_ERROR("memory limit for '%s': group '%s': %lu of %lu\n",
				                name.data(),
				                memory_group.name.data(),
				                group_total,
				                memory_group.limit);
				for (const auto& object_name : object_names)
				{
					YANET_LOG_ERROR("  object '%s': %lu\n",
					                object_name.data(),
					                currents[object_name].value);
				}
				result = false;
			}
		}
	});

	return result;
}

void dataplane::memory_manager::limits(common::idp::limits::response& response)
{
	(void)response;
}
