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
	std::lock_guard<std::mutex> guard(pointers_mutex);
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
	root_memory_group = request;
	return eResult::success;
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

	YANET_LOG_INFO("yanet_alloc(name: '%s', socket: %u, size: %lu)\n",
	               name,
	               socket_id,
	               size);

	void* pointer = rte_malloc_socket(nullptr,
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

	{
		std::lock_guard<std::mutex> guard(pointers_mutex);
		pointers.try_emplace(pointer, name, socket_id, size, pointer, [destructor](void* pointer) {
			destructor(pointer);
			rte_free(pointer);
		});
	}

	return pointer;
}

void memory_manager::destroy(void* pointer)
{
	std::lock_guard<std::mutex> guard(pointers_mutex);

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

void dataplane::memory_manager::limits(common::idp::limits::response& response)
{
	(void)response;
}
