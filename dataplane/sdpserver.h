#pragma once

#include <rte_byteorder.h>

#include "common/result.h"
#include "common/sdpcommon.h"
#include "common/shared_memory.h"

namespace common::sdp
{

class SdrSever
{
public:
	static eResult PrepareSharedMemoryData(DataPlaneInSharedMemory& sdp_data,
	                                       const std::vector<tCoreId>& workers_id,
	                                       const std::vector<tCoreId>& workers_gc_id,
	                                       bool use_huge_tlb)
	{
		// Part 1 - prepare data workers
		//
		std::map<tSocketId, uint64_t> sockets_shifts;

		// Fill workers info
		for (tCoreId core_id : workers_id)
		{
			tSocketId socket_id = GetNumaNode(core_id);
			sdp_data.workers[core_id] = {socket_id, sockets_shifts[socket_id], nullptr};
			sockets_shifts[socket_id] += sdp_data.metadata_worker.size;
		}

		// Fill workers_gc info
		for (tCoreId core_id : workers_gc_id)
		{
			tSocketId socket_id = GetNumaNode(core_id);
			sdp_data.workers_gc[core_id] = {socket_id, sockets_shifts[socket_id], nullptr};
			sockets_shifts[socket_id] += sdp_data.metadata_worker_gc.size;
		}

		// Create buffers in shared memory for workers in numa nodes
#ifndef YANET_USE_POSIX_SHARED_MEMORY
		key_t key_shared_memory_segment = YANET_SHARED_MEMORY_KEY_DATAPLANE;
#endif
		std::map<tSocketId, void*> sockets_buffers;
		for (auto [socket_id, size] : sockets_shifts)
		{
#ifdef YANET_USE_POSIX_SHARED_MEMORY
			std::string filename = common::sdp::FileNameWorkerOnNumaNode(socket_id);
			void* buffer = common::ipc::SharedMemory::CreateBufferFile(filename, size, use_huge_tlb, socket_id);
			if (buffer == nullptr)
			{
				YANET_LOG_ERROR("Error create buffer in shared memory for workers on numa=%d, filename=%s, size=%ld\n",
				                socket_id,
				                filename.c_str(),
				                size);
				return eResult::errorInitSharedMemory;
			}
#else
			key_shared_memory_segment++;
			void* buffer = common::ipc::SharedMemory::CreateBufferKey(key_shared_memory_segment, size, use_huge_tlb, socket_id);
			if (buffer == nullptr)
			{
				YANET_LOG_ERROR("Error create buffer in shared memory for workers on numa=%d, key=%d, size=%ld\n",
				                socket_id,
				                key_shared_memory_segment,
				                size);
				return eResult::errorInitSharedMemory;
			}
#endif
			sockets_buffers[socket_id] = buffer;
		}

		// Fill workers buffers
		for (auto& worker_info : sdp_data.workers)
		{
			worker_info.second.buffer = (char*)sockets_buffers[worker_info.second.socket] + worker_info.second.shift_in_socket;
		}

		// Fill workers_gc buffers
		for (auto& worker_info : sdp_data.workers_gc)
		{
			worker_info.second.buffer = (char*)sockets_buffers[worker_info.second.socket] + worker_info.second.shift_in_socket;
		}

		// Part 2 - prepare data dataplane
		// Create buffer in shared memory for dataplane data
		sdp_data.FillSizes();
#ifdef YANET_USE_POSIX_SHARED_MEMORY
		sdp_data.dataplane_data = common::ipc::SharedMemory::CreateBufferFile(YANET_SHARED_MEMORY_FILE_DATAPLANE,
		                                                                      sdp_data.size_dataplane_buffer,
		                                                                      use_huge_tlb,
		                                                                      std::nullopt);
		if (sdp_data.dataplane_data == nullptr)
		{
			YANET_LOG_ERROR("Error create buffer in shared memory for dataplane data, filename=%s, size=%ld\n",
			                YANET_SHARED_MEMORY_FILE_DATAPLANE,
			                sdp_data.size_dataplane_buffer);
			return eResult::errorInitSharedMemory;
		}
#else
		sdp_data.dataplane_data = common::ipc::SharedMemory::CreateBufferKey(YANET_SHARED_MEMORY_KEY_DATAPLANE,
		                                                                     sdp_data.size_dataplane_buffer,
		                                                                     use_huge_tlb,
		                                                                     std::nullopt);
		if (sdp_data.dataplane_data == nullptr)
		{
			YANET_LOG_ERROR("Error create buffer in shared memory for dataplane data, key=%d, size=%ld\n",
			                key_shared_memory_segment,
			                sdp_data.size_dataplane_buffer);
			return eResult::errorInitSharedMemory;
		}
#endif

		WriteMainDataToBuffer(sdp_data);

		return eResult::success;
	}

	static uint64_t GetStartData(uint64_t size, uint64_t& current_start)
	{
		static constexpr uint64_t cache_line_size = 64;
		uint64_t result = current_start;
		current_start += size;
		current_start = cache_line_size * ((current_start + cache_line_size - 1) / cache_line_size);
		return result;
	}

private:
	static void WriteMainDataToBuffer(DataPlaneInSharedMemory& sdp_data)
	{
		// HEADER
		uint64_t start_workers = DataPlaneInSharedMemory::size_header;
		WriteValue(sdp_data, 0, start_workers);
		WriteValue(sdp_data, 1, sdp_data.size_workers_section);

		uint64_t start_workers_metadata = start_workers + sdp_data.size_workers_section;
		WriteValue(sdp_data, 2, start_workers_metadata);
		WriteValue(sdp_data, 3, sdp_data.size_workers_metadata_section);

		sdp_data.start_bus_section = start_workers_metadata + sdp_data.size_workers_metadata_section;
		WriteValue(sdp_data, 4, sdp_data.start_bus_section);
		WriteValue(sdp_data, 5, sdp_data.size_bus_section);

		// WORKERS
		{
			uint64_t index = start_workers / sizeof(uint64_t);
			WriteValue(sdp_data, index++, sdp_data.workers.size());
			WriteValue(sdp_data, index++, sdp_data.workers_gc.size());

			for (const auto& [coreId, info] : sdp_data.workers)
			{
				WriteValue(sdp_data, index++, coreId);
				WriteValue(sdp_data, index++, info.socket);
				WriteValue(sdp_data, index++, info.shift_in_socket);
			}

			for (const auto& [coreId, info] : sdp_data.workers_gc)
			{
				WriteValue(sdp_data, index++, coreId);
				WriteValue(sdp_data, index++, info.socket);
				WriteValue(sdp_data, index++, info.shift_in_socket);
			}
		}

		// WORKERS_METADATA
		{
			uint64_t index = start_workers_metadata / sizeof(uint64_t);

			// 0-5 - values from MetadataWorker
			WriteValue(sdp_data, index, sdp_data.metadata_worker.start_counters);
			WriteValue(sdp_data, index + 1, sdp_data.metadata_worker.start_acl_counters);
			WriteValue(sdp_data, index + 2, sdp_data.metadata_worker.start_bursts);
			WriteValue(sdp_data, index + 3, sdp_data.metadata_worker.start_stats);
			WriteValue(sdp_data, index + 4, sdp_data.metadata_worker.start_stats_ports);
			WriteValue(sdp_data, index + 5, sdp_data.metadata_worker.size);
			// 6 - n1 = size MetadataWorker.counter_positions
			WriteValue(sdp_data, index + 6, sdp_data.metadata_worker.counter_positions.size());
			// 7-9 - values from MetadataWorker
			WriteValue(sdp_data, index + 7, sdp_data.metadata_worker_gc.start_counters);
			WriteValue(sdp_data, index + 8, sdp_data.metadata_worker_gc.start_stats);
			WriteValue(sdp_data, index + 9, sdp_data.metadata_worker_gc.size);
			// 10 - n2 = size MetadataWorker.counter_positions
			WriteValue(sdp_data, index + 10, sdp_data.metadata_worker_gc.counter_positions.size());

			WriteMap(sdp_data, start_workers_metadata + 128, sdp_data.metadata_worker.counter_positions);
			WriteMap(sdp_data, start_workers_metadata + 128 * (1 + sdp_data.metadata_worker.counter_positions.size()), sdp_data.metadata_worker_gc.counter_positions);
		}
	}

	static void WriteMap(DataPlaneInSharedMemory& sdp_data, uint64_t index, const std::map<std::string, uint64_t>& values)
	{
		for (const auto& [key, value] : values)
		{
			WriteValue(sdp_data, index / sizeof(uint64_t), value);
			WriteString(sdp_data, index, key);
			index += 128;
		}
	}

	static void WriteValue(DataPlaneInSharedMemory& sdp_data, uint64_t index, uint64_t value)
	{
		((uint64_t*)sdp_data.dataplane_data)[index] = rte_cpu_to_be_64(value);
	}

	static void WriteString(DataPlaneInSharedMemory& sdp_data, uint64_t index, const std::string& str)
	{
		snprintf(reinterpret_cast<char*>(sdp_data.dataplane_data) + index + 8, 120, "%s", str.c_str());
	}

	static int GetNumaNode(tCoreId core_id)
	{
		int socket_id = numa_node_of_cpu(core_id);
		if (socket_id == -1)
		{
			YANET_LOG_ERROR("numa_node_of_cpu(%d) err: %s\n", core_id, strerror(errno));
			socket_id = 0;
		}
		return socket_id;
	}
};

} // namespace common::sdp
