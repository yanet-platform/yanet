#pragma once

#include <algorithm>
#include <numa.h>
#include <sys/mman.h>

#include "define.h"
#include "idp.h"
#include "utils.h"

// #define YANET_USE_POSIX_SHARED_MEMORY

#ifdef YANET_USE_POSIX_SHARED_MEMORY

#define YANET_SHARED_MEMORY_FILE_DATAPLANE "yanet_dataplane.shm"
#define YANET_SHARED_MEMORY_PREFIX_WORKERS "yanet_workers_node_"

#else

#define YANET_SHARED_MEMORY_KEY_DATAPLANE 54321

#endif

/*

The structure of data storage in memory DataPlaneInSharedMemory

The following files are created to store data in shared memory:
1) The main file with information about workers, metadata, some common counters of the system
2) A separate file is created for each socket (numa node) - it stores the data of the worker counters

All numeric values are stored as 64-bit numbers in Big Endian

---------------------------------------
1 - The main file
The file contains the following sections:
- HEADER
- WORKERS
- WORKERS_METADATA
- BUS

HEADER - 1024 bytes in size (DataPlaneInSharedMemory::size_header)
Contains the beginning and the size of the remaining sections, 2 numbers each:
- 0,1 - WORKERS
- 2,3 - WORKERS_MET
- 4,5 - BUS
  The remaining values are reserved

WORKERS
Contains the following values:
  0 - n1 = number of workers
  1 - n2 = number of worker_gc
  The following contains n1 + n2 triples of numbers:
  n - core_id
  n+1 - socket
  n+2 - shift in socket

WORKERS_METADATA
  At the beginning, 11 64-bit numbers are written:
    0-5 - values from MetadataWorker
    6 - n1 = size MetadataWorker.counter_positions
    7-9 - values from MetadataWorker
    10 - n2 = size MetadataWorker.counter_positions

  Starting from 128 bytes, there are n1+n2 entries from counter_positions, each entry occupies 128 bytes:
    The first 8 bytes are the value from the map
    The remaining 120 bytes are a string (key), ending with a null byte

BUS
Contains a buffer used by cBus counters

---------------------------------------
2 - Socket data file
The file consists of several blocks, each block corresponds to a worker or worker_gc.

Block for worker
  The block size is equal to MetadataWorker::size.
  This block is divided into 5 blocks - counters, acl_counters, bursts, stats, stats_port.
  To determine the beginning of a block, for example, stats:
   DataPlaneInSharedMemory::workers_info[core_id].shift_in_socket + MetadataWorker::start_stats

Block for worker_gc
  The block size is equal to MetadataWorkerGc::size.
  This block is divided into 2 blocks - counters, stats.

*/

namespace common::sdp
{

using utils::ShiftBuffer;

#ifdef YANET_USE_POSIX_SHARED_MEMORY
inline std::string FileNameWorkerOnNumaNode(tSocketId socket_id)
{
	return YANET_SHARED_MEMORY_PREFIX_WORKERS + std::to_string(socket_id) + ".shm";
}
#endif

template<typename Key, typename Value>
bool MapsEqual(const std::map<Key, Value>& left, const std::map<Key, Value>& right)
{
	if (left.size() != right.size())
	{
		return false;
	}

	auto [stop_left, stop_right] = std::mismatch(left.begin(), left.end(), right.begin(), right.end());

	return (stop_left == left.end()) && (stop_right == right.end());
}

struct MetadataWorker
{
	uint64_t start_counters;
	uint64_t start_acl_counters;
	uint64_t start_bursts;
	uint64_t start_stats;
	uint64_t start_stats_ports;
	uint64_t size;

	std::map<std::string, uint64_t> counter_positions;

	bool operator==(const MetadataWorker& other) const
	{
		return other.start_counters == start_counters &&
		       other.start_acl_counters == start_acl_counters &&
		       other.start_bursts == start_bursts &&
		       other.start_stats == start_stats &&
		       other.start_stats_ports == start_stats_ports &&
		       other.size == size &&
		       MapsEqual(other.counter_positions, counter_positions);
	}
};

struct MetadataWorkerGc
{
	uint64_t start_counters;
	uint64_t start_stats;
	uint64_t size;

	std::map<std::string, uint64_t> counter_positions;

	bool operator==(const MetadataWorkerGc& other) const
	{
		return other.start_counters == start_counters &&
		       other.start_stats == start_stats &&
		       other.size == size &&
		       MapsEqual(other.counter_positions, counter_positions);
	}
};

struct WorkerInSharedMemory
{
	tSocketId socket;
	uint64_t shift_in_socket;
	void* buffer;

	bool operator==(const WorkerInSharedMemory& other) const
	{
		return other.socket == socket &&
		       other.shift_in_socket == shift_in_socket;
	}
};

struct DataPlaneInSharedMemory
{
	static constexpr uint64_t size_header = 1024;

	using workers_info = std::map<tCoreId, WorkerInSharedMemory>;

	workers_info workers;
	workers_info workers_gc;

	MetadataWorker metadata_worker;
	MetadataWorkerGc metadata_worker_gc;

	uint64_t size_workers_section;
	uint64_t size_workers_metadata_section;
	uint64_t size_bus_section;

	uint64_t size_dataplane_buffer;
	void* dataplane_data = nullptr;
	uint64_t start_bus_section;

	void UnmapBuffers(uint64_t size)
	{
		if (dataplane_data != nullptr)
		{
			if (munmap(dataplane_data, size) < 0)
			{
				YANET_LOG_ERROR("Error munmap %d: %s", errno, strerror(errno));
			}
			dataplane_data = nullptr;
		}
	}

	bool operator==(const DataPlaneInSharedMemory& other) const
	{
		return other.metadata_worker == metadata_worker &&
		       other.metadata_worker_gc == metadata_worker_gc &&
		       other.start_bus_section == start_bus_section &&
		       MapsEqual(other.workers, workers) &&
		       MapsEqual(other.workers_gc, workers_gc);
	}

	void FillSizes()
	{
		size_workers_section = Allign64((2 + 3 * (workers.size() + workers_gc.size())) * sizeof(uint64_t));
		size_workers_metadata_section = 128 * (1 + metadata_worker.counter_positions.size() + metadata_worker_gc.counter_positions.size());
		size_bus_section = Allign64(size_bus_section);
		size_dataplane_buffer = size_header + size_workers_section + size_workers_metadata_section + size_bus_section;
	}

	static uint64_t Allign64(uint64_t value)
	{
		return ((value + 63) / 64) * 64;
	}

	[[nodiscard]] std::tuple<uint64_t*, uint64_t*, uint64_t*> BuffersBus() const
	{
		auto count_errors = static_cast<uint32_t>(common::idp::errorType::size);
		auto count_requests = static_cast<uint32_t>(common::idp::requestType::size);
		auto* requests = ShiftBuffer<uint64_t*>(dataplane_data, start_bus_section);
		auto* errors = ShiftBuffer<uint64_t*>(dataplane_data, start_bus_section + count_requests * sizeof(uint64_t));
		auto* durations = ShiftBuffer<uint64_t*>(dataplane_data, start_bus_section + (count_requests + count_errors) * sizeof(uint64_t));
		return {requests, errors, durations};
	}
};

} // namespace common::sdp
