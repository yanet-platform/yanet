#pragma once

#include <numa.h>

#include "define.h"
#include "stream.h"
#include "type.h"

#define YANET_SHARED_MEMORY_FILE_DATAPLANE "yanet_dataplane.shm"
#define YANET_SHARED_MEMORY_PREFIX_WORKERS "yanet_workers_node_"
#define YANET_SIZE_BUFFER_METADATA_DATAPLANE 1024 * 8

namespace common::sdp
{

inline std::string FileNameWorkerOnNumaNode(tSocketId socket_id)
{
	return YANET_SHARED_MEMORY_PREFIX_WORKERS + std::to_string(socket_id) + ".shm";
}

template<typename TResult, typename TBuffer = void*>
inline TResult ShiftBuffer(TBuffer buffer, uint64_t size)
{
	return reinterpret_cast<TResult>((reinterpret_cast<char*>(buffer) + size));
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

	void WriteToStream(common::stream_out_t& stream)
	{
		stream.push(start_counters);
		stream.push(start_acl_counters);
		stream.push(start_bursts);
		stream.push(start_stats);
		stream.push(start_stats_ports);
		stream.push(size);
		stream.push(counter_positions);
	}
};

struct MetadataWorkerGc
{
	uint64_t start_counters;
	uint64_t start_stats;
	uint64_t size;

	std::map<std::string, uint64_t> counter_positions;

	void WriteToStream(common::stream_out_t& stream)
	{
		stream.push(start_counters);
		stream.push(start_stats);
		stream.push(size);
		stream.push(counter_positions);
	}
};

struct MetadataBusCounters
{
	uint64_t start_bus_errors;
	uint64_t start_bus_requests;
	uint64_t start_bus_durations;

	void WriteToStream(common::stream_out_t& stream)
	{
		stream.push(start_bus_errors);
		stream.push(start_bus_requests);
		stream.push(start_bus_durations);
	}
};

struct WorkerInSharedMemory
{
	tSocketId socket;
	uint64_t shift_in_socket;
	void* buffer;
};

struct DataPlaneInSharedMemory
{
	using workers_info = std::map<tCoreId, WorkerInSharedMemory>;
	using workers_info_stream = std::map<uint64_t, std::pair<uint64_t, uint64_t>>;

	workers_info workers;
	workers_info workers_gc;

	MetadataWorker metadata_worker;
	MetadataWorkerGc metadata_worker_gc;
	MetadataBusCounters metadata_bus;

	void* dataplane_data;

	workers_info_stream WorkersForStream(const workers_info& info)
	{
		workers_info_stream result;
		for (const auto& iter : info)
		{
			result[iter.first] = {iter.second.socket, iter.second.shift_in_socket};
		}
		return result;
	}

	void WriteToStream(common::stream_out_t& stream)
	{
		stream.push(WorkersForStream(workers));
		stream.push(WorkersForStream(workers_gc));
		metadata_worker.WriteToStream(stream);
		metadata_worker_gc.WriteToStream(stream);
		metadata_bus.WriteToStream(stream);
	}
};

} // namespace common::sdp
