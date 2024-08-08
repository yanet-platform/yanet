#pragma once

#include <algorithm>
#include <numa.h>
#include <sys/mman.h>

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

	void ReadFromStream(common::stream_in_t& stream)
	{
		stream.pop(start_counters);
		stream.pop(start_acl_counters);
		stream.pop(start_bursts);
		stream.pop(start_stats);
		stream.pop(start_stats_ports);
		stream.pop(size);
		stream.pop(counter_positions);
	}

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

	void WriteToStream(common::stream_out_t& stream)
	{
		stream.push(start_counters);
		stream.push(start_stats);
		stream.push(size);
		stream.push(counter_positions);
	}

	void ReadFromStream(common::stream_in_t& stream)
	{
		stream.pop(start_counters);
		stream.pop(start_stats);
		stream.pop(size);
		stream.pop(counter_positions);
	}

	bool operator==(const MetadataWorkerGc& other) const
	{
		return other.start_counters == start_counters &&
		       other.start_stats == start_stats &&
		       other.size == size &&
		       MapsEqual(other.counter_positions, counter_positions);
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

	void ReadFromStream(common::stream_in_t& stream)
	{
		stream.pop(start_bus_errors);
		stream.pop(start_bus_requests);
		stream.pop(start_bus_durations);
	}

	bool operator==(const MetadataBusCounters& other) const
	{
		return other.start_bus_errors == start_bus_errors &&
		       other.start_bus_requests == start_bus_requests &&
		       other.start_bus_durations == start_bus_durations;
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
	using workers_info = std::map<tCoreId, WorkerInSharedMemory>;
	using workers_info_stream = std::map<uint64_t, std::pair<uint64_t, uint64_t>>;

	workers_info workers;
	workers_info workers_gc;

	MetadataWorker metadata_worker;
	MetadataWorkerGc metadata_worker_gc;
	MetadataBusCounters metadata_bus;

	uint64_t size_dataplane_buffer;
	void* dataplane_data = nullptr;

	workers_info_stream WorkersForStream(const workers_info& info)
	{
		workers_info_stream result;
		for (const auto& iter : info)
		{
			result[iter.first] = {iter.second.socket, iter.second.shift_in_socket};
		}
		return result;
	}

	void WorkersFromStream(workers_info& info, common::stream_in_t& stream)
	{
		workers_info_stream data_worker;
		stream.pop(data_worker);
		for (const auto& iter : data_worker)
		{
			info[iter.first] = {tSocketId(iter.second.first), iter.second.second, nullptr};
		}
	}

	void WriteToStream(common::stream_out_t& stream)
	{
		stream.push(size_dataplane_buffer);
		stream.push(WorkersForStream(workers));
		stream.push(WorkersForStream(workers_gc));
		metadata_worker.WriteToStream(stream);
		metadata_worker_gc.WriteToStream(stream);
		metadata_bus.WriteToStream(stream);
	}

	bool ReadFromStream(common::stream_in_t& stream)
	{
		stream.pop(size_dataplane_buffer);
		WorkersFromStream(workers, stream);
		WorkersFromStream(workers_gc, stream);
		metadata_worker.ReadFromStream(stream);
		metadata_worker_gc.ReadFromStream(stream);
		metadata_bus.ReadFromStream(stream);
		return !stream.isFailed();
	}

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

	bool operator==(const DataPlaneInSharedMemory& other)
	{
		return other.metadata_worker == metadata_worker &&
		       other.metadata_worker_gc == metadata_worker_gc &&
		       other.metadata_bus == metadata_bus &&
		       MapsEqual(other.workers, workers) &&
		       MapsEqual(other.workers_gc, workers_gc);
	}
};

} // namespace common::sdp
