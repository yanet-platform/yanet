#include "sdpserver.h"
#include "bus.h"
#include "worker.h"
#include "worker_gc.h"

#include "common/shared_memory.h"

namespace common::sdp
{

int GetNumaNode(tCoreId core_id)
{
	int socket_id = numa_node_of_cpu(core_id);
	if (socket_id == -1)
	{
		YANET_LOG_ERROR("numa_node_of_cpu(%d) err: %s\n", core_id, strerror(errno));
		socket_id = 0;
	}
	return socket_id;
}

eResult PrepareSharedMemoryData(DataPlaneInSharedMemory& sdp_data,
                                const std::vector<tCoreId>& workers_id,
                                const std::vector<tCoreId>& workers_gc_id,
                                bool use_huge_tlb)
{
	// Part 1 - prepare data workers
	//
	std::map<tSocketId, uint64_t> sockets_shifts;

	// Fill workers info
	cWorker::FillMetadataWorkerCounters(sdp_data.metadata_worker);
	for (tCoreId core_id : workers_id)
	{
		tSocketId socket_id = GetNumaNode(core_id);
		sdp_data.workers[core_id] = {socket_id, sockets_shifts[socket_id], nullptr};
		sockets_shifts[socket_id] += sdp_data.metadata_worker.size;
	}

	// Fill workers_gc info
	worker_gc_t::FillMetadataWorkerCounters(sdp_data.metadata_worker_gc);
	for (tCoreId core_id : workers_gc_id)
	{
		tSocketId socket_id = GetNumaNode(core_id);
		sdp_data.workers_gc[core_id] = {socket_id, sockets_shifts[socket_id], nullptr};
		sockets_shifts[socket_id] += sdp_data.metadata_worker_gc.size;
	}

	// Create buffers in shared memory for workers in numa nodes
	std::map<tSocketId, void*> sockets_buffers;
	for (auto [socket_id, size] : sockets_shifts)
	{
		std::string filename = common::sdp::FileNameWorkerOnNumaNode(socket_id);
		void* buffer = common::ipc::SharedMemory::CreateBuffer(filename, size, use_huge_tlb, socket_id);
		if (buffer == nullptr)
		{
			YANET_LOG_ERROR("Error create buffer in shared memory for workers on numa=%d, filename=%s, size=%ld",
			                socket_id,
			                filename.c_str(),
			                size);
			return eResult::errorInitSharedMemory;
		}
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
	//
	sdp_data.size_dataplane_buffer = YANET_SIZE_BUFFER_METADATA_DATAPLANE;

	// Fill bus info
	cBus::FillMetadataBusCounters(sdp_data.metadata_bus, sdp_data.size_dataplane_buffer);

	// Create buffer in shared memory for dataplane data
	sdp_data.dataplane_data = common::ipc::SharedMemory::CreateBuffer(YANET_SHARED_MEMORY_FILE_DATAPLANE,
	                                                                  sdp_data.size_dataplane_buffer,
	                                                                  use_huge_tlb,
	                                                                  std::nullopt);
	if (sdp_data.dataplane_data == nullptr)
	{
		YANET_LOG_ERROR("Error create buffer in shared memory for dataplane data, filename=%s, size=%ld",
		                YANET_SHARED_MEMORY_FILE_DATAPLANE,
		                sdp_data.size_dataplane_buffer);
		return eResult::errorInitSharedMemory;
	}

	// Write metadata info in dataplane data
	common::stream_out_t stream;
	sdp_data.WriteToStream(stream);
	uint64_t size_metadata = stream.getBuffer().size();
	YANET_LOG_DEBUG("Size of metadata in dataplane buffer: %ld\n", size_metadata);
	if (size_metadata + sizeof(uint64_t) > YANET_SIZE_BUFFER_METADATA_DATAPLANE)
	{
		YANET_LOG_ERROR("At least %ld bytes are required for data metadata, but only %d bytes are allocated\n",
		                size_metadata + sizeof(uint64_t),
		                YANET_SIZE_BUFFER_METADATA_DATAPLANE);
		return eResult::errorInitSharedMemory;
	}
	*(reinterpret_cast<uint64_t*>(sdp_data.dataplane_data)) = size_metadata;
	memcpy(common::sdp::ShiftBuffer<void*>(sdp_data.dataplane_data, sizeof(uint64_t)),
	       reinterpret_cast<const void*>(stream.getBuffer().data()),
	       size_metadata);

	return eResult::success;
}

uint64_t GetStartData(uint64_t size, uint64_t& current_start)
{
	static constexpr uint64_t cache_line_size = 64;
	uint64_t result = current_start;
	current_start += size;
	current_start = cache_line_size * ((current_start + cache_line_size - 1) / cache_line_size);
	return result;
}

} // namespace common::sdp
