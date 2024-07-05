#pragma once

#include <thread>

#include "result.h"
#include "sdpcommon.h"
#include "shared_memory.h"

#define SHARED_MEMORY_REREAD_TIMEOUT_MICROSECONDS 100
#define SHARED_MEMORY_REREAD_MAXIMUM_ATTEMPTS 100

namespace common::sdp
{

class SdpClient
{
public:
	/*
	 * The function opens buffers created in Dataplane in shared memory and fills in the necessary fields in the
	 * DataPlaneInSharedMemory structure
	 * Params:
	 * sdp_data - the Data Plane In Shared Memory object contains data about connection to shared memory buffers
	 * open_workers_data - if false, only the main file is opened, if true, files with workers counters on
	 *                     different numa nodes are also opened
	 * Returns: result::success if successful, in case of error hresult::error InitSharedMemory
	 */
	[[nodiscard]] static eResult ReadSharedMemoryData(DataPlaneInSharedMemory& sdp_data, bool open_workers_data)
	{
		// Read main file
		int number_of_attempts = 0;
		eResultRead result = eResultRead::need_reread;
		while (result != eResultRead::ok)
		{
			number_of_attempts++;
			std::string message_error;
			uint64_t size_mmap;
			result = ReadItAgainMainFileDataplane(sdp_data, size_mmap, message_error);
			if (result == eResultRead::error)
			{
				YANET_LOG_ERROR("File %s. %s\n", YANET_SHARED_MEMORY_FILE_DATAPLANE, message_error.c_str());
				sdp_data.UnmapBuffers(size_mmap);
				return eResult::errorInitSharedMemory;
			}
			else if (result == eResultRead::need_reread)
			{
				sdp_data.UnmapBuffers(size_mmap);
				if (number_of_attempts >= SHARED_MEMORY_REREAD_MAXIMUM_ATTEMPTS)
				{
					YANET_LOG_ERROR("File %s. Attempts were made to read: %d. %s\n",
					                YANET_SHARED_MEMORY_FILE_DATAPLANE,
					                number_of_attempts,
					                message_error.c_str());
					return eResult::errorInitSharedMemory;
				}
				YANET_LOG_WARNING("File %s. %s\n", YANET_SHARED_MEMORY_FILE_DATAPLANE, message_error.c_str());
				std::this_thread::sleep_for(std::chrono::microseconds{SHARED_MEMORY_REREAD_TIMEOUT_MICROSECONDS});
			}
		}

		if (!open_workers_data)
		{
			return eResult::success;
		}

		// Read workers files

		// Get all sockets
		std::map<tSocketId, std::pair<void*, uint64_t>> sockets_buffer;
		for (const auto& iter : sdp_data.workers)
		{
			sockets_buffer[iter.second.socket] = {nullptr, 0};
		}
		for (const auto& iter : sdp_data.workers_gc)
		{
			sockets_buffer[iter.second.socket] = {nullptr, 0};
		}

		// Open buffers for each socket
		for (auto& iter : sockets_buffer)
		{
			std::string filename = FileNameWorkerOnNumaNode(iter.first);
			auto [buffer, size] = common::ipc::SharedMemory::OpenBuffer(filename, false);
			if (buffer == nullptr)
			{
				YANET_LOG_ERROR("Error openning shared memory buffer from file: %s\n", filename.c_str());
				return eResult::errorInitSharedMemory;
			}
			iter.second = {buffer, size};
		}

		// Set buffers for workers
		for (auto& iter : sdp_data.workers)
		{
			uint64_t shift = iter.second.shift_in_socket;
			auto [buffer, size] = sockets_buffer[iter.second.socket];
			if (shift + sdp_data.metadata_worker.size > size)
			{
				YANET_LOG_ERROR("Error in file for socket: %d, file size: %ld, worker: %d, metadata_worker.size: %ld, shift: %ld\n",
				                iter.second.socket,
				                size,
				                iter.first,
				                sdp_data.metadata_worker.size,
				                shift);
				return eResult::errorInitSharedMemory;
			}
			iter.second.buffer = ShiftBuffer<void*>(buffer, shift);
		}
		for (auto& iter : sdp_data.workers_gc)
		{
			uint64_t shift = iter.second.shift_in_socket;
			auto [buffer, size] = sockets_buffer[iter.second.socket];
			if (shift + sdp_data.metadata_worker_gc.size > size)
			{
				YANET_LOG_ERROR("Error in file for socket: %d, file size: %ld, worker: %d, metadata_worker_gc.size: %ld, shift: %ld\n",
				                iter.second.socket,
				                size,
				                iter.first,
				                sdp_data.metadata_worker_gc.size,
				                shift);
				return eResult::errorInitSharedMemory;
			}
			iter.second.buffer = ShiftBuffer<void*>(buffer, shift);
		}

		return eResult::success;
	}

	/*
	 * The counter name function gets its value on workers.
	 * Params:
	 * - sdp_data - the Data Plane In Shared Memory object contains data about connection to shared memory buffers
	 * - counter_name - the name of the counter
	 * - core_id is the id of the core on which the worker is running for which it need to get the counter value,
	 *   if it passed std::nullopt, then it gets from all workers
	 * Return: The counter value for each core
	 */
	static std::map<tCoreId, uint64_t> GetCounterByName(DataPlaneInSharedMemory& sdp_data,
	                                                    const std::string& counter_name,
	                                                    std::optional<tCoreId> core_id)
	{
		std::map<tCoreId, uint64_t> result;

		// Find counter in workers
		const auto& iter_workers = sdp_data.metadata_worker.counter_positions.find(counter_name);
		if (iter_workers != sdp_data.metadata_worker.counter_positions.end())
		{
			uint64_t index = iter_workers->second;
			for (const auto& [worker_core_id, worker_info] : sdp_data.workers)
			{
				if (!core_id.has_value() || worker_core_id == core_id)
				{
					uint64_t* counters = common::sdp::ShiftBuffer<uint64_t*>(worker_info.buffer,
					                                                         sdp_data.metadata_worker.start_counters);
					result[worker_core_id] = counters[index];
				}
			}
		}

		// Find counter in workers_gc
		const auto& iter_workers_gc = sdp_data.metadata_worker_gc.counter_positions.find(counter_name);
		if (iter_workers_gc != sdp_data.metadata_worker_gc.counter_positions.end())
		{
			uint64_t index = iter_workers_gc->second;
			for (const auto& [worker_core_id, worker_info] : sdp_data.workers_gc)
			{
				if (!core_id.has_value() || worker_core_id == core_id)
				{
					uint64_t* counters = common::sdp::ShiftBuffer<uint64_t*>(worker_info.buffer,
					                                                         sdp_data.metadata_worker.start_counters);
					result[worker_core_id] = counters[index];
				}
			}
		}

		return result;
	}

	/*
	 * The function works like the previous one, but it opens buffers in shared memory by itself. In case of
	 *  an opening error, it calls exit().
	 */
	static std::map<tCoreId, uint64_t> GetCounterByName(const std::string& counter_name,
	                                                    std::optional<tCoreId> core_id)
	{
		DataPlaneInSharedMemory sdp_data;
		if (ReadSharedMemoryData(sdp_data, true) != eResult::success)
		{
			std::exit(1);
		}
		return GetCounterByName(sdp_data, counter_name, core_id);
	}

	/*
	 * The function for each counter ID gets the sum of the values for it from all workers
	 * Params:
	 * - sdp_data - the Data Plane In Shared Memory object contains data about connection to shared memory buffers
	 * - counter_ids - counter IDs
	 * Return: Aggregated counter values
	 */
	static std::vector<uint64_t> GetCounters(DataPlaneInSharedMemory& sdp_data,
	                                         const std::vector<tCounterId>& counter_ids)
	{
		std::vector<uint64_t> result(counter_ids.size());
		std::vector<uint64_t*> buffers;
		for (const auto& iter : sdp_data.workers)
		{
			buffers.push_back(common::sdp::ShiftBuffer<uint64_t*>(iter.second.buffer,
			                                                      sdp_data.metadata_worker.start_counters));
		}

		for (size_t i = 0; i < counter_ids.size(); i++)
		{
			auto counter_id = counter_ids[i];
			if (counter_id >= YANET_CONFIG_COUNTERS_SIZE)
			{
				continue;
			}

			uint64_t counter = 0;
			for (const auto& buffer : buffers)
			{
				counter += buffer[counter_id];
			}

			result[i] = counter;
		}

		return result;
	}

	/*
	 * The function works like the previous one, but it opens buffers in shared memory by itself. In case of
	 *  an opening error, it calls exit().
	 */
	static std::vector<uint64_t> GetCounters(const std::vector<tCounterId>& counter_ids)
	{
		DataPlaneInSharedMemory sdp_data;
		if (ReadSharedMemoryData(sdp_data, true) != eResult::success)
		{
			std::exit(1);
		}
		return GetCounters(sdp_data, counter_ids);
	}

private:
	enum class eResultRead : uint8_t
	{
		ok,
		need_reread,
		error
	};

	static eResultRead ReadMainFileDataplane(DataPlaneInSharedMemory& sdp_data, uint64_t& size_mmap, std::string& message)
	{
		// Try open buffer
		auto [buffer, size] = common::ipc::SharedMemory::OpenBuffer(YANET_SHARED_MEMORY_FILE_DATAPLANE, false);
		size_mmap = size;
		if (buffer == nullptr)
		{
			message = "File opening error";
			return eResultRead::error;
		}
		sdp_data.dataplane_data = buffer;

		// Compare size of buffer and default size block of metadata dataplane
		if (size < YANET_SIZE_BUFFER_METADATA_DATAPLANE)
		{
			message = "Size of file " + std::to_string(size) + " < " +
			          std::to_string(YANET_SIZE_BUFFER_METADATA_DATAPLANE) + " size of metadata buffer";
			return eResultRead::need_reread;
		}

		// Read metadata
		uint64_t size_metadata = *(reinterpret_cast<uint64_t*>(buffer));
		if (size_metadata + sizeof(uint64_t) > YANET_SIZE_BUFFER_METADATA_DATAPLANE)
		{
			message = "Size metadata: " + std::to_string(size_metadata) + " for size of buffer: " + std::to_string(YANET_SIZE_BUFFER_METADATA_DATAPLANE);
			return eResultRead::need_reread;
		}

		uint8_t* buffer_metadata = common::sdp::ShiftBuffer<uint8_t*>(buffer, sizeof(uint64_t));
		std::vector<uint8_t> buffer_for_stream(size_metadata);
		memcpy(buffer_for_stream.data(), buffer_metadata, size_metadata);
		common::stream_in_t stream(buffer_for_stream);
		if (!sdp_data.ReadFromStream(stream))
		{
			message = "Error read metadata structure";
			return eResultRead::need_reread;
		}

		if (sdp_data.size_dataplane_buffer > size)
		{
			message = "Size data in metadata: " + std::to_string(sdp_data.size_dataplane_buffer) + ", but buffer size: " + std::to_string(size);
			return eResultRead::need_reread;
		}

		return eResultRead::ok;
	}

	static eResultRead ReadItAgainMainFileDataplane(DataPlaneInSharedMemory& sdp_data, uint64_t& size_mmap, std::string& message)
	{
		// First read
		DataPlaneInSharedMemory tmp_data;
		eResultRead result = ReadMainFileDataplane(tmp_data, size_mmap, message);
		tmp_data.UnmapBuffers(size_mmap);
		if (result != eResultRead::ok)
		{
			return result;
		}

		// Sleep
		std::this_thread::sleep_for(std::chrono::microseconds{SHARED_MEMORY_REREAD_TIMEOUT_MICROSECONDS});

		// Second read
		result = ReadMainFileDataplane(sdp_data, size_mmap, message);
		if (result != eResultRead::ok)
		{
			return result;
		}
		else if (!(sdp_data == tmp_data))
		{
			message = "The data changed during the re-reading";
			return eResultRead::need_reread;
		}

		return eResultRead::ok;
	}
};

} // namespace common::sdp
