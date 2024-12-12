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
			uint64_t size_mmap = 0;
			result = ReadItAgainMainFileDataplane(sdp_data, size_mmap, message_error);
			if (result == eResultRead::error)
			{
#ifdef YANET_USE_POSIX_SHARED_MEMORY
				YANET_LOG_ERROR("File %s. %s\n", YANET_SHARED_MEMORY_FILE_DATAPLANE, message_error.c_str());
#else
				YANET_LOG_ERROR("Key %d. %s\n", YANET_SHARED_MEMORY_KEY_DATAPLANE, message_error.c_str());
#endif
				sdp_data.UnmapBuffers(size_mmap);
				return eResult::errorInitSharedMemory;
			}
			else if (result == eResultRead::need_reread)
			{
				sdp_data.UnmapBuffers(size_mmap);
				if (number_of_attempts >= SHARED_MEMORY_REREAD_MAXIMUM_ATTEMPTS)
				{
#ifdef YANET_USE_POSIX_SHARED_MEMORY
					YANET_LOG_ERROR("File %s. Attempts were made to read: %d. %s\n",
					                YANET_SHARED_MEMORY_FILE_DATAPLANE,
					                number_of_attempts,
					                message_error.c_str());
#else
					YANET_LOG_ERROR("Key %d. Attempts were made to read: %d. %s\n",
					                YANET_SHARED_MEMORY_KEY_DATAPLANE,
					                number_of_attempts,
					                message_error.c_str());
#endif
					return eResult::errorInitSharedMemory;
				}
#ifdef YANET_USE_POSIX_SHARED_MEMORY
				YANET_LOG_WARNING("File %s. %s\n", YANET_SHARED_MEMORY_FILE_DATAPLANE, message_error.c_str());
#else
				YANET_LOG_WARNING("KEY %d. %s\n", YANET_SHARED_MEMORY_KEY_DATAPLANE, message_error.c_str());
#endif
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
#ifndef YANET_USE_POSIX_SHARED_MEMORY
		key_t key_shared_memory_segment = YANET_SHARED_MEMORY_KEY_DATAPLANE;
#endif
		for (auto& iter : sockets_buffer)
		{
#ifdef YANET_USE_POSIX_SHARED_MEMORY
			std::string filename = FileNameWorkerOnNumaNode(iter.first);
			auto [buffer, size] = common::ipc::SharedMemory::OpenBufferFile(filename, false);
			if (buffer == nullptr)
			{
				YANET_LOG_ERROR("Error openning shared memory buffer from file: %s\n", filename.c_str());
				return eResult::errorInitSharedMemory;
			}
#else
			key_shared_memory_segment++;
			auto [buffer, size] = common::ipc::SharedMemory::OpenBufferKey(key_shared_memory_segment, false);
			if (buffer == nullptr)
			{
				YANET_LOG_ERROR("Error openning shared memory buffer from segment: %d\n", key_shared_memory_segment);
				return eResult::errorInitSharedMemory;
			}
#endif
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
			iter.second.buffer = ShiftBuffer(buffer, shift);
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
			iter.second.buffer = ShiftBuffer(buffer, shift);
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
	static std::map<tCoreId, uint64_t> GetCounterByName(const DataPlaneInSharedMemory& sdp_data,
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
					auto* counters = ShiftBuffer<uint64_t*>(worker_info.buffer,
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
					auto* counters = ShiftBuffer<uint64_t*>(worker_info.buffer,
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
	static std::vector<uint64_t> GetCounters(const DataPlaneInSharedMemory& sdp_data,
	                                         const std::vector<tCounterId>& counter_ids)
	{
		std::vector<uint64_t> result(counter_ids.size());
		std::vector<uint64_t*> buffers;
		for (const auto& iter : sdp_data.workers)
		{
			buffers.push_back(ShiftBuffer<uint64_t*>(iter.second.buffer,
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
#ifdef YANET_USE_POSIX_SHARED_MEMORY
		auto [buffer, size] = common::ipc::SharedMemory::OpenBufferFile(YANET_SHARED_MEMORY_FILE_DATAPLANE, false);
#else
		auto [buffer, size] = common::ipc::SharedMemory::OpenBufferKey(YANET_SHARED_MEMORY_KEY_DATAPLANE, false);
#endif
		size_mmap = size;
		if (buffer == nullptr)
		{
			message = "File opening error";
			return eResultRead::error;
		}
		sdp_data.dataplane_data = buffer;

		// Compare size of buffer and size header of metadata dataplane
		if (size < common::sdp::DataPlaneInSharedMemory::size_header)
		{
			message = "Size of file " + std::to_string(size) + " < " +
			          std::to_string(common::sdp::DataPlaneInSharedMemory::size_header) + " size of header";
			return eResultRead::need_reread;
		}

		// WORKERS
		{
			sdp_data.workers.clear();
			sdp_data.workers_gc.clear();

			uint64_t start_workers = ReadValue(buffer, 0);
			uint64_t size_workers = ReadValue(buffer, 1);
			if ((start_workers + size_workers > size) || (2 * sizeof(uint64_t) > size_workers))
			{
				message = "Bad postion info section WORKERS";
				return eResultRead::need_reread;
			}
			uint64_t index = start_workers / sizeof(uint64_t);

			uint64_t count_workers = ReadValue(buffer, index++);
			uint64_t count_workers_gc = ReadValue(buffer, index++);
			if ((2 + 3 * (count_workers + count_workers_gc)) * sizeof(uint64_t) > size_workers)
			{
				message = "Size of section WORKERS < (2 + 3 * (count_workers + count_workers_gc)) * sizeof(uint64_t)";
				return eResultRead::need_reread;
			}

			for (uint64_t index_worker = 0; index_worker < count_workers; index_worker++)
			{
				uint64_t coreId = ReadValue(buffer, index++);
				tSocketId socket = ReadValue(buffer, index++);
				uint64_t shift_in_socket = ReadValue(buffer, index++);
				sdp_data.workers[coreId] = {socket, shift_in_socket, nullptr};
			}

			for (uint64_t index_worker = 0; index_worker < count_workers_gc; index_worker++)
			{
				uint64_t coreId = ReadValue(buffer, index++);
				tSocketId socket = ReadValue(buffer, index++);
				uint64_t shift_in_socket = ReadValue(buffer, index++);
				sdp_data.workers_gc[coreId] = {socket, shift_in_socket, nullptr};
			}
		}

		// WORKERS_METADATA
		{
			uint64_t start_workers_metadata = ReadValue(buffer, 2);
			uint64_t size_workers_metadata = ReadValue(buffer, 3);
			if ((start_workers_metadata + size_workers_metadata > size) || (size_workers_metadata < 128))
			{
				message = "Bad postion info section WORKERS_METADATA";
				return eResultRead::need_reread;
			}
			uint64_t index = start_workers_metadata / sizeof(uint64_t);

			// 0-5 - values from MetadataWorker
			sdp_data.metadata_worker.start_counters = ReadValue(buffer, index);
			sdp_data.metadata_worker.start_acl_counters = ReadValue(buffer, index + 1);
			sdp_data.metadata_worker.start_bursts = ReadValue(buffer, index + 2);
			sdp_data.metadata_worker.start_stats = ReadValue(buffer, index + 3);
			sdp_data.metadata_worker.start_stats_ports = ReadValue(buffer, index + 4);
			sdp_data.metadata_worker.size = ReadValue(buffer, index + 5);
			// 6 - n1 = size MetadataWorker.counter_positions
			uint64_t n1 = ReadValue(buffer, index + 6);
			// 7-9 - значения из MetadataWorker
			sdp_data.metadata_worker_gc.start_counters = ReadValue(buffer, index + 7);
			sdp_data.metadata_worker_gc.start_stats = ReadValue(buffer, index + 8);
			sdp_data.metadata_worker_gc.size = ReadValue(buffer, index + 9);
			// 10 - n2 = size MetadataWorker.counter_positions
			uint64_t n2 = ReadValue(buffer, index + 10);

			if (128 * (1 + n1 + n2) > size_workers_metadata)
			{
				message = "Size of section WORKERS_METADATA < 128 * (1 + n1 + n2)";
				return eResultRead::need_reread;
			}

			if (!ReadMap(sdp_data.metadata_worker.counter_positions, buffer, start_workers_metadata + 128, n1))
			{
				return eResultRead::need_reread;
			}
			if (!ReadMap(sdp_data.metadata_worker_gc.counter_positions, buffer, start_workers_metadata + 128 * (1 + n1), n2))
			{
				return eResultRead::need_reread;
			}
		}

		// BUS
		{
			sdp_data.start_bus_section = ReadValue(buffer, 4);
			sdp_data.size_bus_section = ReadValue(buffer, 5);
			if (sdp_data.start_bus_section + sdp_data.size_bus_section > size)
			{
				message = "Bad postion info section BUS";
				return eResultRead::need_reread;
			}
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

	static uint64_t ReadValue(void* buffer, uint64_t index)
	{
		auto* data = ShiftBuffer<uint8_t*>(buffer, index * sizeof(uint64_t));
		uint64_t result = 0;
		for (int i = 0; i < 8; i++)
		{
			result = 256 * result + data[i];
		}
		return result;
	}

	static bool ReadMap(std::map<std::string, uint64_t>& values, void* buffer, uint64_t shift, uint64_t count)
	{
		values.clear();
		for (uint64_t index = 0; index < count; index++)
		{
			void* current = ShiftBuffer(buffer, shift + 128 * index);
			uint64_t value = ReadValue(current, 0);
			char* str = ShiftBuffer<char*>(current, 8);
			if (str[119] != 0)
			{
				// 119 - index of last symbol
				return false;
			}
			std::string name = std::string(str);
			values[name] = value;
		}

		return true;
	}
};

} // namespace common::sdp
