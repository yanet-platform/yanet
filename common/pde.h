#pragma once

#include <rte_build_config.h>

#include <map>
#include <stdint.h>
#include <string>

#include "idp.h"
#include "result.h"
#include "shared_memory.h"
#include "type.h"

#define SHARED_FILENAME_MAIN "/yanet_main.shm"
#define SHARED_FILENAME_SOCKET_PREFIX "/yanet_socket_"

// processes_data_exchange
namespace common::pde
{

namespace
{

inline std::string GetNameOfSocketFileName(tSocketId socket_id)
{
	return SHARED_FILENAME_SOCKET_PREFIX + std::to_string(socket_id) + ".shm";
}

} // namespace

inline void* PtrAdd(void* buf, uint64_t count)
{
	return (char*)buf + count;
}

inline uint64_t* PtrAdd64(void* buf, uint64_t count)
{
	return (uint64_t*)((char*)buf + count);
}

inline uint64_t AllignToSizeCacheLine(uint64_t size)
{
	return (size + (RTE_CACHE_LINE_SIZE - 1)) / RTE_CACHE_LINE_SIZE * RTE_CACHE_LINE_SIZE;
}

class BufferWriter
{
public:
	BufferWriter(void* buffer, uint64_t total_size) :
	        total_size_(total_size), buffer_next_(buffer)
	{
	}

	static uint64_t Size(uint64_t size)
	{
		return AllignToSizeCacheLine((1 + size) * sizeof(uint64_t));
	}

	static uint64_t SizeOfStringIn64(const std::string& str)
	{
		// first byte - size of string
		return str.size() / 8 + 1;
	}

	void StartBlock(const char* block_name, uint64_t size)
	{
		if (total_size_ < size)
		{
			YANET_LOG_ERROR("BufferWriter::StartBlock: name=%s, size=%lu, total_size=%lu\n", block_name, size, total_size_);
		}
		else
		{
			total_size_ -= size;
		}
		block_name_ = block_name;
		buffer_current_ = buffer_next_;
		current_size_ = size;
		buffer_next_ = PtrAdd(buffer_next_, current_size_);
		Write64(size);
	}

	void Write64(uint64_t value)
	{
		if (current_size_ < sizeof(uint64_t))
		{
			YANET_LOG_ERROR("BufferWriter::Write64: name=%s, current_size_=%lu\n", block_name_, current_size_);
		}
		else
		{
			current_size_ -= sizeof(uint64_t);
		}
		*(uint64_t*)(buffer_current_) = value;
		buffer_current_ = PtrAdd(buffer_current_, 8);
	}
	void WriteString(const std::string& str)
	{
		uint64_t size = SizeOfStringIn64(str) * 8;

		if (current_size_ < size)
		{
			YANET_LOG_ERROR("BufferWriter::WriteString: name=%s, str=%s, current_size_=%lu, size=%lu\n", block_name_, str.data(), current_size_, size);
		}
		else
		{
			current_size_ -= size;
		}

		char* buf = (char*)buffer_current_;
		*buf = str.size();
		for (size_t index = 0; index < str.size(); ++index)
		{
			buf[index + 1] = str[index];
		}
		buffer_current_ = buf + size;
	}

private:
	uint64_t total_size_; // remaining size of full buffer

	// Current block info: buffer, remaining size, name, a pointer to the next one after the end
	void* buffer_current_;
	uint64_t current_size_ = 0;
	const char* block_name_;
	void* buffer_next_;
};

class BufferReader
{
public:
	BufferReader(void* buffer, uint64_t total_size) :
	        total_size_(total_size), buffer_next_(buffer)
	{
	}

	void StartBlock(const char* block_name)
	{
		if (total_size_ < sizeof(uint64_t))
		{
			YANET_LOG_ERROR("BufferReader::StartBlock: name=%s, total_size=%lu\n", block_name, total_size_);
		}
		else
		{
			total_size_ -= sizeof(uint64_t);
		}
		block_name_ = block_name;
		buffer_current_ = buffer_next_;
		current_size_ = sizeof(uint64_t);
		current_size_ = Read64();
		buffer_next_ = PtrAdd(buffer_next_, current_size_);
	}

	uint64_t Read64()
	{
		if (current_size_ < sizeof(uint64_t))
		{
			YANET_LOG_ERROR("BufferReader::Read64: name=%s, current_size_=%lu\n", block_name_, current_size_);
		}
		else
		{
			current_size_ -= sizeof(uint64_t);
		}
		uint64_t result = *(uint64_t*)buffer_current_;
		buffer_current_ = PtrAdd(buffer_current_, 8);
		return result;
	}

	std::string ReadString()
	{
		if (current_size_ == 0)
		{
			YANET_LOG_ERROR("BufferReader::ReadString: name=%s, current_size_=%lu\n", block_name_, current_size_);
		}
		char* buffer = (char*)buffer_current_;
		uint64_t size = (uint8_t)*buffer;

		uint64_t str_size = (size / 8 + 1) * sizeof(uint64_t);
		if (current_size_ < str_size)
		{
			YANET_LOG_ERROR("BufferWriter::WriteString: name=%s, current_size_=%lu, size=%lu\n", block_name_, current_size_, str_size);
		}
		else
		{
			current_size_ -= str_size;
		}

		std::string result;
		result.reserve(size);
		for (uint64_t index = 0; index < size; ++index)
		{
			result.push_back(buffer[index + 1]);
		}
		buffer_current_ = buffer + str_size;
		return result;
	}

private:
	uint64_t total_size_; // remaining size of full buffer

	// Current block info: buffer, remaining size, name, a pointer to the next one after the end
	void* buffer_current_;
	uint64_t current_size_ = 0;
	const char* block_name_;
	void* buffer_next_;
};

struct MetadataWorker
{
	uint64_t start_counters;
	uint64_t start_acl_counters;
	uint64_t start_bursts;
	uint64_t start_stats;
	uint64_t start_stats_ports;

	uint64_t total_size; // size of all data from this structure

	std::map<std::string, uint64_t> counter_positions;

	uint64_t Size()
	{
		uint64_t size_of_names = 0;
		for (const auto& iter : counter_positions)
		{
			size_of_names += BufferWriter::SizeOfStringIn64(iter.first);
		}
		// 6 start positions + map (1 (size) + size (values) + size_of_names)
		return BufferWriter::Size(6 + 1 + counter_positions.size() + size_of_names);
	}

	void WriteToBuffer(BufferWriter& writer)
	{
		writer.StartBlock("MetadataWorker", Size());

		writer.Write64(start_counters);
		writer.Write64(start_acl_counters);
		writer.Write64(start_bursts);
		writer.Write64(start_stats);
		writer.Write64(start_stats_ports);
		writer.Write64(total_size);

		writer.Write64(counter_positions.size());
		for (const auto& iter : counter_positions)
		{
			writer.WriteString(iter.first);
			writer.Write64(iter.second);
		}
	}

	void ReadFromBuffer(BufferReader& reader)
	{
		reader.StartBlock("MetadataWorker");

		start_counters = reader.Read64();
		start_acl_counters = reader.Read64();
		start_bursts = reader.Read64();
		start_stats = reader.Read64();
		start_stats_ports = reader.Read64();
		total_size = reader.Read64();

		uint64_t size_positions = reader.Read64();
		for (uint64_t index = 0; index < size_positions; ++index)
		{
			std::string name = reader.ReadString();
			uint64_t value = reader.Read64();
			counter_positions[name] = value;
		}

		UpdateIndexes();
	}

	uint64_t index_counters;
	uint64_t index_acl_counters;
	uint64_t index_bursts;
	uint64_t index_stats_ports;
	void UpdateIndexes()
	{
		index_counters = start_counters / sizeof(uint64_t);
		index_acl_counters = start_acl_counters / sizeof(uint64_t);
		index_bursts = start_bursts / sizeof(uint64_t);
		index_stats_ports = start_stats_ports / sizeof(uint64_t);
	}
};

struct MetadataWorkerGc
{
	uint64_t start_counters;
	uint64_t start_stats;

	uint64_t total_size;

	std::map<std::string, uint64_t> counter_positions;

	uint64_t Size()
	{
		uint64_t size_of_names = 0;
		for (const auto& iter : counter_positions)
		{
			size_of_names += BufferWriter::SizeOfStringIn64(iter.first);
		}
		// 3 start positions + map (1 (size) + size (values) + size_of_names)
		return BufferWriter::Size(3 + 1 + counter_positions.size() + size_of_names);
	}

	void WriteToBuffer(BufferWriter& writer)
	{
		writer.StartBlock("MetadataWorkerGc", Size());

		writer.Write64(start_counters);
		writer.Write64(start_stats);
		writer.Write64(total_size);

		writer.Write64(counter_positions.size());
		for (const auto& iter : counter_positions)
		{
			writer.WriteString(iter.first);
			writer.Write64(iter.second);
		}
	}

	void ReadFromBuffer(BufferReader& reader)
	{
		reader.StartBlock("MetadataWorkerGc");

		start_counters = reader.Read64();
		start_stats = reader.Read64();
		total_size = reader.Read64();

		uint64_t size_positions = reader.Read64();
		for (uint64_t index = 0; index < size_positions; ++index)
		{
			std::string name = reader.ReadString();
			uint64_t value = reader.Read64();
			counter_positions[name] = value;
		}

		index_counters = start_counters / sizeof(uint64_t);
	}

	uint64_t index_counters;
};

struct MetadataCommonCounters
{
	uint64_t start_bus_errors;
	uint64_t start_bus_requests;
	uint64_t start_bus_durations;

	uint64_t Size()
	{
		return BufferWriter::Size(3);
	}

	uint64_t Initialize(uint64_t start)
	{
		start_bus_errors = start;
		start += AllignToSizeCacheLine(static_cast<uint64_t>(common::idp::errorType::size) * sizeof(uint64_t));
		start_bus_requests = start;
		start += AllignToSizeCacheLine(static_cast<uint64_t>(common::idp::requestType::size) * sizeof(uint64_t));
		start_bus_durations = start;
		start += AllignToSizeCacheLine(static_cast<uint64_t>(common::idp::requestType::size) * sizeof(uint64_t));
		return start;
	}

	void WriteToBuffer(BufferWriter& writer)
	{
		writer.StartBlock("MetadataCommonCounters", Size());
		writer.Write64(start_bus_errors);
		writer.Write64(start_bus_requests);
		writer.Write64(start_bus_durations);
	}

	void ReadFromBuffer(BufferReader& reader)
	{
		reader.StartBlock("MetadataCommonCounters");
		start_bus_errors = reader.Read64();
		start_bus_requests = reader.Read64();
		start_bus_durations = reader.Read64();
	}
};

struct CommonData
{
	struct OneWorkerInfo
	{
		tSocketId socket_id;
		uint64_t start_at_memory;
		void* buffer;
	};

	void* main_buffer = nullptr;
	std::map<tSocketId, void*> sockets;
	std::map<tCoreId, OneWorkerInfo> workers;
	std::map<tCoreId, OneWorkerInfo> workers_gc;

	void* BufferWorker(tCoreId core_id) const
	{
		auto iter = workers.find(core_id);
		if (iter == workers.end())
		{
			YANET_LOG_ERROR("Try get buffer for unknown worker: %d\n", core_id);
			return nullptr;
		}
		return iter->second.buffer;
	}

	void* BufferWorkerGc(tCoreId core_id) const
	{
		auto iter = workers_gc.find(core_id);
		if (iter == workers_gc.end())
		{
			YANET_LOG_ERROR("Try get buffer for unknown worker_gc: %d\n", core_id);
			return nullptr;
		}
		return iter->second.buffer;
	}

	uint64_t Size()
	{
		// number of workers, workers_gc - 1 + 1
		// for each worker 3 values - core_id, socket_id, start_at_memory
		return BufferWriter::Size(1 + 1 + 3 * (workers.size() + workers_gc.size()));
	}

	void WriteToBuffer(BufferWriter& writer)
	{
		writer.StartBlock("CommonData", Size());
		writer.Write64(workers.size());
		writer.Write64(workers_gc.size());
		for (auto [core_id, worker_info] : workers)
		{
			writer.Write64(core_id);
			writer.Write64(worker_info.socket_id);
			writer.Write64(worker_info.start_at_memory);
		}
		for (auto [core_id, worker_info] : workers_gc)
		{
			writer.Write64(core_id);
			writer.Write64(worker_info.socket_id);
			writer.Write64(worker_info.start_at_memory);
		}
	}
	void ReadFromBuffer(BufferReader& reader)
	{
		reader.StartBlock("CommonData");
		uint64_t count_workers = reader.Read64();
		uint64_t count_workers_gc = reader.Read64();

		for (uint64_t index = 0; index < count_workers; ++index)
		{
			uint64_t core_id = reader.Read64();
			tSocketId socket_id = reader.Read64();
			uint64_t start_at_memory = reader.Read64();
			workers[core_id] = {socket_id, start_at_memory, nullptr};
			sockets[socket_id] = nullptr;
		}

		for (uint64_t index = 0; index < count_workers_gc; ++index)
		{
			uint64_t core_id = reader.Read64();
			tSocketId socket_id = reader.Read64();
			uint64_t start_at_memory = reader.Read64();
			workers_gc[core_id] = {socket_id, start_at_memory, nullptr};
			sockets[socket_id] = nullptr;
		}
	}

	eResult FillWorkers(const std::map<tCoreId, tSocketId>& workers_to_sockets,
	                    const std::map<tCoreId, tSocketId>& workers_gc_to_sockets,
	                    size_t size_worker,
	                    size_t size_worker_gc,
	                    bool useHugeMem)
	{
		// Calculate sizes for each socket
		std::map<tSocketId, size_t> sizes_by_sockets;
		for (auto [core_id, socket_id] : workers_to_sockets)
		{
			workers[core_id] = {socket_id, sizes_by_sockets[socket_id], nullptr};
			sizes_by_sockets[socket_id] += size_worker;
		}
		for (auto [core_id, socket_id] : workers_gc_to_sockets)
		{
			workers_gc[core_id] = {socket_id, sizes_by_sockets[socket_id], nullptr};
			sizes_by_sockets[socket_id] += size_worker_gc;
		}

		// Create shared memory files by sockets
		for (auto [socket_id, size] : sizes_by_sockets)
		{
			std::string fname = GetNameOfSocketFileName(socket_id);
			void* buffer = SharedMemory::CreateBufferInSharedMemory(fname.c_str(), size, useHugeMem, true, socket_id);
			if (buffer == nullptr)
			{
				return eResult::errorInitSharedMemory;
			}
			sockets[socket_id] = buffer;
		}

		// Set buffers for workers
		for (auto [core_id, socket_id] : workers_to_sockets)
		{
			workers[core_id].buffer = PtrAdd(sockets[socket_id], workers[core_id].start_at_memory);
		}
		for (auto [core_id, socket_id] : workers_gc_to_sockets)
		{
			workers_gc[core_id].buffer = PtrAdd(sockets[socket_id], workers_gc[core_id].start_at_memory);
		}

		return eResult::success;
	}
};

struct MainFileData
{
	CommonData common_data;
	MetadataWorker metadata_workers;
	MetadataWorkerGc metadata_workers_gc;
	MetadataCommonCounters common_counters;

	eResult BuildFromDataPlane(const std::map<tCoreId, tSocketId>& workers_to_sockets,
	                           const std::map<tCoreId, tSocketId>& workers_gc_to_sockets,
	                           bool useHugeMem)
	{
		// Fill common data
		eResult result = common_data.FillWorkers(workers_to_sockets, workers_gc_to_sockets, metadata_workers.total_size, metadata_workers_gc.total_size, useHugeMem);
		if (result != eResult::success)
		{
			return result;
		}

		// Calculate total size main buffer
		uint64_t total_size = common_data.Size() + metadata_workers.Size() + metadata_workers_gc.Size() +
		                      common_counters.Size();
		total_size = common_counters.Initialize(total_size);
		YANET_LOG_WARNING("MainFileData::BuildFromDataPlane size main buffer: %lu\n", total_size);

		// Create main buffer
		common_data.main_buffer = SharedMemory::CreateBufferInSharedMemory(SHARED_FILENAME_MAIN, total_size, useHugeMem, false, 0);
		if (common_data.main_buffer == nullptr)
		{
			return eResult::errorInitSharedMemory;
		}

		// Write all data to main buffer
		BufferWriter writer(common_data.main_buffer, total_size);
		common_data.WriteToBuffer(writer);
		metadata_workers.WriteToBuffer(writer);
		metadata_workers_gc.WriteToBuffer(writer);
		common_counters.WriteToBuffer(writer);

		return eResult::success;
	}

	eResult ReadFromDataplane(bool useHugeMem, bool open_sockets_file)
	{
		YANET_LOG_WARNING("MainFileData::ReadFromDataplane start, open_sockets_file=%d\n", int(open_sockets_file));
		uint64_t size;
		common_data.main_buffer = SharedMemory::OpenBufferInSharedMemory(SHARED_FILENAME_MAIN, false, useHugeMem, &size);
		if (common_data.main_buffer == nullptr)
		{
			return eResult::errorInitSharedMemory;
		}

		BufferReader reader(common_data.main_buffer, size);
		common_data.ReadFromBuffer(reader);
		metadata_workers.ReadFromBuffer(reader);
		metadata_workers_gc.ReadFromBuffer(reader);
		common_counters.ReadFromBuffer(reader);

		if (open_sockets_file)
		{
			for (auto& iter : common_data.sockets)
			{
				std::string fname = GetNameOfSocketFileName(iter.first);
				iter.second = SharedMemory::OpenBufferInSharedMemory(fname.c_str(), false, useHugeMem, &size);
			}
			for (auto& iter : common_data.workers)
			{
				iter.second.buffer = PtrAdd(common_data.sockets[iter.second.socket_id], iter.second.start_at_memory);
			}
			for (auto& iter : common_data.workers_gc)
			{
				iter.second.buffer = PtrAdd(common_data.sockets[iter.second.socket_id], iter.second.start_at_memory);
			}
		}
		YANET_LOG_WARNING("MainFileData::ReadFromDataplane finish, size=%ld\n", size);

		return eResult::success;
	}

	uint64_t* BufferCommonCounters(uint64_t start) const
	{
		return PtrAdd64(common_data.main_buffer, start);
	}

	std::map<tCoreId, uint64_t> GetCounterByName(const std::string& counter_name, std::optional<tCoreId> core_id) const
	{
		std::map<tCoreId, uint64_t> result;

		const auto& iter_workers = metadata_workers.counter_positions.find(counter_name);
		if (iter_workers != metadata_workers.counter_positions.end())
		{
			uint64_t index = iter_workers->second + metadata_workers.index_counters;
			for (const auto& [worker_core_id, worker_info] : common_data.workers)
			{
				if (core_id == std::nullopt || worker_core_id == core_id)
				{
					result[worker_core_id] = ((uint64_t*)worker_info.buffer)[index];
				}
			}
		}

		const auto& iter_workers_gc = metadata_workers_gc.counter_positions.find(counter_name);
		if (iter_workers_gc != metadata_workers_gc.counter_positions.end())
		{
			uint64_t index = iter_workers_gc->second + metadata_workers_gc.index_counters;
			for (const auto& [worker_core_id, worker_info] : common_data.workers_gc)
			{
				if (core_id == std::nullopt || worker_core_id == core_id)
				{
					result[worker_core_id] = ((uint64_t*)worker_info.buffer)[index];
				}
			}
		}

		return result;
	}

	std::vector<uint64_t> GetCounters(const std::vector<tCounterId>& counter_ids) const
	{
		std::vector<uint64_t> result(counter_ids.size());
		std::vector<uint64_t*> buffers;
		for (const auto& iter : common_data.workers)
		{
			buffers.push_back(PtrAdd64(iter.second.buffer, metadata_workers.start_counters));
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
};

} // namespace common::pde
