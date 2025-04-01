#pragma once

#include "common/define.h"
#include "common/type.h"
#include <set>
#include <string>

using InterfaceName = std::string;

struct tDataPlaneConfig
{
	enum class DumpFormat
	{
		kRaw,
		kPcap
	};

	// TODO: add here path, prefix, pcap files count? like std::variant if format == pcap?
	struct DumpConfig
	{
		DumpFormat format;
		unsigned int size;
		unsigned int count;

		DumpConfig() :
		        format(DumpFormat::kRaw), size(0), count(0)
		{
		}

		DumpConfig(std::string_view format_str, unsigned int size, unsigned int count) :
		        format(StringToDumpFormat(format_str)), size(size), count(count)
		{
		}

		// TODO: temporary, adjust after we refactor cli?
		[[nodiscard]] std::string ToString() const
		{
			return DumpFormatToString(format) + " " + std::to_string(size) + " " + std::to_string(count);
		}
	};

	static DumpFormat StringToDumpFormat(std::string_view format_str)
	{
		if (format_str == "raw")
			return DumpFormat::kRaw;
		else if (format_str == "pcap")
			return DumpFormat::kPcap;

		YANET_LOG_WARNING("Invalid dump format %s, will use raw format", format_str.data());
		return DumpFormat::kRaw;
	}

	static std::string DumpFormatToString(DumpFormat format)
	{
		switch (format)
		{
			case DumpFormat::kRaw:
				return "raw";
			case DumpFormat::kPcap:
				return "pcap";
			default:
				YANET_THROW("Invalid dump format");
				std::abort();
		}
	}

	struct DumpRingDesc
	{
		// Denotes ring within a worker
		std::string tag;
		// Denotes a worker
		tCoreId core_id;
		tSocketId socket_id;

		SERIALIZABLE(tag, core_id, socket_id);
	};

	/*
	   DPDK ports used by `dataplane`.
	   Each port has a name with which is exposed into host system
	   and an identifier (typically pci id) used to lookup the port within
	   DPDK.
	*/
	std::map<InterfaceName,
	         std::tuple<std::string, ///< pci
	                    std::string, ///< name
	                    bool, ///< symmetric_mode
	                    uint64_t ///< rssFlags
	                    >>
	        ports;

	std::set<tCoreId> workerGCs;
	tCoreId controlPlaneCoreId;
	std::map<tCoreId, std::set<tCoreId>> controlplane_workers;
	std::map<tCoreId, std::vector<InterfaceName>> workers;
	bool useHugeMem = true;
	bool use_kernel_interface = true;
	bool interfaces_required = true;
	uint32_t SWNormalPriorityRateLimitPerWorker = 0;
	uint32_t SWICMPOutRateLimit = 0;
	uint32_t rateLimitDivisor = 1;
	std::string memory;
	std::map<std::string, DumpConfig> shared_memory;

	std::vector<std::string> ealArgs;
	std::set<InterfaceName> WorkersInterfaces(std::set<tCoreId> cores)
	{
		std::set<InterfaceName> ifaces;
		for (auto core : cores)
		{
			auto worker = workers.at(core);
			ifaces.insert(worker.begin(), worker.end());
		}
		return ifaces;
	}
	std::map<InterfaceName, tQueueId> VdevQueues()
	{
		std::map<InterfaceName, tQueueId> total;
		for (auto& [_, cores] : controlplane_workers)
		{
			GCC_BUG_UNUSED(_);
			std::set<InterfaceName> ifaces;
			for (auto core : cores)
			{
				const auto& w = workers.at(core);
				ifaces.insert(w.begin(), w.end());
			}
			for (auto& iface : ifaces)
			{
				++total[iface];
			}
		}
		return total;
	}
};
