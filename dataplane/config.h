#pragma once

#include "common/define.h"
#include "common/type.h"
#include "rte_ethdev.h"
#include <set>
#include <string>

using InterfaceName = std::string;

struct CPlaneWorkerConfig
{
	std::set<InterfaceName> interfaces;
	std::set<tCoreId> workers;
	std::set<tCoreId> gcs;
};

struct tDataPlaneConfig
{
	enum class DumpFormat
	{
		kRaw,
		kPcap
	};

	struct DumpConfig
	{
		unsigned int size;
		unsigned int count;
		DumpFormat format;
	};

	static DumpFormat StringToDumpFormat(const std::string& format_str)
	{
		if (format_str == "raw")
			return DumpFormat::kRaw;
		else if (format_str == "pcap")
			return DumpFormat::kPcap;

		YANET_LOG_WARNING("Invalid dump format %s, will use raw format", format_str.data());
		return DumpFormat::kRaw;
	}

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
	uint64_t rssFlags = RTE_ETH_RSS_IP;
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
			YANET_GCC_BUG_UNUSED(_);
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
