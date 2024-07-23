#pragma once

#include <arpa/inet.h>
#include <pthread.h>

#include <map>
#include <string>
#include <vector>

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <nlohmann/json.hpp>

#include "common/idp.h"
#include "common/result.h"
#include "common/type.h"

#include "bus.h"
#include "config_values.h"
#include "controlplane.h"
#include "globalbase.h"
#include "memory_manager.h"
#include "neighbor.h"
#include "report.h"
#include "type.h"
#include "worker_gc.h"

struct tDataPlaneConfig
{
	/*
	   DPDK ports used by `dataplane`.
	   Each port has a name with which is exposed into host system
	   and an identifier (typically pci id) used to lookup the port within
	   DPDK.
	*/
	std::map<std::string, ///< interfaceName
	         std::tuple<std::string, ///< pci
	                    std::string, ///< name
	                    bool, ///< symmetric_mode
	                    uint64_t ///< rssFlags
	                    >>
	        ports;

	std::set<tCoreId> workerGCs;
	tCoreId controlPlaneCoreId;
	std::map<tCoreId, std::vector<std::string>> workers;
	bool useHugeMem = true;
	bool use_kernel_interface = true;
	bool interfaces_required = true;
	uint64_t rssFlags = RTE_ETH_RSS_IP;
	uint32_t SWNormalPriorityRateLimitPerWorker = 0;
	uint32_t SWICMPOutRateLimit = 0;
	uint32_t rateLimitDivisor = 1;
	std::string memory;
	std::map<std::string, std::tuple<unsigned int, unsigned int>> shared_memory;

	std::vector<std::string> ealArgs;
};

class hugepage_pointer
{
public:
	hugepage_pointer(const size_t size,
	                 const std::function<void()>& destructor) :
	        size(size),
	        destructor(destructor)
	{
	}

	~hugepage_pointer()
	{
		destructor();
	}

public:
	size_t size;
	std::function<void()> destructor;
};

class cDataPlane
{
public:
	cDataPlane();
	~cDataPlane();

	eResult init(const std::string& binaryPath,
	             const std::string& configFilePath);

	void start();
	void join();

	const ConfigValues& getConfigValues() const { return configValues; }
	std::map<std::string, common::uint64> getPortStats(const tPortId& portId) const;
	std::optional<tPortId> interface_name_to_port_id(const std::string& interface_name);
	const std::set<tSocketId>& get_socket_ids() const;
	const std::vector<cWorker*>& get_workers() const;
	void run_on_worker_gc(const tSocketId socket_id, const std::function<bool()>& callback);

	void switch_worker_base();

	inline uint32_t get_current_time() const
	{
		return current_time;
	}

protected:
	eResult parseConfig(const std::string& configFilePath);
	eResult parseJsonPorts(const nlohmann::json& json);
	eResult parseConfigValues(const nlohmann::json& json);
	eResult parseRateLimits(const nlohmann::json& json);
	eResult parseSharedMemory(const nlohmann::json& json);
	eResult checkConfig();

	eResult initEal(const std::string& binaryPath, const std::string& filePrefix);
	eResult initPorts();
	eResult initRingPorts();
	eResult initGlobalBases();
	eResult initWorkers();
	eResult initQueues();
	void init_worker_base();

	eResult allocateSharedMemory();
	eResult splitSharedMemoryPerWorkers();

	std::optional<uint64_t> getCounterValueByName(const std::string& counter_name, uint32_t coreId);
	common::idp::get_shm_info::response getShmInfo();
	common::idp::get_shm_tsc_info::response getShmTscInfo();

	static int lcoreThread(void* args);
	void timestamp_thread();

protected:
	friend class cWorker;
	friend class cReport;
	friend class cControlPlane;
	friend class cBus;
	friend class dataplane::globalBase::generation;
	friend class worker_gc_t;

	tDataPlaneConfig config;

	std::map<tPortId,
	         std::tuple<std::string, ///< interface_name
	                    std::map<tCoreId, tQueueId>, ///< rx_queues
	                    unsigned int, ///< tx_queues_count
	                    common::mac_address_t, ///< mac_address
	                    std::string, ///< pci
	                    bool ///< symmetric_mode
	                    >>
	        ports;
	std::map<tCoreId, cWorker*> workers;
	std::map<tCoreId, worker_gc_t*> worker_gcs;

	std::mutex currentGlobalBaseId_mutex;
	uint8_t currentGlobalBaseId;
	std::map<tSocketId, dataplane::globalBase::atomic*> globalBaseAtomics;
	size_t numaNodesInUse;
	std::map<tSocketId, std::array<dataplane::globalBase::generation*, 2>> globalBases;
	uint32_t globalBaseSerial;

	ConfigValues configValues;

	std::map<std::string,
	         std::tuple<int, ///< socket
	                    rte_ring*,
	                    rte_ring*>>
	        ringPorts;

	pthread_barrier_t initPortBarrier;
	pthread_barrier_t runBarrier;

	rte_mempool* mempool_log;

	common::idp::get_shm_info::response dumps_meta;
	std::map<std::string, uint64_t> tag_to_id;

	common::idp::get_shm_tsc_info::response tscs_meta;

	// array instead of the table - how many coreIds can be there?
	std::unordered_map<uint32_t, std::unordered_map<std::string, uint64_t*>> coreId_to_stats_tables;

	std::map<tSocketId, std::tuple<key_t, void*>> shm_by_socket_id;

	std::set<tSocketId> socket_ids;
	std::map<tSocketId, worker_gc_t*> socket_worker_gcs;
	std::vector<cWorker*> workers_vector;

	std::mutex switch_worker_base_mutex;
	uint32_t current_time;

	std::vector<std::thread> threads;

	mutable std::mutex dpdk_mutex;

public: ///< modules
	cReport report;
	std::unique_ptr<cControlPlane> controlPlane;
	cBus bus;
	dataplane::memory_manager memory_manager;
	dataplane::neighbor::module neighbor;
};
