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
#include "kernel_interface_handler.h"
#include "memory_manager.h"
#include "neighbor.h"
#include "report.h"
#include "sdpserver.h"
#include "slow_worker.h"
#include "type.h"

using InterfaceName = std::string;

struct CPlaneWorkerConfig
{
	std::set<InterfaceName> interfaces;
	std::set<tCoreId> workers;
	std::set<tCoreId> gcs;
};

struct tDataPlaneConfig
{
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
	std::map<tCoreId, CPlaneWorkerConfig> controlplane_workers;
	std::map<tCoreId, std::vector<InterfaceName>> workers;
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

	const ConfigValues& getConfigValues() const { return config_values_; }
	std::map<std::string, common::uint64> getPortStats(const tPortId& portId) const;
	std::optional<tPortId> interface_name_to_port_id(const std::string& interface_name);
	const std::set<tSocketId>& get_socket_ids() const;
	const std::set<tCoreId> FastWorkerCores() const;
	const std::vector<cWorker*>& get_workers() const;
	void run_on_worker_gc(const tSocketId socket_id, const std::function<bool()>& callback);

	void switch_worker_base();

	inline uint32_t get_current_time() const
	{
		return current_time;
	}
	std::string InterfaceNameFromPort(tPortId id) { return std::get<0>(ports[id]); };

protected:
	eResult parseConfig(const std::string& configFilePath);
	eResult parseJsonPorts(const nlohmann::json& json);
	std::optional<std::map<tCoreId, CPlaneWorkerConfig>> parseControlPlaneWorkers(const nlohmann::json& config);
	std::optional<std::pair<tCoreId, CPlaneWorkerConfig>> parseControlPlaneWorker(const nlohmann::json& cpwj);
	nlohmann::json makeLegacyControlPlaneWorkerConfig();
	std::set<InterfaceName> workerInterfacesToService();
	eResult parseConfigValues(const nlohmann::json& json);
	eResult parseRateLimits(const nlohmann::json& json);
	eResult parseSharedMemory(const nlohmann::json& json);
	eResult checkConfig();
	bool checkControlPlaneWorkersConfig();

	eResult initEal(const std::string& binaryPath, const std::string& filePrefix);
	eResult initPorts();

	std::map<tCoreId, std::function<void()>> coreFunctions_;
	static int LcoreFunc(void* args);

public:
	void StartInterfaces();

protected:
	eResult init_kernel_interfaces();
	bool KNIAddTxQueue(tQueueId queue, tSocketId socket);
	bool KNIAddRxQueue(tQueueId queue, tSocketId socket, rte_mempool* mempool);
	eResult initGlobalBases();
	eResult initWorkers();
	eResult InitSlowWorker(const tCoreId core, const CPlaneWorkerConfig& ports);
	eResult InitSlowWorkers();
	eResult initKniQueues();
	eResult InitTxQueues();
	eResult InitRxQueues();
	eResult initSharedMemory();
	void init_worker_base();

	eResult allocateSharedMemory();
	eResult splitSharedMemoryPerWorkers();

	std::optional<uint64_t> getCounterValueByName(const std::string& counter_name, uint32_t coreId);
	common::idp::get_shm_info::response getShmInfo();
	common::idp::get_shm_tsc_info::response getShmTscInfo();

	void timestamp_thread();
	void SWRateLimiterTimeTracker();
	std::chrono::high_resolution_clock::time_point prevTimePointForSWRateLimiter;

protected:
	friend class cWorker;
	friend class cReport;
	friend class cControlPlane;
	friend class cBus;
	friend class dataplane::globalBase::generation;
	friend class worker_gc_t;

	tDataPlaneConfig config;
	ConfigValues config_values_;

	struct KniHandleBundle
	{
		dataplane::KernelInterfaceHandle forward;
		dataplane::KernelInterfaceHandle in_dump;
		dataplane::KernelInterfaceHandle out_dump;
		dataplane::KernelInterfaceHandle drop_dump;
	};
	std::map<tPortId, KniHandleBundle> kni_interface_handles;

	std::map<tPortId,
	         std::tuple<InterfaceName,
	                    std::map<tCoreId, tQueueId>, ///< rx_queues
	                    unsigned int, ///< tx_queues_count
	                    common::mac_address_t, ///< mac_address
	                    std::string, ///< pci
	                    bool ///< symmetric_mode
	                    >>
	        ports;
	tQueueId tx_queues_ = 0;
	std::map<tCoreId, cWorker*> workers;
	std::map<tCoreId, worker_gc_t*> worker_gcs;
	std::map<tCoreId, dataplane::SlowWorker*> slow_workers;
	std::map<tCoreId, dataplane::KernelInterfaceWorker*> kni_workers;

	std::mutex currentGlobalBaseId_mutex;
	uint8_t currentGlobalBaseId;

public:
	std::map<tSocketId, dataplane::globalBase::atomic*> globalBaseAtomics;

protected:
	size_t numaNodesInUse;
	std::map<tSocketId, std::array<dataplane::globalBase::generation*, 2>> globalBases;
	uint32_t globalBaseSerial;

	std::map<std::string,
	         std::tuple<int, ///< socket
	                    rte_ring*,
	                    rte_ring*>>
	        ringPorts;

	rte_mempool* mempool_log;

	common::idp::get_shm_info::response dumps_meta;
	std::map<std::string, uint64_t> tag_to_id;

	common::idp::get_shm_tsc_info::response tscs_meta;

	// array instead of the table - how many coreIds can be there?
	std::unordered_map<uint32_t, std::unordered_map<std::string, uint64_t*>> coreId_to_stats_tables;

	std::map<tSocketId, std::tuple<key_t, void*>> shm_by_socket_id;

	std::set<tSocketId> socket_ids;
	std::map<tSocketId, worker_gc_t*> socket_worker_gcs;
	std::map<tSocketId, rte_mempool*> socket_cplane_mempools;

	std::vector<cWorker*> workers_vector;

	std::mutex switch_worker_base_mutex;
	uint32_t current_time;

	std::vector<std::thread> threads;

	mutable std::mutex dpdk_mutex;

	common::sdp::DataPlaneInSharedMemory sdp_data;

public: ///< modules
	cReport report;
	std::unique_ptr<cControlPlane> controlPlane;
	cBus bus;
	dataplane::memory_manager memory_manager;
	dataplane::neighbor::module neighbor;
};
