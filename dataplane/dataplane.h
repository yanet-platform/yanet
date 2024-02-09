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
#include "controlplane.h"
#include "globalbase.h"
#include "neighbor.h"
#include "report.h"
#include "type.h"
#include "worker_gc.h"

enum class eConfigType
{
	port_rx_queue_size,
	port_tx_queue_size,
	ring_highPriority_size,
	ring_normalPriority_size,
	ring_lowPriority_size,
	ring_toFreePackets_size,
	ring_log_size,
	fragmentation_size,
	fragmentation_timeout_first,
	fragmentation_timeout_last,
	fragmentation_packets_per_flow,
	stateful_firewall_udp_timeout,
	stateful_firewall_tcp_timeout,
	stateful_firewall_other_protocols_timeout,
	gc_step,
	sample_gc_step,
	acl_states4_ht_size,
	acl_states6_ht_size,
	acl_network_lpm4_chunks_size,
	acl_network_source_lpm6_chunks_size,
	acl_network_destination_lpm6_chunks_size,
	acl_network_destination_ht_size,
	acl_network_table_size,
	acl_transport_layers_size,
	acl_transport_ht_size,
	acl_total_ht_size,
	acl_values_size,
	acl_tcp_syn_ack_timeout,
	acl_tcp_syn_timeout,
	acl_tcp_fin_timeout,
	master_mempool_size,
	nat64stateful_states_size,
	kernel_interface_queue_size,
	balancer_state_ttl,
	balancer_state_ht_size,
	tsc_active_state,
	balancer_tcp_syn_ack_timeout,
	balancer_tcp_syn_timeout,
	balancer_tcp_fin_timeout,
	balancer_tcp_timeout,
};

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
	uint64_t rssFlags = RTE_ETH_RSS_IP;
	uint32_t SWNormalPriorityRateLimitPerWorker = 0;
	uint32_t SWICMPOutRateLimit = 0;
	uint32_t rateLimitDivisor = 1;
	unsigned int memory = 0;
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

	uint64_t getConfigValue(const eConfigType& type) const;
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

	template<typename type,
	         typename... args_t>
	type* hugepage_create_static(int socket_id,
	                             const args_t&... args)
	{
		size_t size = sizeof(type) + 2 * RTE_CACHE_LINE_SIZE;

		YADECAP_LOG_INFO("yanet_alloc(size: %lu, align: %u, socket: %u)\n",
		                 size,
		                 RTE_CACHE_LINE_SIZE,
		                 socket_id);

		void* pointer = rte_zmalloc_socket(nullptr,
		                                   size,
		                                   RTE_CACHE_LINE_SIZE,
		                                   socket_id);
		if (pointer == nullptr)
		{
			YADECAP_LOG_ERROR("yanet_alloc(size: %lu)\n", size);
			hugepage_debug(socket_id);
			return nullptr;
		}

		type* result = new ((type*)pointer) type(args...);

		{
			std::lock_guard<std::mutex> guard(hugepage_pointers_mutex);
			hugepage_pointers.try_emplace(result, size, [result]() {
				YADECAP_LOG_INFO("yanet_free()\n");
				result->~type();
				rte_free(result);
			});
		}

		return result;
	}

	template<typename type,
	         typename... args_t>
	type* hugepage_create_static_array(int socket_id, const size_t count, const args_t&... args)
	{
		size_t size = count * sizeof(type) + 2 * RTE_CACHE_LINE_SIZE;

		YADECAP_LOG_INFO("yanet_alloc(size: %lu, align: %u, socket: %u)\n",
		                 size,
		                 RTE_CACHE_LINE_SIZE,
		                 socket_id);

		void* pointer = rte_zmalloc_socket(nullptr,
		                                   size,
		                                   RTE_CACHE_LINE_SIZE,
		                                   socket_id);
		if (pointer == nullptr)
		{
			YADECAP_LOG_ERROR("yanet_alloc(size: %lu)\n", size);
			hugepage_debug(socket_id);
			return nullptr;
		}

		for (size_t i = 0;
		     i < count;
		     i++)
		{
			new (((type*)pointer) + i) type(args...);
		}

		{
			std::lock_guard<std::mutex> guard(hugepage_pointers_mutex);
			hugepage_pointers.try_emplace(pointer, size, [pointer, count]() {
				YADECAP_LOG_INFO("yanet_free()\n");
				for (size_t i = 0;
				     i < count;
				     i++)
				{
					type* result = ((type*)pointer) + i;
					result->~type();
				}
				rte_free(pointer);
			});
		}

		return (type*)pointer;
	}

	template<typename type,
	         typename elems_t,
	         typename updater_type,
	         typename... args_t>
	type* hugepage_create_dynamic(int socket_id,
	                              elems_t elems,
	                              updater_type& updater,
	                              const args_t&... args)
	{
		size_t size = type::calculate_sizeof(elems);
		if (!size)
		{
			return nullptr;
		}

		size += 2 * RTE_CACHE_LINE_SIZE;

		YADECAP_LOG_INFO("yanet_alloc(size: %lu, align: %u, socket: %u)\n",
		                 size,
		                 RTE_CACHE_LINE_SIZE,
		                 socket_id);

		void* pointer = rte_zmalloc_socket(nullptr,
		                                   size,
		                                   RTE_CACHE_LINE_SIZE,
		                                   socket_id);
		if (pointer == nullptr)
		{
			YADECAP_LOG_ERROR("yanet_alloc(size: %lu)\n", size);
			hugepage_debug(socket_id);
			return nullptr;
		}

		type* result = new ((type*)pointer) type(args...);

		{
			std::lock_guard<std::mutex> guard(hugepage_pointers_mutex);
			hugepage_pointers.try_emplace(result, size, [result]() {
				YADECAP_LOG_INFO("yanet_free()\n");
				result->~type();
				rte_free(result);
			});
		}

		updater.update_pointer(result, socket_id, elems, args...);

		return result;
	}

	void hugepage_destroy(void* pointer);
	void hugepage_debug(tSocketId socket_id);

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

	std::map<eConfigType, uint64_t> configValues;

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

	/// modules
	cReport report;
	std::unique_ptr<cControlPlane> controlPlane;
	cBus bus;
	dataplane::neighbor::module neighbor;

	// array instead of the table - how many coreIds can be there?
	std::unordered_map<uint32_t, std::unordered_map<std::string, uint64_t*>> coreId_to_stats_tables;

	std::map<tSocketId, std::tuple<key_t, void*>> shm_by_socket_id;

	std::mutex hugepage_pointers_mutex;
	std::map<void*, hugepage_pointer> hugepage_pointers;

	std::set<tSocketId> socket_ids;
	std::map<tSocketId, worker_gc_t*> socket_worker_gcs;
	std::vector<cWorker*> workers_vector;

	std::mutex switch_worker_base_mutex;
	uint32_t current_time;

	std::vector<std::thread> threads;
};
