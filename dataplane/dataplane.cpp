#include <arpa/inet.h>
#include <cstdint>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <fstream>
#include <thread>

#include <rte_eal.h>
#include <rte_eth_ring.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_version.h>

#include <numa.h>
#include <numaif.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "common.h"
#include "common/idp.h"
#include "common/result.h"
#include "common/tsc_deltas.h"
#include "dataplane.h"
#include "debug_latch.h"
#include "globalbase.h"
#include "lpm.h"
#include "report.h"
#include "sock_dev.h"
#include "worker.h"

common::log::LogPriority common::log::logPriority = common::log::TLOG_INFO;

cDataPlane::cDataPlane() :
        currentGlobalBaseId(0),
        globalBaseSerial(0),
        report(this),
        controlPlane(new cControlPlane(this)),
        bus(this),
        memory_manager(this)
{
}

cDataPlane::~cDataPlane()
{
	if (mempool_log)
	{
		rte_mempool_free(mempool_log);
	}
}

eResult cDataPlane::init(const std::string& binaryPath,
                         const std::string& configFilePath)
{
	eResult result = eResult::success;

	current_time = time(nullptr);

	result = parseConfig(configFilePath);
	if (result != eResult::success)
	{
		return result;
	}

	/// init environment abstraction layer
	std::string filePrefix;
	{
		char* pointer = getenv("YANET_FILEPREFIX");
		if (pointer)
		{
			filePrefix = pointer;
		}
		else
		{
			char* pointer = getenv("YANET_PREFIX");
			if (pointer)
			{
				filePrefix = pointer;
			}
		}
	}

	result = allocateSharedMemory();
	if (result != eResult::success)
	{
		return result;
	}

	result = initEal(binaryPath, filePrefix);
	if (result != eResult::success)
	{
		return result;
	}

	result = initPorts();
	if (result != eResult::success)
	{
		return result;
	}

	mempool_log = rte_mempool_create("log", YANET_CONFIG_SAMPLES_SIZE, sizeof(samples::sample_t), 0, 0, NULL, NULL, NULL, NULL, SOCKET_ID_ANY, MEMPOOL_F_NO_IOVA_CONTIG);

	result = initGlobalBases();
	if (result != eResult::success)
	{
		return result;
	}

	result = initWorkers();
	if (result != eResult::success)
	{
		return result;
	}

	result = splitSharedMemoryPerWorkers();
	if (result != eResult::success)
	{
		return result;
	}

	/// sanity check
	if (rte_lcore_count() != workers.size() + worker_gcs.size())
	{
		YADECAP_LOG_ERROR("invalid cores count: %u != %lu\n",
		                  rte_lcore_count(),
		                  workers.size());
		return eResult::invalidCoresCount;
	}

	/// sanity check: gc
	{
		std::set<tSocketId> worker_sockets_used;
		std::set<tSocketId> gc_sockets_used;

		for (const auto& [core_id, worker] : workers)
		{
			(void)core_id;
			worker_sockets_used.emplace(worker->socketId);
		}

		for (const auto& [core_id, worker_gc] : worker_gcs)
		{
			(void)core_id;
			gc_sockets_used.emplace(worker_gc->socket_id);
		}

		if (worker_sockets_used != gc_sockets_used)
		{
			YADECAP_LOG_ERROR("invalid worker_gc\n");
			return eResult::invalidConfigurationFile;
		}

		if (worker_gcs.size() != worker_sockets_used.size())
		{
			YADECAP_LOG_ERROR("invalid worker_gc\n");
			return eResult::invalidConfigurationFile;
		}
	}
	numaNodesInUse = worker_gcs.size();

	result = initQueues();
	if (result != eResult::success)
	{
		return result;
	}

	result = controlPlane->init(config.use_kernel_interface);
	if (result != eResult::success)
	{
		return result;
	}

	result = bus.init();
	if (result != eResult::success)
	{
		return result;
	}

	result = neighbor.init(this);
	if (result != eResult::success)
	{
		return result;
	}

	init_worker_base();

	/// init sync barrier
	int rc = pthread_barrier_init(&initPortBarrier, nullptr, workers.size());
	if (rc != 0)
	{
		YADECAP_LOG_ERROR("pthread_barrier_init() = %d\n", rc);
		return eResult::errorInitBarrier;
	}

	/// init run sync barrier
	rc = pthread_barrier_init(&runBarrier, nullptr, workers.size() + worker_gcs.size());
	if (rc != 0)
	{
		YADECAP_LOG_ERROR("pthread_barrier_init() = %d\n", rc);
		return eResult::errorInitBarrier;
	}

	return result;
}

std::string rss_flags_to_string(uint64_t rss_flags)
{
	std::string flag_names;
	if (rss_flags & RTE_ETH_RSS_IPV4)
	{
		flag_names += "IPV4 ";
	}
	if (rss_flags & RTE_ETH_RSS_FRAG_IPV4)
	{
		flag_names += "FRAG_IPV4 ";
	}
	if (rss_flags & RTE_ETH_RSS_NONFRAG_IPV4_TCP)
	{
		flag_names += "NONFRAG_IPV4_TCP ";
	}
	if (rss_flags & RTE_ETH_RSS_NONFRAG_IPV4_UDP)
	{
		flag_names += "NONFRAG_IPV4_UDP ";
	}
	if (rss_flags & RTE_ETH_RSS_NONFRAG_IPV4_SCTP)
	{
		flag_names += "NONFRAG_IPV4_SCTP ";
	}
	if (rss_flags & RTE_ETH_RSS_NONFRAG_IPV4_OTHER)
	{
		flag_names += "NONFRAG_IPV4_OTHER ";
	}
	if (rss_flags & RTE_ETH_RSS_IPV6)
	{
		flag_names += "IPV6 ";
	}
	if (rss_flags & RTE_ETH_RSS_FRAG_IPV6)
	{
		flag_names += "FRAG_IPV6 ";
	}
	if (rss_flags & RTE_ETH_RSS_NONFRAG_IPV6_TCP)
	{
		flag_names += "NONFRAG_IPV6_TCP ";
	}
	if (rss_flags & RTE_ETH_RSS_NONFRAG_IPV6_UDP)
	{
		flag_names += "NONFRAG_IPV6_UDP ";
	}
	if (rss_flags & RTE_ETH_RSS_NONFRAG_IPV6_SCTP)
	{
		flag_names += "NONFRAG_IPV6_SCTP ";
	}
	if (rss_flags & RTE_ETH_RSS_NONFRAG_IPV6_OTHER)
	{
		flag_names += "NONFRAG_IPV6_OTHER ";
	}
	if (rss_flags & RTE_ETH_RSS_L2_PAYLOAD)
	{
		flag_names += "L2_PAYLOAD ";
	}
	if (rss_flags & RTE_ETH_RSS_IPV6_EX)
	{
		flag_names += "IPV6_EX ";
	}
	if (rss_flags & RTE_ETH_RSS_IPV6_TCP_EX)
	{
		flag_names += "IPV6_TCP_EX ";
	}
	if (rss_flags & RTE_ETH_RSS_IPV6_UDP_EX)
	{
		flag_names += "IPV6_UDP_EX ";
	}
	if (rss_flags & RTE_ETH_RSS_PORT)
	{
		flag_names += "PORT ";
	}
	if (rss_flags & RTE_ETH_RSS_VXLAN)
	{
		flag_names += "VXLAN ";
	}
	if (rss_flags & RTE_ETH_RSS_GENEVE)
	{
		flag_names += "GENEVE ";
	}
	if (rss_flags & RTE_ETH_RSS_NVGRE)
	{
		flag_names += "NVGRE ";
	}
	if (rss_flags & RTE_ETH_RSS_MPLS)
	{
		flag_names += "MPLS ";
	}
	return flag_names;
}

uint64_t string_to_rss_flag(std::string flag_str)
{
	std::transform(flag_str.begin(), flag_str.end(), flag_str.begin(), ::toupper);
	if (flag_str == "IPV4")
	{
		return RTE_ETH_RSS_IPV4;
	}
	else if (flag_str == "FRAG_IPV4")
	{
		return RTE_ETH_RSS_FRAG_IPV4;
	}
	else if (flag_str == "NONFRAG_IPV4_TCP")
	{
		return RTE_ETH_RSS_NONFRAG_IPV4_TCP;
	}
	else if (flag_str == "NONFRAG_IPV4_UDP")
	{
		return RTE_ETH_RSS_NONFRAG_IPV4_UDP;
	}
	else if (flag_str == "NONFRAG_IPV4_SCTP")
	{
		return RTE_ETH_RSS_NONFRAG_IPV4_SCTP;
	}
	else if (flag_str == "NONFRAG_IPV4_OTHER")
	{
		return RTE_ETH_RSS_NONFRAG_IPV4_OTHER;
	}
	else if (flag_str == "IPV6")
	{
		return RTE_ETH_RSS_IPV6;
	}
	else if (flag_str == "FRAG_IPV6")
	{
		return RTE_ETH_RSS_FRAG_IPV6;
	}
	else if (flag_str == "NONFRAG_IPV6_TCP")
	{
		return RTE_ETH_RSS_NONFRAG_IPV6_TCP;
	}
	else if (flag_str == "NONFRAG_IPV6_UDP")
	{
		return RTE_ETH_RSS_NONFRAG_IPV6_UDP;
	}
	else if (flag_str == "NONFRAG_IPV6_SCTP")
	{
		return RTE_ETH_RSS_NONFRAG_IPV6_SCTP;
	}
	else if (flag_str == "NONFRAG_IPV6_OTHER")
	{
		return RTE_ETH_RSS_NONFRAG_IPV6_OTHER;
	}
	else if (flag_str == "L2_PAYLOAD")
	{
		return RTE_ETH_RSS_L2_PAYLOAD;
	}
	else if (flag_str == "IPV6_EX")
	{
		return RTE_ETH_RSS_IPV6_EX;
	}
	else if (flag_str == "IPV6_TCP_EX")
	{
		return RTE_ETH_RSS_IPV6_TCP_EX;
	}
	else if (flag_str == "IPV6_UDP_EX")
	{
		return RTE_ETH_RSS_IPV6_UDP_EX;
	}
	else if (flag_str == "PORT")
	{
		return RTE_ETH_RSS_PORT;
	}
	else if (flag_str == "VXLAN")
	{
		return RTE_ETH_RSS_VXLAN;
	}
	else if (flag_str == "GENEVE")
	{
		return RTE_ETH_RSS_GENEVE;
	}
	else if (flag_str == "NVGRE")
	{
		return RTE_ETH_RSS_NVGRE;
	}
	else if (flag_str == "MPLS")
	{
		return RTE_ETH_RSS_MPLS;
	}
	else
	{
		YADECAP_LOG_WARNING("incorrect value for rss flag: '%s'\n", flag_str.c_str());
		return 0;
	}
}

eResult cDataPlane::initPorts()
{
	std::vector<std::string> remove_keys;

	for (const auto& configPortIter : config.ports)
	{
		const std::string& interfaceName = configPortIter.first;
		const auto& [pci, name, symmetric_mode, rss_flags] = configPortIter.second;
		(void)pci;

		tPortId portId;
		if (strncmp(name.data(), SOCK_DEV_PREFIX, strlen(SOCK_DEV_PREFIX)) == 0)
		{
			portId = sock_dev_create(name.data(), 0);
		}
		else if (rte_eth_dev_get_port_by_name(name.data(), &portId))
		{
			YADECAP_LOG_ERROR("invalid name: '%s'\n", name.data());
			remove_keys.emplace_back(interfaceName);
			continue;
		}

		YADECAP_LOG_INFO("portId: %u, socketId: %u, interfaceName: %s, pci: %s\n",
		                 portId,
		                 rte_eth_dev_socket_id(portId),
		                 interfaceName.data(),
		                 pci.data());

		rte_ether_addr etherAddress;
		rte_eth_macaddr_get(portId, &etherAddress);

		rte_eth_dev_info devInfo;
		rte_eth_dev_info_get(portId, &devInfo);

		rte_eth_conf portConf;
		memset(&portConf, 0, sizeof(rte_eth_conf));

		if (rss_flags != 0)
		{
			portConf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;

			YADECAP_LOG_INFO("device info: flow type rss offloads 0x%lx\n", devInfo.flow_type_rss_offloads);
			YADECAP_LOG_INFO("port.rss_flags: 0x%lx\n", rss_flags);
			if ((devInfo.flow_type_rss_offloads | rss_flags) == devInfo.flow_type_rss_offloads)
			{
				portConf.rx_adv_conf.rss_conf.rss_hf = rss_flags;
			}
			else
			{
				uint64_t missedFlags = ~devInfo.flow_type_rss_offloads & rss_flags;
				YADECAP_LOG_ERROR("port.rssFlags 0x%lx not supported, missed flags %s\n",
				                  rss_flags,
				                  rss_flags_to_string(missedFlags).c_str());
				return eResult::invalidConfigurationFile;
			}
		}
		else
		{
			YADECAP_LOG_INFO("Packets distribution among NIC queues is switched off\n");
		}

		/// @todo: jumbo frame ?
		portConf.rxmode.max_lro_pkt_size = RTE_MIN(((uint32_t)CONFIG_YADECAP_MBUF_SIZE - 2 * RTE_PKTMBUF_HEADROOM),
		                                           devInfo.max_rx_pktlen - 2 * RTE_PKTMBUF_HEADROOM);

		unsigned int mtu = CONFIG_YADECAP_MTU; ///< @todo: mtu vendor1 != mtu vendor2

		YADECAP_LOG_INFO("max_lro_pkt_size: %u\n", portConf.rxmode.max_lro_pkt_size);
		YADECAP_LOG_INFO("mtu: %u\n", mtu);

		std::map<tCoreId, tQueueId> rx_queues;

		uint16_t rxQueuesCount = 0;
		uint16_t txQueuesCount = config.workers.size() + 1; ///< tx queue '0' for control plane
		for (const auto& configWorkerIter : config.workers)
		{
			const tCoreId& coreId = configWorkerIter.first;

			for (const auto& workerInterfaceName : configWorkerIter.second)
			{
				if (interfaceName == workerInterfaceName)
				{
					rx_queues[coreId] = rxQueuesCount;
					rxQueuesCount++;
				}
			}
		}

		if (symmetric_mode &&
		    rxQueuesCount < txQueuesCount)
		{
			YADECAP_LOG_INFO("symmetric mode is enabled. configure rx queues size from '%u' to '%u'\n",
			                 rxQueuesCount,
			                 txQueuesCount);
			rxQueuesCount = txQueuesCount;
		}

		YADECAP_LOG_INFO("rxQueuesCount: %u, txQueuesCount: %u\n", rxQueuesCount, txQueuesCount);

		int ret = rte_eth_dev_configure(portId,
		                                rxQueuesCount,
		                                txQueuesCount,
		                                &portConf);
		if (ret < 0)
		{
			YADECAP_LOG_ERROR("rte_eth_dev_configure() = %d\n", ret);
			return eResult::errorInitEthernetDevice;
		}

		ret = rte_eth_dev_set_mtu(portId, mtu);
		if (ret != 0)
		{
			YADECAP_LOG_ERROR("rte_eth_dev_set_mtu() = %d\n", ret);
			return eResult::errorInitEthernetDevice;
		}

		{
			std::lock_guard<std::mutex> guard(dpdk_mutex);
			rte_eth_stats_reset(portId);
		}

		ports[portId] = {interfaceName,
		                 rx_queues,
		                 txQueuesCount,
		                 etherAddress.addr_bytes,
		                 pci,
		                 symmetric_mode};
	}

	for (const auto& interface_name : remove_keys)
	{
		YANET_LOG_ERROR("Failed to init interface '%s'\n", std::get<0>(config.ports.at(interface_name.c_str())).c_str());
		config.ports.erase(interface_name);
	}

	if (config.interfaces_required && config.ports.empty())
	{
		YANET_LOG_ERROR("Failed to configure at least one interface\n");
		return eResult::errorInitEthernetDevice;
	}

	return eResult::success;
}

eResult cDataPlane::initGlobalBases()
{
	eResult result = eResult::success;

	auto create_globalbase_atomics = [this](const tSocketId& socket_id) -> eResult {
		if (globalBaseAtomics.find(socket_id) == globalBaseAtomics.end())
		{
			auto* globalbase_atomic = memory_manager.create_static<dataplane::globalBase::atomic>("globalbase.atomic",
			                                                                                      socket_id,
			                                                                                      this,
			                                                                                      socket_id);
			if (!globalbase_atomic)
			{
				return eResult::errorAllocatingMemory;
			}

			{
				using namespace dataplane::globalBase;

				auto* ipv4_states_ht = memory_manager.create<acl::ipv4_states_ht>("acl.state.v4.ht",
				                                                                  socket_id,
				                                                                  acl::ipv4_states_ht::calculate_sizeof(getConfigValues().acl_states4_ht_size));
				if (!ipv4_states_ht)
				{
					return eResult::errorAllocatingMemory;
				}

				auto* ipv6_states_ht = memory_manager.create<acl::ipv6_states_ht>("acl.state.v6.ht",
				                                                                  socket_id,
				                                                                  acl::ipv6_states_ht::calculate_sizeof(getConfigValues().acl_states6_ht_size));
				if (!ipv6_states_ht)
				{
					return eResult::errorAllocatingMemory;
				}

				auto* nat64stateful_lan_state = memory_manager.create<nat64stateful::lan_ht>("nat64stateful.state.lan.ht",
				                                                                             socket_id,
				                                                                             nat64stateful::lan_ht::calculate_sizeof(getConfigValues().nat64stateful_states_size));
				if (!nat64stateful_lan_state)
				{
					return eResult::errorAllocatingMemory;
				}

				auto* nat64stateful_wan_state = memory_manager.create<nat64stateful::wan_ht>("nat64stateful.state.wan.ht",
				                                                                             socket_id,
				                                                                             nat64stateful::wan_ht::calculate_sizeof(getConfigValues().nat64stateful_states_size));
				if (!nat64stateful_wan_state)
				{
					return eResult::errorAllocatingMemory;
				}

				auto* balancer_state = memory_manager.create<dataplane::globalBase::balancer::state_ht>("balancer.state.ht",
				                                                                                        socket_id,
				                                                                                        dataplane::globalBase::balancer::state_ht::calculate_sizeof(getConfigValues().balancer_state_ht_size));
				if (!balancer_state)
				{
					return eResult::errorAllocatingMemory;
				}

				globalbase_atomic->updater.fw4_state.update_pointer(ipv4_states_ht, socket_id, getConfigValues().acl_states4_ht_size);
				globalbase_atomic->updater.fw6_state.update_pointer(ipv6_states_ht, socket_id, getConfigValues().acl_states6_ht_size);
				globalbase_atomic->updater.nat64stateful_lan_state.update_pointer(nat64stateful_lan_state, socket_id, getConfigValues().nat64stateful_states_size);
				globalbase_atomic->updater.nat64stateful_wan_state.update_pointer(nat64stateful_wan_state, socket_id, getConfigValues().nat64stateful_states_size);
				globalbase_atomic->updater.balancer_state.update_pointer(balancer_state, socket_id, getConfigValues().balancer_state_ht_size);

				globalbase_atomic->fw4_state = ipv4_states_ht;
				globalbase_atomic->fw6_state = ipv6_states_ht;
				globalbase_atomic->nat64stateful_lan_state = nat64stateful_lan_state;
				globalbase_atomic->nat64stateful_wan_state = nat64stateful_wan_state;
				globalbase_atomic->balancer_state = balancer_state;
			}

			globalBaseAtomics[socket_id] = globalbase_atomic;
		}

		return eResult::success;
	};

	auto create_globalbase = [this](const tSocketId& socket_id) -> dataplane::globalBase::generation* {
		auto* globalbase = memory_manager.create_static<dataplane::globalBase::generation>("globalbase.generation",
		                                                                                   socket_id,
		                                                                                   this,
		                                                                                   socket_id);
		if (!globalbase)
		{
			return nullptr;
		}

		if (globalbase->init() != eResult::success)
		{
			return nullptr;
		}

		return globalbase;
	};

	auto create_globalbases = [&](const tSocketId& socket_id) -> eResult {
		if (globalBases.find(socket_id) == globalBases.end())
		{
			auto* globalbase = create_globalbase(socket_id);
			if (!globalbase)
			{
				return eResult::errorAllocatingMemory;
			}

			auto* globalbase_next = create_globalbase(socket_id);
			if (!globalbase_next)
			{
				return eResult::errorAllocatingMemory;
			}

			globalBases[socket_id] = {globalbase,
			                          globalbase_next};
		}

		return eResult::success;
	};

	/// slow worker
	{
		tSocketId socketId = rte_lcore_to_socket_id(config.controlPlaneCoreId);

		result = create_globalbase_atomics(socketId);
		if (result != eResult::success)
		{
			return result;
		}

		result = create_globalbases(socketId);
		if (result != eResult::success)
		{
			return result;
		}

		socket_ids.emplace(socketId);
	}

	for (const auto& configWorkerIter : config.workers)
	{
		const tCoreId& coreId = configWorkerIter.first;
		tSocketId socketId = rte_lcore_to_socket_id(coreId);

		result = create_globalbase_atomics(socketId);
		if (result != eResult::success)
		{
			return result;
		}

		result = create_globalbases(socketId);
		if (result != eResult::success)
		{
			return result;
		}

		socket_ids.emplace(socketId);
	}

	return result;
}

eResult cDataPlane::initWorkers()
{
	tQueueId outQueueId = 0;

	/// slow worker
	{
		const tCoreId& coreId = config.controlPlaneCoreId;
		const tSocketId socket_id = rte_lcore_to_socket_id(coreId);

		YADECAP_LOG_INFO("initWorker. coreId: %u [slow worker]\n", coreId);

		auto* worker = memory_manager.create_static<cWorker>("worker",
		                                                     socket_id,
		                                                     this);
		if (!worker)
		{
			return eResult::errorAllocatingMemory;
		}

		dataplane::base::permanently basePermanently;
		basePermanently.globalBaseAtomic = globalBaseAtomics[socket_id];
		basePermanently.outQueueId = outQueueId; ///< 0
		for (const auto& portIter : ports)
		{
			if (!basePermanently.ports.Register(portIter.first))
				return eResult::invalidPortsCount;
		}

		basePermanently.SWNormalPriorityRateLimitPerWorker = config.SWNormalPriorityRateLimitPerWorker;

		dataplane::base::generation base;
		base.globalBase = globalBases[socket_id][currentGlobalBaseId];

		eResult result = worker->init(coreId,
		                              basePermanently,
		                              base);
		if (result != eResult::success)
		{
			return result;
		}

		worker->fillStatsNamesToAddrsTable(coreId_to_stats_tables[coreId]);

		workers[coreId] = worker;
		controlPlane->slowWorker = worker;
		workers_vector.emplace_back(worker);

		outQueueId++;
	}

	for (const auto& configWorkerIter : config.workers)
	{
		const tCoreId& coreId = configWorkerIter.first;
		const tSocketId socket_id = rte_lcore_to_socket_id(coreId);

		YADECAP_LOG_INFO("initWorker. coreId: %u\n", coreId);

		auto* worker = memory_manager.create_static<cWorker>("worker",
		                                                     socket_id,
		                                                     this);
		if (!worker)
		{
			return eResult::errorAllocatingMemory;
		}

		dataplane::base::permanently basePermanently;
		{
			auto iter = globalBaseAtomics.find(socket_id);
			if (iter == globalBaseAtomics.end())
			{
				YADECAP_LOG_ERROR("globalBaseAtomics[%u] not found\n", socket_id);
				return eResult::invalidSocketId;
			}
			basePermanently.globalBaseAtomic = iter->second;
		}

		unsigned int idx = 0;
		for (const auto it : globalBaseAtomics)
		{
			basePermanently.globalBaseAtomics[idx] = it.second;
			idx++;
		}

		if (socket_id >= globalBaseAtomics.size())
		{
			YADECAP_LOG_ERROR("invalid socket_id: %u\n", socket_id);
			return eResult::invalidSocketId;
		}

		if (globalBaseAtomics.size() > 1)
		{
			size_t pow2_size = 1;
			while (pow2_size < globalBaseAtomics.size())
			{
				pow2_size <<= 1;
			}

			unsigned int shift = __builtin_popcount(pow2_size - 1);

			basePermanently.nat64stateful_numa_mask = rte_cpu_to_be_16(0xFFFFu << shift);
			basePermanently.nat64stateful_numa_reverse_mask = rte_cpu_to_be_16(0xFFFFu >> (16 - shift));
			basePermanently.nat64stateful_numa_id = rte_cpu_to_be_16(socket_id);
		}

		for (const auto& [port_id, port] : ports)
		{
			const auto& [interface_name, rx_queues, tx_queues_count, mac_address, pci, symmetric_mode] = port;
			(void)mac_address;
			(void)pci;

			if (!basePermanently.ports.Register(port_id))
				return eResult::invalidPortsCount;

			if (exist(rx_queues, coreId))
			{
				YANET_LOG_DEBUG("worker[%u]: add_worker_port(port_id: %u, queue_id: %u)\n",
				                coreId,
				                port_id,
				                rx_queues.find(coreId)->second);

				if (!basePermanently.add_worker_port(port_id, rx_queues.find(coreId)->second))
				{
					YADECAP_LOG_ERROR("can't add port '%s' to worker '%u'\n",
					                  interface_name.data(),
					                  coreId);
					return eResult::invalidCoresCount;
				}

				if (symmetric_mode)
				{
					/// symmetric mode. add more rx queues
					///
					/// before
					/// rx_queue_id -> core_id
					/// 0           -> 1
					/// 1           -> 2
					/// 2           -> 3
					/// 3           -> n/s
					/// 4           -> n/s
					/// 5           -> n/s
					/// 6           -> n/s
					///
					/// after
					/// rx_queue_id -> core_id
					/// 0           -> 1
					/// 1           -> 2
					/// 2           -> 3
					/// 3           -> 1
					/// 4           -> 2
					/// 5           -> 3
					/// 6           -> 1

					uint16_t workers_count = rx_queues.size();
					uint16_t rx_queue_id = rx_queues.find(coreId)->second + workers_count;

					while (rx_queue_id < tx_queues_count)
					{
						YANET_LOG_DEBUG("worker[%u]: add_worker_port(port_id: %u, queue_id: %u)\n",
						                coreId,
						                port_id,
						                rx_queue_id);

						if (!basePermanently.add_worker_port(port_id, rx_queue_id))
						{
							YADECAP_LOG_ERROR("can't add port '%s' to worker '%u'\n",
							                  interface_name.data(),
							                  coreId);
							return eResult::invalidCoresCount;
						}

						rx_queue_id += workers_count;
					}
				}
			}
		}

		basePermanently.outQueueId = outQueueId;

		dataplane::base::generation base;
		{
			auto iter = globalBases.find(socket_id);
			if (iter == globalBases.end())
			{
				YADECAP_LOG_ERROR("globalBases[%u] not found\n", socket_id);
				return eResult::invalidSocketId;
			}
			base.globalBase = iter->second[currentGlobalBaseId];
		}

		eResult result = worker->init(coreId,
		                              basePermanently,
		                              base);
		if (result != eResult::success)
		{
			return result;
		}

		worker->fillStatsNamesToAddrsTable(coreId_to_stats_tables[coreId]);
		workers[coreId] = worker;
		workers_vector.emplace_back(worker);

		outQueueId++;
	}

	/// worker_gc
	for (const auto& core_id : config.workerGCs)
	{
		const tSocketId socket_id = rte_lcore_to_socket_id(core_id);

		YADECAP_LOG_INFO("initWorker. coreId: %u [worker_gc]\n", core_id);

		auto* worker = memory_manager.create_static<worker_gc_t>("worker_gc",
		                                                         socket_id,
		                                                         this);
		if (!worker)
		{
			return eResult::errorAllocatingMemory;
		}

		dataplane::base::permanently basePermanently;
		{
			auto iter = globalBaseAtomics.find(socket_id);
			if (iter == globalBaseAtomics.end())
			{
				YADECAP_LOG_ERROR("globalBaseAtomics[%u] not found\n", socket_id);
				return eResult::invalidSocketId;
			}
			basePermanently.globalBaseAtomic = iter->second;
		}

		unsigned int idx = 0;
		for (const auto it : globalBaseAtomics)
		{
			basePermanently.globalBaseAtomics[idx] = it.second;
			idx++;
		}

		if (socket_id >= globalBaseAtomics.size())
		{
			YADECAP_LOG_ERROR("invalid socket_id: %u\n", socket_id);
			return eResult::invalidSocketId;
		}

		if (globalBaseAtomics.size() > 1)
		{
			size_t pow2_size = 1;
			while (pow2_size < globalBaseAtomics.size())
			{
				pow2_size <<= 1;
			}

			unsigned int shift = __builtin_popcount(pow2_size - 1);

			basePermanently.nat64stateful_numa_mask = rte_cpu_to_be_16(0xFFFFu << shift);
			basePermanently.nat64stateful_numa_reverse_mask = rte_cpu_to_be_16(0xFFFFu >> (16 - shift));
			basePermanently.nat64stateful_numa_id = rte_cpu_to_be_16(socket_id);
		}

		dataplane::base::generation base;
		{
			auto iter = globalBases.find(socket_id);
			if (iter == globalBases.end())
			{
				YADECAP_LOG_ERROR("globalBases[%u] not found\n", socket_id);
				return eResult::invalidSocketId;
			}
			base.globalBase = iter->second[currentGlobalBaseId];
		}

		eResult result = worker->init(core_id,
		                              socket_id,
		                              basePermanently,
		                              base);
		if (result != eResult::success)
		{
			return result;
		}

		worker->fillStatsNamesToAddrsTable(coreId_to_stats_tables[core_id]);
		worker_gcs[core_id] = worker;
		socket_worker_gcs[socket_id] = worker;
	}

	return eResult::success;
}

std::optional<uint64_t> cDataPlane::getCounterValueByName(const std::string& counter_name, uint32_t coreId)
{
	if (coreId_to_stats_tables.count(coreId) == 0)
	{
		return std::optional<uint64_t>();
	}

	const auto& specific_core_table = coreId_to_stats_tables[coreId];

	if (specific_core_table.count(counter_name) == 0)
	{
		return std::optional<uint64_t>();
	}

	uint64_t counter_value = *(specific_core_table.at(counter_name));
	return std::optional<uint64_t>(counter_value);
}

eResult cDataPlane::initQueues()
{
	for (const auto& portIter : ports)
	{
		const tPortId& portId = portIter.first;

		for (tQueueId queueId = 0;
		     queueId < workers.size();
		     queueId++)
		{
			int ret = rte_eth_tx_queue_setup(portId,
			                                 queueId,
			                                 getConfigValues().port_tx_queue_size,
			                                 rte_eth_dev_socket_id(portId),
			                                 nullptr); ///< @todo
			if (ret < 0)
			{
				YADECAP_LOG_ERROR("rte_eth_tx_queue_setup(%u, %u) = %d\n", portId, queueId, ret);
				return eResult::errorInitQueue;
			}
		}
	}

	return eResult::success;
}

void cDataPlane::init_worker_base()
{
	std::vector<std::tuple<tSocketId, dataplane::base::generation*>> base_nexts;
	for (auto& [core_id, worker] : workers)
	{
		(void)core_id;

		auto* base = &worker->bases[worker->currentBaseId];
		auto* base_next = &worker->bases[worker->currentBaseId ^ 1];
		base_nexts.emplace_back(worker->socketId, base);
		base_nexts.emplace_back(worker->socketId, base_next);
	}
	for (auto& [core_id, worker] : worker_gcs)
	{
		(void)core_id;

		auto* base = &worker->bases[worker->current_base_id];
		auto* base_next = &worker->bases[worker->current_base_id ^ 1];
		base_nexts.emplace_back(worker->socket_id, base);
		base_nexts.emplace_back(worker->socket_id, base_next);
	}

	neighbor.update_worker_base(base_nexts);
}

int cDataPlane::lcoreThread(void* args)
{
	cDataPlane* dataPlane = (cDataPlane*)args;

	if (rte_lcore_id() == dataPlane->config.controlPlaneCoreId)
	{
		dataPlane->controlPlane->start();
		return 0;
	}

	if (exist(dataPlane->workers, rte_lcore_id()))
	{
		dataPlane->workers[rte_lcore_id()]->start();
	}
	else if (exist(dataPlane->worker_gcs, rte_lcore_id()))
	{
		dataPlane->worker_gcs[rte_lcore_id()]->start();
	}
	else
	{
		YADECAP_LOG_ERROR("invalid core id: '%u'\n", rte_lcore_id());
		/// @todo: stop
	}

	return 0;
}

void cDataPlane::timestamp_thread()
{
	uint32_t prev_time = 0;

	for (;;)
	{
		current_time = time(nullptr);

		if (current_time != prev_time)
		{
			for (const auto& [socket_id, globalbase_atomic] : globalBaseAtomics)
			{
				(void)socket_id;
				globalbase_atomic->currentTime = current_time;
			}

			prev_time = current_time;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
}

void cDataPlane::start()
{
	threads.emplace_back([this]() {
		timestamp_thread();
	});

	bus.run();

	/// run forwarding plane and control plane
	rte_eal_mp_remote_launch(lcoreThread, this, CALL_MAIN);
}

void cDataPlane::join()
{
	rte_eal_mp_wait_lcore();

	bus.join();
}

const std::set<tSocketId>& cDataPlane::get_socket_ids() const
{
	return socket_ids;
}

const std::vector<cWorker*>& cDataPlane::get_workers() const
{
	return workers_vector;
}

void cDataPlane::run_on_worker_gc(const tSocketId socket_id,
                                  const std::function<bool()>& callback)
{
	socket_worker_gcs.find(socket_id)->second->run_on_this_thread(callback);
}

eResult cDataPlane::allocateSharedMemory()
{
	/// precalculation of shared memory size for each numa
	std::map<tSocketId, uint64_t> number_of_workers_per_socket;
	for (const auto& worker : config.workers)
	{
		const int coreId = worker.first;

		auto socket_id = numa_node_of_cpu(coreId);
		if (socket_id == -1)
		{
			YADECAP_LOG_ERROR("numa_node_of_cpu err: %s\n", strerror(errno));
			socket_id = 0;
		}

		if (number_of_workers_per_socket.find(socket_id) == number_of_workers_per_socket.end())
		{
			number_of_workers_per_socket[socket_id] = 1;
		}
		else
		{
			number_of_workers_per_socket[socket_id]++;
		}
	}

	/// slow worker
	{
		const int coreId = config.controlPlaneCoreId;

		auto socket_id = numa_node_of_cpu(coreId);
		if (socket_id == -1)
		{
			YADECAP_LOG_ERROR("numa_node_of_cpu err: %s\n", strerror(errno));
			socket_id = 0;
		}

		if (number_of_workers_per_socket.find(socket_id) == number_of_workers_per_socket.end())
		{
			number_of_workers_per_socket[socket_id] = 1;
		}
		else
		{
			number_of_workers_per_socket[socket_id]++;
		}
	}

	std::map<tSocketId, uint64_t> shm_size_per_socket;
	for (const auto& ring_cfg : config.shared_memory)
	{
		const auto& [dump_size, dump_count] = ring_cfg.second;

		auto unit_size = sizeof(sharedmemory::item_header_t) + dump_size;
		if (unit_size % RTE_CACHE_LINE_SIZE != 0)
		{
			unit_size += RTE_CACHE_LINE_SIZE - unit_size % RTE_CACHE_LINE_SIZE; /// round up
		}

		auto size = sizeof(sharedmemory::ring_header_t) + unit_size * dump_count;

		for (const auto& [socket_id, num] : number_of_workers_per_socket)
		{
			auto it = shm_size_per_socket.find(socket_id);
			if (it == shm_size_per_socket.end())
			{
				it = shm_size_per_socket.emplace_hint(it, socket_id, 0);
			}
			it->second += size * num;
		}
	}

	for (const auto& [socket_id, num] : number_of_workers_per_socket)
	{
		auto it = shm_size_per_socket.find(socket_id);
		if (it == shm_size_per_socket.end())
		{
			it = shm_size_per_socket.emplace_hint(it, socket_id, 0);
		}

		it->second += sizeof(dataplane::perf::tsc_deltas) * (num + ((int)socket_id == numa_node_of_cpu(config.controlPlaneCoreId)));
	}

	/// allocating IPC shared memory
	key_t key = YANET_DEFAULT_IPC_SHMKEY;
	for (const auto& [socket_id, size] : shm_size_per_socket)
	{
		if (numa_run_on_node(socket_id) < 0)
		{
			YADECAP_LOG_ERROR("numa_run_on_node(%d): %s\n", socket_id, strerror(errno));
		}

		// deleting old shared memory if exists
		int shmid = shmget(key, 0, 0);
		if (shmid != -1)
		{
			if (shmctl(shmid, IPC_RMID, NULL) < 0)
			{
				YADECAP_LOG_ERROR("shmctl(%d, IPC_RMID, NULL): %s\n", shmid, strerror(errno));
				return eResult::errorInitSharedMemory;
			}
		}

		int flags = IPC_CREAT | 0666;
		if (config.useHugeMem)
		{
			flags |= SHM_HUGETLB;
		}

		shmid = shmget(key, size, flags);
		if (shmid == -1)
		{
			YADECAP_LOG_ERROR("shmget(%d, %lu, %d): %s\n", key, size, flags, strerror(errno));
			return eResult::errorInitSharedMemory;
		}

		void* shmaddr = shmat(shmid, NULL, 0);
		if (shmaddr == (void*)-1)
		{
			YADECAP_LOG_ERROR("shmat(%d, NULL, %d): %s\n", shmid, 0, strerror(errno));
			return eResult::errorInitSharedMemory;
		}

		shm_by_socket_id[socket_id] = std::make_tuple(key, shmaddr);

		key++;
	}

	return eResult::success;
}

eResult cDataPlane::splitSharedMemoryPerWorkers()
{
	std::map<void*, uint64_t> offsets;
	for (const auto& it : shm_by_socket_id)
	{
		const auto& addr = std::get<1>(it.second);
		offsets[addr] = 0;
	}

	/// split memory per worker
	for (auto& [core_id, worker] : workers)
	{
		const auto& socket_id = worker->socketId;
		const auto& it = shm_by_socket_id.find(socket_id);
		if (it == shm_by_socket_id.end())
		{
			continue;
		}

		const auto& [key, shm] = it->second;

		int ring_id = 0;
		for (const auto& [tag, ring_cfg] : config.shared_memory)
		{
			const auto& [dump_size, units_number] = ring_cfg;

			auto unit_size = sizeof(sharedmemory::item_header_t) + dump_size;
			if (unit_size % RTE_CACHE_LINE_SIZE != 0)
			{
				unit_size += RTE_CACHE_LINE_SIZE - unit_size % RTE_CACHE_LINE_SIZE; /// round up
			}

			auto size = sizeof(sharedmemory::ring_header_t) + unit_size * units_number;
			if (size % RTE_CACHE_LINE_SIZE != 0)
			{
				size += RTE_CACHE_LINE_SIZE - size % RTE_CACHE_LINE_SIZE; /// round up
			}

			auto name = "shm_" + std::to_string(core_id) + "_" + std::to_string(ring_id);

			auto offset = offsets[shm];

			auto memaddr = (void*)((intptr_t)shm + offset);

			sharedmemory::cSharedMemory ring;

			ring.init(memaddr, unit_size, units_number);

			offsets[shm] += size;

			worker->dumpRings[ring_id] = ring;

			auto meta = common::idp::get_shm_info::dump_meta(name, tag, unit_size, units_number, core_id, socket_id, key, offset);
			dumps_meta.emplace_back(meta);

			tag_to_id[tag] = ring_id;

			ring_id++;
		}
	}

	for (auto& [core_id, worker] : workers)
	{
		const auto& socket_id = worker->socketId;
		const auto& it = shm_by_socket_id.find(socket_id);
		if (it == shm_by_socket_id.end())
		{
			continue;
		}
		const auto& [key, shm] = it->second;

		auto offset = offsets[shm];
		worker->tsc_deltas = (dataplane::perf::tsc_deltas*)((intptr_t)shm + offset);
		memset(worker->tsc_deltas, 0, sizeof(dataplane::perf::tsc_deltas));
		offsets[shm] += sizeof(dataplane::perf::tsc_deltas);

		auto meta = common::idp::get_shm_tsc_info::tsc_meta(core_id, socket_id, key, offset);
		tscs_meta.emplace_back(meta);
	}

	return eResult::success;
}

common::idp::get_shm_info::response cDataPlane::getShmInfo()
{
	common::idp::get_shm_info::response result;
	result.reserve(dumps_meta.size());

	std::copy(dumps_meta.begin(), dumps_meta.end(), std::back_inserter(result));

	return result;
}

common::idp::get_shm_tsc_info::response cDataPlane::getShmTscInfo()
{
	common::idp::get_shm_tsc_info::response result;
	result.reserve(tscs_meta.size());

	std::copy(tscs_meta.begin(), tscs_meta.end(), std::back_inserter(result));

	return result;
}

std::map<std::string, common::uint64> cDataPlane::getPortStats(const tPortId& portId) const
{
	/// unsafe

	std::map<std::string, common::uint64> result;

	{
		rte_eth_link link;
		{
			std::lock_guard<std::mutex> guard(dpdk_mutex);
			rte_eth_link_get_nowait(portId, &link);
		}

		if (link.link_speed == RTE_ETH_SPEED_NUM_UNKNOWN)
		{
			result["link_speed"] = RTE_ETH_SPEED_NUM_10G;
		}
		else
		{
			result["link_speed"] = link.link_speed;
		}
		result["link_duplex"] = link.link_duplex;
		result["link_autoneg"] = link.link_autoneg;
		result["link_status"] = link.link_status;
	}

	constexpr uint64_t xstatNamesSize = 512;
	constexpr uint64_t xstatsSize = 512;

	rte_eth_xstat_name xstatNames[xstatNamesSize];
	rte_eth_xstat xstats[xstatsSize];
	int xstatNamesCount_i = 0;
	int xstatsCount_i = 0;
	{
		std::lock_guard<std::mutex> guard(dpdk_mutex);
		xstatNamesCount_i = rte_eth_xstats_get_names(portId, xstatNames, xstatNamesSize);
		xstatsCount_i = rte_eth_xstats_get(portId, xstats, xstatsSize);
	}

	if (xstatNamesCount_i <= 0 ||
	    xstatsCount_i <= 0)
	{
		YADECAP_LOG_WARNING("get port stats failed\n");
		return result;
	}

	uint64_t xstatNamesCount = xstatNamesCount_i;
	uint64_t xstatsCount = xstatsCount_i;

	xstatNamesCount = RTE_MIN(xstatNamesCount, xstatNamesSize);
	xstatsCount = RTE_MIN(xstatsCount, xstatsSize);

	for (unsigned int i = 0;
	     i < xstatsCount;
	     i++)
	{
		rte_eth_xstat& xstat = xstats[i];

		if (xstat.id >= xstatNamesCount)
		{
			continue;
		}

		xstatNames[xstat.id].name[RTE_ETH_XSTATS_NAME_SIZE - 1] = 0;

		result[xstatNames[xstat.id].name] = xstat.value;
	}

	return result;
}

std::optional<tPortId> cDataPlane::interface_name_to_port_id(const std::string& interface_name)
{
	for (const auto& [port_id, port] : ports)
	{
		const auto& port_interface_name = std::get<0>(port);
		if (port_interface_name == interface_name)
		{
			return port_id;
		}
	}

	/// unknown interface
	return std::nullopt;
}

void cDataPlane::switch_worker_base()
{
	std::lock_guard<std::mutex> guard(switch_worker_base_mutex);

	/// collect all base_next
	std::vector<std::tuple<tSocketId, dataplane::base::generation*>> base_nexts;
	for (auto& [core_id, worker] : workers)
	{
		(void)core_id;

		auto* base_next = &worker->bases[worker->currentBaseId ^ 1];
		base_nexts.emplace_back(worker->socketId, base_next);
	}
	for (auto& [core_id, worker] : worker_gcs)
	{
		(void)core_id;

		auto* base_next = &worker->bases[worker->current_base_id ^ 1];
		base_nexts.emplace_back(worker->socket_id, base_next);
	}

	/// update base_next
	{
		std::lock_guard<std::mutex> guard(currentGlobalBaseId_mutex);
		for (const auto& [socket_id, base_next] : base_nexts)
		{
			base_next->globalBase = globalBases[socket_id][currentGlobalBaseId];
		}
	}
	neighbor.update_worker_base(base_nexts);

	/// switch
	controlPlane->switchBase();
}

eResult cDataPlane::parseConfig(const std::string& configFilePath)
{
	eResult result = eResult::success;

	std::ifstream fromFileStream(configFilePath);
	if (!fromFileStream.is_open())
	{
		YADECAP_LOG_ERROR("can't open file '%s'\n", configFilePath.data());
		return eResult::errorOpenFile;
	}

	nlohmann::json rootJson = nlohmann::json::parse(fromFileStream, nullptr, /* allow_exceptions */ false);
	if (rootJson.is_discarded())
	{
		YADECAP_LOG_ERROR("failed to parse configuration file: malformed JSON\n");
		return eResult::invalidConfigurationFile;
	}

	if (rootJson.find("ports") == rootJson.end())
	{
		YADECAP_LOG_ERROR("not found: 'ports'\n");
		return eResult::invalidConfigurationFile;
	}

	if (rootJson.find("workerGC") == rootJson.end())
	{
		YADECAP_LOG_ERROR("not found: 'workerGC'\n");
		return eResult::invalidConfigurationFile;
	}

	if (rootJson.find("controlPlaneCoreId") == rootJson.end())
	{
		YADECAP_LOG_ERROR("not found: 'controlPlaneCoreId'\n");
		return eResult::invalidConfigurationFile;
	}

	result = parseJsonPorts(rootJson.find("ports").value());
	if (result != eResult::success)
	{
		return result;
	}

	for (const auto& core_id : rootJson.find("workerGC").value())
	{
		config.workerGCs.emplace(core_id);
	}
	config.controlPlaneCoreId = rootJson.find("controlPlaneCoreId").value();

	if (rootJson.find("configValues") != rootJson.end())
	{
		result = parseConfigValues(rootJson.find("configValues").value());
		if (result != eResult::success)
		{
			return result;
		}
	}

	if (rootJson.find("hugeMem") != rootJson.end())
	{
		config.useHugeMem = rootJson.find("hugeMem").value();
	}

	if (rootJson.find("useKni") != rootJson.end())
	{
		config.use_kernel_interface = rootJson.find("useKni").value();
	}
	if (rootJson.find("use_kernel_interface") != rootJson.end())
	{
		config.use_kernel_interface = rootJson.find("use_kernel_interface").value();
	}

	config.interfaces_required = rootJson.value("interfacesRequired", config.interfaces_required);

	if (rootJson.find("rateLimits") != rootJson.end())
	{
		result = parseRateLimits(rootJson.find("rateLimits").value());
		if (result != eResult::success)
		{
			return result;
		}
	}

	config.memory = std::to_string(rootJson.value("memory", 0));

	if (rootJson.find("memory_numa") != rootJson.end())
	{
		config.memory = rootJson.find("memory_numa").value();
	}

	if (rootJson.find("sharedMemory") != rootJson.end())
	{
		result = parseSharedMemory(rootJson.find("sharedMemory").value());
		if (result != eResult::success)
		{
			return result;
		}
	}

	auto it = rootJson.find("ealArgs");
	if (it != rootJson.end())
	{
		for (auto& arg : *it)
		{
			config.ealArgs.emplace_back(arg);
		}
	}

	result = checkConfig();
	if (result != eResult::success)
	{
		return result;
	}

	return result;
}

eResult cDataPlane::parseJsonPorts(const nlohmann::json& json)
{
	for (const auto& portJson : json)
	{
		std::string interfaceName = portJson["interfaceName"];
		std::string pci = portJson["pci"];
		std::string name = pci;
		bool symmetric_mode = false;
		uint64_t rss_flags = 0;

		if (exist(config.ports, interfaceName))
		{
			YADECAP_LOG_ERROR("interfaceName '%s' already exist\n", interfaceName.data());
			return eResult::invalidConfigurationFile;
		}

		if (exist(portJson, "name"))
		{
			name = portJson["name"];
		}

		if (exist(portJson, "symmetric_mode"))
		{
			symmetric_mode = portJson["symmetric_mode"];
		}

		auto rssFlagsJson = portJson.find("rssFlags");
		if (rssFlagsJson != portJson.end())
		{
			for (const auto& flag : rssFlagsJson.value())
			{
				rss_flags |= string_to_rss_flag(flag.get<std::string>());
			}
		}
		else
		{
			YADECAP_LOG_WARNING("not found: 'rssFlags', using default 'IP'\n");
			rss_flags = RTE_ETH_RSS_IP;
		}

		config.ports[interfaceName] = {pci, name, symmetric_mode, rss_flags};

		for (tCoreId coreId : portJson["coreIds"])
		{
			if (exist(config.workers, coreId))
			{
				YADECAP_LOG_ERROR("worker on core '%u' already exist\n", coreId);
				return eResult::invalidConfigurationFile;
			}

			for (const auto& iter : config.workers[coreId])
			{
				if (iter == interfaceName)
				{
					YADECAP_LOG_ERROR("interfaceName '%s' already exist\n", interfaceName.data());
					return eResult::invalidConfigurationFile;
				}
			}

			config.workers[coreId].emplace_back(interfaceName);
		}
	}

	return eResult::success;
}

eResult cDataPlane::parseConfigValues(const nlohmann::json& json)
{
	configValues = json;
	return eResult::success;
}

eResult cDataPlane::parseRateLimits(const nlohmann::json& json)
{
	config.rateLimitDivisor = json.value("rateLimitDivisor", 1);

	if (config.rateLimitDivisor == 0)
	{
		config.rateLimitDivisor = 1;
	}

	if (json.find("InNormalPriorityRing") != json.end())
	{
		config.SWNormalPriorityRateLimitPerWorker = json.find("InNormalPriorityRing").value();
		config.SWNormalPriorityRateLimitPerWorker /= config.workers.size();
		config.SWNormalPriorityRateLimitPerWorker /= config.rateLimitDivisor;
	}

	config.SWICMPOutRateLimit = json.value("OutICMP", 0);

	return eResult::success;
}

eResult cDataPlane::parseSharedMemory(const nlohmann::json& json)
{
	for (const auto& shmJson : json)
	{
		std::string tag = shmJson["tag"];
		unsigned int size = shmJson["dump_size"];
		unsigned int count = shmJson["dump_count"];

		if (exist(config.shared_memory, tag))
		{
			YADECAP_LOG_ERROR("tag '%s' already exist\n", tag.data());
			return eResult::invalidConfigurationFile;
		}

		config.shared_memory[tag] = {size, count};
	}

	return eResult::success;
}

eResult cDataPlane::checkConfig()
{
	if (config.ports.size() > CONFIG_YADECAP_PORTS_SIZE)
	{
		YADECAP_LOG_ERROR("invalid ports count: '%lu'\n", config.ports.size());
		return eResult::invalidConfigurationFile;
	}

	if (config.controlPlaneCoreId >= std::thread::hardware_concurrency())
	{
		YADECAP_LOG_ERROR("invalid coreId: '%u'\n", config.controlPlaneCoreId);
		return eResult::invalidConfigurationFile;
	}

	{
		std::set<std::string> names;
		for (const auto& portIter : config.ports)
		{
			const auto& [pci, name, symmetric_mode, rss_flags] = portIter.second;
			(void)pci;
			(void)symmetric_mode;
			(void)rss_flags;

			if (exist(names, name))
			{
				YADECAP_LOG_ERROR("pci '%s' already exist\n", name.data());
				return eResult::invalidConfigurationFile;
			}

			names.emplace(name);
		}
	}

	for (const auto& workerIter : config.workers)
	{
		const tCoreId& coreId = workerIter.first;

		if (coreId >= std::thread::hardware_concurrency() ||
		    coreId == config.controlPlaneCoreId)
		{
			YADECAP_LOG_ERROR("invalid coreId: '%u'\n", coreId);
			return eResult::invalidConfigurationFile;
		}

		for (const auto& workerPort : workerIter.second)
		{
			if (!exist(config.ports, workerPort))
			{
				YADECAP_LOG_ERROR("invalid interfaceName: '%s'\n", workerPort.data());
				return eResult::invalidConfigurationFile;
			}
		}
	}

	return eResult::success;
}

eResult cDataPlane::initEal(const std::string& binaryPath,
                            const std::string& filePrefix)
{
#define insert_eal_arg(args...)                                                                               \
	do                                                                                                    \
	{                                                                                                     \
		eal_argv[eal_argc++] = &buffer[bufferPosition];                                               \
		bufferPosition += snprintf(&buffer[bufferPosition], sizeof(buffer) - bufferPosition, ##args); \
		bufferPosition++;                                                                             \
	} while (0)

	unsigned int bufferPosition = 0;
	char buffer[8192];

	unsigned int eal_argc = 0;
	char* eal_argv[128];

	insert_eal_arg("%s", binaryPath.data());

	for (auto& arg : config.ealArgs)
	{
		insert_eal_arg("%s", arg.c_str());
	}

	insert_eal_arg("-c");

	uint64_t coresMask = 0;
	coresMask |= (((uint64_t)1) << (uint64_t)config.controlPlaneCoreId);
	for (const auto& coreId : config.workerGCs)
	{
		coresMask |= (((uint64_t)1) << (uint64_t)coreId);
	}
	for (const auto& iter : config.workers)
	{
		const tCoreId& coreId = iter.first;
		coresMask |= (((uint64_t)1) << (uint64_t)coreId);
	}
	insert_eal_arg("0x%" PRIx64, coresMask);

#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
	insert_eal_arg("--main-lcore");
	insert_eal_arg("%u", config.controlPlaneCoreId);
#else
	insert_eal_arg("--master-lcore");
	insert_eal_arg("%u", config.controlPlaneCoreId);
#endif

	if (!config.useHugeMem)
	{
		insert_eal_arg("--no-huge");
	}

	insert_eal_arg("--proc-type=primary");

	for (const auto& port : config.ports)
	{
		const auto& [pci, name, symmetric_mode, rss_flags] = port.second;
		(void)name;
		(void)symmetric_mode;
		(void)rss_flags;

		// Do not whitelist sock dev virtual devices
		if (strncmp(pci.data(), SOCK_DEV_PREFIX, strlen(SOCK_DEV_PREFIX)) == 0)
		{
			continue;
		}

#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
		insert_eal_arg("-a");
		insert_eal_arg("%s", pci.data());
#else
		insert_eal_arg("--pci-whitelist=%s", pci.data());
#endif
	}

	if (!config.memory.empty())
	{
		if (config.useHugeMem)
		{
			insert_eal_arg("--socket-mem=%s", config.memory.data());
			insert_eal_arg("--socket-limit=%s", config.memory.data());
		}
		else
		{
			insert_eal_arg("-m %s", config.memory.data());
		}
	}

	if (filePrefix.size())
	{
		insert_eal_arg("--file-prefix=%s", filePrefix.data());
	}

	eal_argv[eal_argc] = nullptr;

	int ret = rte_eal_init(eal_argc, eal_argv);
	if (ret < 0)
	{
		YADECAP_LOG_ERROR("rte_eal_init() = %d\n", ret);
		return eResult::errorInitEal;
	}

	return eResult::success;

#undef insert_eal_arg
}
