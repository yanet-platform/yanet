#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <iostream>
#include <thread>
#include <fstream>

#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_eth_ring.h>

#include "common.h"
#include "dataplane.h"
#include "report.h"
#include "sock_dev.h"
#include "worker.h"

common::log::LogPriority common::log::logPriority = common::log::TLOG_INFO;

YADECAP_UNUSED
static void printHugepageMemory(const char* prefix, tSocketId socketId) ///< @todo
{
	rte_malloc_socket_stats stats;
	if (rte_malloc_get_socket_stats(socketId, &stats) == 0)
	{
		YADECAP_LOG_INFO("%sheap_totalsz_bytes: %lu MB\n", prefix, stats.heap_totalsz_bytes / (1024 * 1024));
		YADECAP_LOG_INFO("%sheap_freesz_bytes: %lu MB\n", prefix, stats.heap_freesz_bytes / (1024 * 1024));
		YADECAP_LOG_INFO("%sgreatest_free_size: %lu MB\n", prefix, stats.greatest_free_size / (1024 * 1024));
		YADECAP_LOG_INFO("%sfree_count: %u\n", prefix, stats.free_count);
		YADECAP_LOG_INFO("%salloc_count: %u\n", prefix, stats.alloc_count);
		YADECAP_LOG_INFO("%sheap_allocsz_bytes: %lu MB\n", prefix, stats.heap_allocsz_bytes / (1024 * 1024));
	}
}

YADECAP_UNUSED
static unsigned int getMaximumSpeed(const rte_eth_dev_info& devInfo)
{
	uint32_t speedCapabilities = devInfo.speed_capa;

	if (speedCapabilities & RTE_ETH_LINK_SPEED_100G)
	{
		return 100000;
	}
	else if (speedCapabilities & RTE_ETH_LINK_SPEED_40G)
	{
		return 40000;
	}
	else if (speedCapabilities & RTE_ETH_LINK_SPEED_25G)
	{
		return 25000;
	}
	else if (speedCapabilities & RTE_ETH_LINK_SPEED_10G)
	{
		return 10000;
	}
	else if (speedCapabilities & RTE_ETH_LINK_SPEED_1G)
	{
		return 1000;
	}
	else if (speedCapabilities & (RTE_ETH_LINK_SPEED_100M | RTE_ETH_LINK_SPEED_100M_HD))
	{
		return 100;
	}
	else if (speedCapabilities & (RTE_ETH_LINK_SPEED_10M | RTE_ETH_LINK_SPEED_10M_HD))
	{
		return 10;
	}

	return 0;
}

cDataPlane::cDataPlane() :
        currentGlobalBaseId(0),
        globalBaseSerial(0),
        report(this),
        controlPlane(new cControlPlane(this)),
        bus(this)
{
	configValues = {{eConfigType::port_rx_queue_size, 4096},
	                {eConfigType::port_tx_queue_size, 4096},
	                {eConfigType::ring_highPriority_size, 64},
	                {eConfigType::ring_normalPriority_size, 256},
	                {eConfigType::ring_lowPriority_size, 64},
	                {eConfigType::ring_toFreePackets_size, 64},
	                {eConfigType::ring_log_size, 1024},
	                {eConfigType::fragmentation_size, 1024},
	                {eConfigType::fragmentation_timeout_first, 32},
	                {eConfigType::fragmentation_timeout_last, 16},
	                {eConfigType::fragmentation_packets_per_flow, 64},
	                {eConfigType::stateful_firewall_tcp_timeout, 120},
	                {eConfigType::stateful_firewall_udp_timeout, 30},
	                {eConfigType::stateful_firewall_other_protocols_timeout, 16},
	                {eConfigType::gc_step, 8},
	                {eConfigType::sample_gc_step, 512},
	                {eConfigType::acl_states4_ht_size, YANET_CONFIG_ACL_STATES4_HT_SIZE},
	                {eConfigType::acl_states6_ht_size, YANET_CONFIG_ACL_STATES6_HT_SIZE},
	                {eConfigType::acl_network_lpm4_chunks_size, YANET_CONFIG_ACL_NETWORK_LPM4_EXTENDED_CHUNKS_SIZE},
	                {eConfigType::acl_network_source_lpm6_chunks_size, YANET_CONFIG_ACL_NETWORK_SOURCE_LPM6_CHUNKS_SIZE},
	                {eConfigType::acl_network_destination_lpm6_chunks_size, YANET_CONFIG_ACL_NETWORK_DESTINATION_LPM6_CHUNKS_SIZE},
	                {eConfigType::acl_network_destination_ht_size, YANET_CONFIG_ACL_NETWORK_DESTINATION_HT_SIZE},
	                {eConfigType::acl_network_table_size, YANET_CONFIG_ACL_NETWORK_TABLE_SIZE},
	                {eConfigType::acl_transport_layers_size, YANET_CONFIG_ACL_TRANSPORT_LAYERS_SIZE},
	                {eConfigType::acl_transport_ht_size, YANET_CONFIG_ACL_TRANSPORT_HT_SIZE},
	                {eConfigType::acl_total_ht_size, YANET_CONFIG_ACL_TOTAL_HT_SIZE},
	                {eConfigType::acl_values_size, YANET_CONFIG_ACL_VALUES_SIZE},
	                {eConfigType::master_mempool_size, 8192},
	                {eConfigType::nat64stateful_states_size, YANET_CONFIG_NAT64STATEFUL_HT_SIZE}};
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

	/// sanity check
	if (rte_eth_dev_count_avail() != ports.size())
	{
		YADECAP_LOG_ERROR("invalid ports count: %u != %lu\n",
		                  rte_eth_dev_count_avail(),
		                  ports.size());
		return eResult::invalidPortsCount;
	}

	mempool_log = rte_mempool_create("log", YANET_CONFIG_SAMPLES_SIZE,
					sizeof(samples::sample_t), 0, 0,
					NULL, NULL, NULL, NULL,
					SOCKET_ID_ANY, MEMPOOL_F_NO_IOVA_CONTIG);

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

	result = report.init();
	if (result != eResult::success)
	{
		return result;
	}

	result = controlPlane->init(config.useKni);
	if (result != eResult::success)
	{
		return result;
	}

	result = bus.init();
	if (result != eResult::success)
	{
		return result;
	}

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

eResult cDataPlane::initPorts()
{
	std::vector<std::string> remove_keys;

	for (const auto& configPortIter : config.ports)
	{
		const std::string& interfaceName = configPortIter.first;
		const auto& [pci, bind] = configPortIter.second;
		(void)bind;

		tPortId portId;
		if (strncmp(pci.data(), SOCK_DEV_PREFIX, strlen(SOCK_DEV_PREFIX)) == 0)
		{
			portId = sock_dev_create(pci.data(), 0);
		}
		else if (rte_eth_dev_get_port_by_name(pci.data(), &portId))
		{
			YADECAP_LOG_ERROR("invalid pci: '%s'\n", pci.data());
			remove_keys.emplace_back(interfaceName);
			continue;
		}

		YADECAP_LOG_INFO("portId: %u, socketId: %u, interfaceName: %s, pci: %s\n",
		                  portId,
		                  rte_eth_dev_socket_id(portId),
		                  interfaceName.data(),
		                  pci.data());

		std::get<0>(ports[portId]) = interfaceName;
		std::get<3>(ports[portId]) = pci;

		rte_ether_addr etherAddress;
		rte_eth_macaddr_get(portId, &etherAddress);
		memcpy(std::get<2>(ports[portId]).data(), etherAddress.addr_bytes, 6);

		rte_eth_dev_info devInfo;
		rte_eth_dev_info_get(portId, &devInfo);

		unsigned int speed = getMaximumSpeed(devInfo);
		if (!speed)
		{
			YADECAP_LOG_ERROR("unsupported device\n");
			return eResult::unsupportedDevice;
		}

		rte_eth_conf portConf;
		memset(&portConf, 0, sizeof(rte_eth_conf));

		if (config.rssFlags != 0)
		{
			portConf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;

			YADECAP_LOG_INFO("device info: flow type rss offloads 0x%lx\n", devInfo.flow_type_rss_offloads);
			YADECAP_LOG_INFO("config.rssFlags: 0x%lx\n", config.rssFlags);
			if ((devInfo.flow_type_rss_offloads | config.rssFlags) == devInfo.flow_type_rss_offloads)
			{
				portConf.rx_adv_conf.rss_conf.rss_hf = config.rssFlags;
			}
			else
			{
				YADECAP_LOG_WARNING("config.rssFlags 0x%lx not supported, fallback to 0x%lx\n",
									config.rssFlags, (uint64_t)RTE_ETH_RSS_IP);
				portConf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_IP;
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

		uint16_t rxQueuesCount = 0;
		uint16_t txQueuesCount = config.workers.size() + 1; ///< tx queue '0' for control plane
		for (const auto& configWorkerIter : config.workers)
		{
			const tCoreId& coreId = configWorkerIter.first;

			for (const auto& workerInterfaceName : configWorkerIter.second)
			{
				if (interfaceName == workerInterfaceName)
				{
					std::get<1>(ports[portId])[coreId] = rxQueuesCount;
					rxQueuesCount++;
				}
			}
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

		rte_eth_stats_reset(portId);
	}

	for (const auto& interface_name : remove_keys)
	{
		config.ports.erase(interface_name);
	}

	for (const auto& [port_id, port] : ports)
	{
		(void)port;

		if (port_id >= ports.size())
		{
			YADECAP_LOG_ERROR("invalid portId: '%u'\n", port_id);
			return eResult::invalidPortId;
		}

	}

	return eResult::success;
}

eResult cDataPlane::initGlobalBases()
{
	eResult result = eResult::success;

	auto create_globalbase_atomics = [this](const tSocketId& socket_id) -> eResult
	{
		if (globalBaseAtomics.find(socket_id) == globalBaseAtomics.end())
		{
			auto* globalbase_atomic = hugepage_create_static<dataplane::globalBase::atomic>(socket_id,
			                                                                                this, socket_id);
			if (!globalbase_atomic)
			{
				return eResult::errorAllocatingMemory;
			}

			{
				auto* ipv4_states_ht = hugepage_create_dynamic<dataplane::globalBase::acl::ipv4_states_ht>(socket_id, getConfigValue(eConfigType::acl_states4_ht_size),
				                                                                                           globalbase_atomic->updater.fw4_state);
				if (!ipv4_states_ht)
				{
					return eResult::errorAllocatingMemory;
				}

				auto* ipv6_states_ht = hugepage_create_dynamic<dataplane::globalBase::acl::ipv6_states_ht>(socket_id, getConfigValue(eConfigType::acl_states6_ht_size),
				                                                                                           globalbase_atomic->updater.fw6_state);
				if (!ipv6_states_ht)
				{
					return eResult::errorAllocatingMemory;
				}

				auto* nat64stateful_lan_state = hugepage_create_dynamic<dataplane::globalBase::nat64stateful::lan_ht>(socket_id, getConfigValue(eConfigType::nat64stateful_states_size),
				                                                                                                      globalbase_atomic->updater.nat64stateful_lan_state);
				if (!nat64stateful_lan_state)
				{
					return eResult::errorAllocatingMemory;
				}

				auto* nat64stateful_wan_state = hugepage_create_dynamic<dataplane::globalBase::nat64stateful::wan_ht>(socket_id, getConfigValue(eConfigType::nat64stateful_states_size),
				                                                                                                      globalbase_atomic->updater.nat64stateful_wan_state);
				if (!nat64stateful_wan_state)
				{
					return eResult::errorAllocatingMemory;
				}

				globalbase_atomic->fw4_state = ipv4_states_ht;
				globalbase_atomic->fw6_state = ipv6_states_ht;
				globalbase_atomic->nat64stateful_lan_state = nat64stateful_lan_state;
				globalbase_atomic->nat64stateful_wan_state = nat64stateful_wan_state;
			}

			globalBaseAtomics[socket_id] = globalbase_atomic;
		}

		return eResult::success;
	};

	auto create_globalbase = [this](const tSocketId& socket_id) -> dataplane::globalBase::generation*
	{
		auto* globalbase = hugepage_create_static<dataplane::globalBase::generation>(socket_id,
		                                                                             this, socket_id);
		if (!globalbase)
		{
			return nullptr;
		}

		{
			auto* acl_network_ipv4_source = hugepage_create_dynamic<dataplane::globalBase::acl::network_ipv4_source>(socket_id, getConfigValue(eConfigType::acl_network_lpm4_chunks_size),
			                                                                                                         globalbase->updater.acl.network_ipv4_source);
			if (!acl_network_ipv4_source)
			{
				return nullptr;
			}

			auto* acl_network_ipv4_destination = hugepage_create_dynamic<dataplane::globalBase::acl::network_ipv4_destination>(socket_id, getConfigValue(eConfigType::acl_network_lpm4_chunks_size),
			                                                                                                                   globalbase->updater.acl.network_ipv4_destination);
			if (!acl_network_ipv4_destination)
			{
				return nullptr;
			}

			auto* acl_network_ipv6_source = hugepage_create_dynamic<dataplane::globalBase::acl::network_ipv6_source>(socket_id, getConfigValue(eConfigType::acl_network_source_lpm6_chunks_size),
			                                                                                                         globalbase->updater.acl.network_ipv6_source);
			if (!acl_network_ipv6_source)
			{
				return nullptr;
			}

			auto* acl_network_ipv6_destination_ht = hugepage_create_dynamic<dataplane::globalBase::acl::network_ipv6_destination_ht>(socket_id, getConfigValue(eConfigType::acl_network_destination_ht_size),
			                                                                                                                         globalbase->updater.acl.network_ipv6_destination_ht);
			if (!acl_network_ipv6_destination_ht)
			{
				return nullptr;
			}

			auto* acl_network_ipv6_destination = hugepage_create_dynamic<dataplane::globalBase::acl::network_ipv6_destination>(socket_id, getConfigValue(eConfigType::acl_network_destination_lpm6_chunks_size),
			                                                                                                                   globalbase->updater.acl.network_ipv6_destination);
			if (!acl_network_ipv6_destination)
			{
				return nullptr;
			}

			auto* acl_network_table = hugepage_create_dynamic<dataplane::globalBase::acl::network_table>(socket_id, getConfigValue(eConfigType::acl_network_table_size),
			                                                                                             globalbase->updater.acl.network_table);
			if (!acl_network_table)
			{
				return nullptr;
			}

			const auto acl_transport_layers_size = getConfigValue(eConfigType::acl_transport_layers_size);
			if ((!acl_transport_layers_size) ||
			    acl_transport_layers_size > 0xFFFFFFFFull)
			{
				YANET_LOG_ERROR("wrong acl_transport_layers_size: %lu\n", acl_transport_layers_size);
				return nullptr;
			}

			if (__builtin_popcount(acl_transport_layers_size) != 1)
			{
				YANET_LOG_ERROR("wrong acl_transport_layers_size: %lu is non power of 2\n", acl_transport_layers_size);
				return nullptr;
			}

			auto* acl_transport_layers = hugepage_create_static_array<dataplane::globalBase::acl::transport_layer_t>(socket_id, acl_transport_layers_size);
			if (!acl_transport_layers)
			{
				return nullptr;
			}

			auto* acl_transport_table = hugepage_create_dynamic<dataplane::globalBase::acl::transport_table>(socket_id, getConfigValue(eConfigType::acl_transport_ht_size),
			                                                                                                 globalbase->updater.acl.transport_table);
			if (!acl_transport_table)
			{
				return nullptr;
			}

			auto* acl_total_table = hugepage_create_dynamic<dataplane::globalBase::acl::total_table>(socket_id, getConfigValue(eConfigType::acl_total_ht_size),
			                                                                                         globalbase->updater.acl.total_table);
			if (!acl_total_table)
			{
				return nullptr;
			}

			const auto acl_values_size = getConfigValue(eConfigType::acl_values_size);
			if (acl_values_size < 2)
			{
				YANET_LOG_ERROR("wrong acl_values_size: %lu\n", acl_values_size);
				return nullptr;
			}

			auto* acl_values = hugepage_create_static_array<common::acl::value_t>(socket_id, getConfigValue(eConfigType::acl_values_size));
			if (!acl_values)
			{
				return nullptr;
			}

			globalbase->acl.network.ipv4.source = acl_network_ipv4_source;
			globalbase->acl.network.ipv4.destination = acl_network_ipv4_destination;
			globalbase->acl.network.ipv6.source = acl_network_ipv6_source;
			globalbase->acl.network.ipv6.destination_ht = acl_network_ipv6_destination_ht;
			globalbase->acl.network.ipv6.destination = acl_network_ipv6_destination;
			globalbase->acl.network_table = acl_network_table;
			globalbase->acl.transport_layers_mask = acl_transport_layers_size - 1;
			globalbase->acl.transport_layers = acl_transport_layers;
			globalbase->acl.transport_table = acl_transport_table;
			globalbase->acl.total_table = acl_total_table;
			globalbase->acl.values = acl_values;
		}

		return globalbase;
	};

	auto create_globalbases = [&](const tSocketId& socket_id) -> eResult
	{
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
	}

	for (const auto& configWorkerIter: config.workers)
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

		auto* worker = hugepage_create_static<cWorker>(socket_id,
		                                               this);
		if (!worker)
		{
			return eResult::errorAllocatingMemory;
		}

		dataplane::base::permanently basePermanently;
		basePermanently.globalBaseAtomic = globalBaseAtomics[socket_id];
		basePermanently.outQueueId = outQueueId; ///< 0
		basePermanently.ports_count = ports.size();
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

		outQueueId++;
	}

	for (const auto& configWorkerIter: config.workers)
	{
		const tCoreId& coreId = configWorkerIter.first;
		const tSocketId socket_id = rte_lcore_to_socket_id(coreId);

		YADECAP_LOG_INFO("initWorker. coreId: %u\n", coreId);

		auto* worker = hugepage_create_static<cWorker>(socket_id,
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

		for (const auto& portIter : ports)
		{
			const auto& portId = portIter.first;
			const auto& rxQueues = std::get<1>(portIter.second);

			if (exist(rxQueues, coreId))
			{
				basePermanently.workerPorts[basePermanently.workerPortsCount].inPortId = portId;
				basePermanently.workerPorts[basePermanently.workerPortsCount].inQueueId = rxQueues.find(coreId)->second;
				basePermanently.workerPortsCount++;
			}
		}
		basePermanently.outQueueId = outQueueId;
		basePermanently.ports_count = ports.size();

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

		outQueueId++;
	}

	/// worker_gc
	for (const auto& core_id: config.workerGCs)
	{
		const tSocketId socket_id = rte_lcore_to_socket_id(core_id);

		YADECAP_LOG_INFO("initWorker. coreId: %u [worker_gc]\n", core_id);

		auto* worker = hugepage_create_static<worker_gc_t>(socket_id,
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
	}

	return eResult::success;
}

std::optional<uint64_t> cDataPlane::getCounterValueByName(const std::string &counter_name, uint32_t coreId)
{
	if (coreId_to_stats_tables.count(coreId) == 0)
	{
		return std::optional<uint64_t>();
	}

	const auto &specific_core_table = coreId_to_stats_tables[coreId];

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
			                                 getConfigValue(eConfigType::port_tx_queue_size),
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

void cDataPlane::hugepage_destroy(void* pointer)
{
	auto it = hugepage_pointers.find(pointer);
	if (it == hugepage_pointers.end())
	{
		YADECAP_LOG_ERROR("unknown pointer: %p\n", pointer);
		return;
	}

	hugepage_pointers.erase(it);
}

void cDataPlane::hugepage_debug(tSocketId socket_id)
{
	rte_malloc_socket_stats stats;
	if (rte_malloc_get_socket_stats(socket_id, &stats) == 0)
	{
		YADECAP_LOG_INFO("heap_totalsz_bytes: %lu MB\n", stats.heap_totalsz_bytes / (1024 * 1024));
		YADECAP_LOG_INFO("heap_freesz_bytes: %lu MB\n", stats.heap_freesz_bytes / (1024 * 1024));
		YADECAP_LOG_INFO("greatest_free_size: %lu MB\n", stats.greatest_free_size / (1024 * 1024));
		YADECAP_LOG_INFO("free_count: %u\n", stats.free_count);
		YADECAP_LOG_INFO("alloc_count: %u\n", stats.alloc_count);
		YADECAP_LOG_INFO("heap_allocsz_bytes: %lu MB\n", stats.heap_allocsz_bytes / (1024 * 1024));
	}
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

void cDataPlane::start()
{
	report.run();
	bus.run();

	/// run forwarding plane and control plane
	rte_eal_mp_remote_launch(lcoreThread, this, CALL_MAIN);
}

void cDataPlane::join()
{
	rte_eal_mp_wait_lcore();

	report.join();
	bus.join();
}

uint64_t cDataPlane::getConfigValue(const eConfigType& type) const
{
	if (configValues.find(type) == configValues.end())
	{
		YADECAP_LOG_ERROR("unknown variable\n");
		return 0;
	}

	return configValues.find(type)->second;
}

std::map<std::string, common::uint64> cDataPlane::getPortStats(const tPortId& portId) const
{
	/// unsafe

	std::map<std::string, common::uint64> result;

	{
		rte_eth_link link;
		rte_eth_link_get_nowait(portId, &link);

		result["link_speed"] = link.link_speed;
		result["link_duplex"] = link.link_duplex;
		result["link_autoneg"] = link.link_autoneg;
		result["link_status"] = link.link_status;
	}

	constexpr uint64_t xstatNamesSize = 512;
	constexpr uint64_t xstatsSize = 512;

	rte_eth_xstat_name xstatNames[xstatNamesSize];
	rte_eth_xstat xstats[xstatsSize];
	int xstatNamesCount_i = rte_eth_xstats_get_names(portId, xstatNames, xstatNamesSize);
	int xstatsCount_i = rte_eth_xstats_get(portId, xstats, xstatsSize);

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
		config.useKni = rootJson.find("useKni").value();
	}

	if (config.useKni)
	{
		if (rootJson.find("dumpKniCoreId") == rootJson.end())
		{
			YADECAP_LOG_ERROR("not found: 'dumpKniCoreId'\n");
			return eResult::invalidConfigurationFile;
		}
		config.dumpKniCoreId = rootJson.find("dumpKniCoreId").value();
	}
	else
	{
		config.dumpKniCoreId = 0;
	}

	auto rssDepth = rootJson.find("rssDepth");
	if (rssDepth != rootJson.end())
	{
		if (rssDepth.value() == "L4" || rssDepth.value() == "l4")
		{
			config.rssFlags = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;
		}
		else if (rssDepth.value() == "L3" || rssDepth.value() == "l3")
		{
			config.rssFlags = RTE_ETH_RSS_IP;
		}
		else if (rssDepth.value() == "NONE" || rssDepth.value() == "none")
		{
			config.rssFlags = 0;
		}
		else
		{
			YADECAP_LOG_WARNING("incorrect value for parameter: 'rssDepth', using default 'L3'\n");
		}
	}
	else
	{
		YADECAP_LOG_WARNING("not found: 'rssDepth', using default 'L3'\n");
	}

	if (rootJson.find("rateLimits") != rootJson.end())
	{
		result = parseRateLimits(rootJson.find("rateLimits").value());
		if (result != eResult::success)
		{
			return result;
		}
	}

	config.memory = rootJson.value("memory", 0);

	auto it = rootJson.find("ealArgs");
	if (it != rootJson.end())
	{
		for (auto& arg: *it)
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
		bool bind = false;

		if (exist(config.ports, interfaceName))
		{
			YADECAP_LOG_ERROR("interfaceName '%s' already exist\n", interfaceName.data());
			return eResult::invalidConfigurationFile;
		}

		if (exist(portJson, "bind"))
		{
			if (portJson["bind"] == "true")
			{
				bind = true;
			}
		}

		config.ports[interfaceName] = {pci, bind};

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
	if (exist(json, "port_rx_queue_size"))
	{
		configValues[eConfigType::port_rx_queue_size] = json["port_rx_queue_size"];
	}

	if (exist(json, "port_tx_queue_size"))
	{
		configValues[eConfigType::port_tx_queue_size] = json["port_tx_queue_size"];
	}

	if (exist(json, "ring_highPriority_size"))
	{
		configValues[eConfigType::ring_highPriority_size] = json["ring_highPriority_size"];
	}

	if (exist(json, "ring_normalPriority_size"))
	{
		configValues[eConfigType::ring_normalPriority_size] = json["ring_normalPriority_size"];
	}

	if (exist(json, "ring_lowPriority_size"))
	{
		configValues[eConfigType::ring_lowPriority_size] = json["ring_lowPriority_size"];
	}

	if (exist(json, "fragmentation_size"))
	{
		configValues[eConfigType::fragmentation_size] = json["fragmentation_size"];
	}

	if (exist(json, "fragmentation_timeout_first"))
	{
		configValues[eConfigType::fragmentation_timeout_first] = json["fragmentation_timeout_first"];
	}

	if (exist(json, "fragmentation_timeout_last"))
	{
		configValues[eConfigType::fragmentation_timeout_last] = json["fragmentation_timeout_last"];
	}

	if (exist(json, "fragmentation_packets_per_flow"))
	{
		configValues[eConfigType::fragmentation_packets_per_flow] = json["fragmentation_packets_per_flow"];
	}
	if (exist(json, "stateful_firewall_tcp_timeout"))
	{
		configValues[eConfigType::stateful_firewall_tcp_timeout] = json["stateful_firewall_tcp_timeout"];
	}
	if (exist(json, "stateful_firewall_udp_timeout"))
	{
		configValues[eConfigType::stateful_firewall_udp_timeout] = json["stateful_firewall_udp_timeout"];
	}
	if (exist(json, "stateful_firewall_other_protocols_timeout"))
	{
		configValues[eConfigType::stateful_firewall_other_protocols_timeout] = json["stateful_firewall_other_protocols_timeout"];
	}
	if (exist(json, "gc_step"))
	{
		configValues[eConfigType::gc_step] = json["gc_step"];
	}
	if (exist(json, "sample_gc_step"))
	{
		configValues[eConfigType::sample_gc_step] = json["sample_gc_step"];
	}
	if (exist(json, "acl_states4_ht_size"))
	{
		configValues[eConfigType::acl_states4_ht_size] = json["acl_states4_ht_size"];
	}
	if (exist(json, "acl_states6_ht_size"))
	{
		configValues[eConfigType::acl_states6_ht_size] = json["acl_states6_ht_size"];
	}
	if (exist(json, "acl_network_lpm4_chunks_size"))
	{
		configValues[eConfigType::acl_network_lpm4_chunks_size] = json["acl_network_lpm4_chunks_size"];
	}
	if (exist(json, "acl_network_source_lpm6_chunks_size"))
	{
		configValues[eConfigType::acl_network_source_lpm6_chunks_size] = json["acl_network_source_lpm6_chunks_size"];
	}
	if (exist(json, "acl_network_destination_lpm6_chunks_size"))
	{
		configValues[eConfigType::acl_network_destination_lpm6_chunks_size] = json["acl_network_destination_lpm6_chunks_size"];
	}
	if (exist(json, "acl_network_destination_ht_size"))
	{
		configValues[eConfigType::acl_network_destination_ht_size] = json["acl_network_destination_ht_size"];
	}
	if (exist(json, "acl_network_table_size"))
	{
		configValues[eConfigType::acl_network_table_size] = json["acl_network_table_size"];
	}
	if (exist(json, "acl_transport_layers_size"))
	{
		configValues[eConfigType::acl_transport_layers_size] = json["acl_transport_layers_size"];
	}
	if (exist(json, "acl_transport_ht_size"))
	{
		configValues[eConfigType::acl_transport_ht_size] = json["acl_transport_ht_size"];
	}
	if (exist(json, "acl_total_ht_size"))
	{
		configValues[eConfigType::acl_total_ht_size] = json["acl_total_ht_size"];
	}
	if (exist(json, "acl_values_size"))
	{
		configValues[eConfigType::acl_values_size] = json["acl_values_size"];
	}

	if (exist(json, "master_mempool_size"))
	{
		configValues[eConfigType::master_mempool_size] = json["master_mempool_size"];
	}

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

	if (config.dumpKniCoreId >= std::thread::hardware_concurrency())
	{
		YADECAP_LOG_ERROR("invalid coreId: '%u'\n", config.dumpKniCoreId);
		return eResult::invalidConfigurationFile;
	}

	{
		std::set<std::string> pcis;
		for (const auto& portIter : config.ports)
		{
			const auto& [pci, bind] = portIter.second;
			(void)bind;

			if (exist(pcis, pci))
			{
				YADECAP_LOG_ERROR("pci '%s' already exist\n", pci.data());
				return eResult::invalidConfigurationFile;
			}

			pcis.emplace(pci);
		}
	}

	for (const auto& workerIter : config.workers)
	{
		const tCoreId& coreId = workerIter.first;

		if (coreId >= std::thread::hardware_concurrency() ||
		    coreId == config.controlPlaneCoreId ||
		    coreId == config.dumpKniCoreId)
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
#define insert_eal_arg(args ...) do { \
eal_argv[eal_argc++] = &buffer[bufferPosition]; \
bufferPosition += snprintf(&buffer[bufferPosition], sizeof(buffer) - bufferPosition, ## args); \
bufferPosition++; \
} while (0)

	unsigned int bufferPosition = 0;
	char buffer[8192];

	unsigned int eal_argc = 0;
	char* eal_argv[128];

	insert_eal_arg("%s", binaryPath.data());

	for(auto& arg: config.ealArgs)
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
		const auto& [pci, bind] = port.second;
		(void)bind;

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

	if (config.memory)
	{
		if (config.useHugeMem)
		{
			insert_eal_arg("--socket-mem=%u", config.memory);
			insert_eal_arg("--socket-limit=%u", config.memory);
		}
		else
		{
			insert_eal_arg("-m %u", config.memory);
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
