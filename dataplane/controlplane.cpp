#include <linux/if.h>
#include <optional>
#include <sys/ioctl.h>
#include <sys/un.h>

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "common/fallback.h"
#include "common/idp.h"
#include "common/version.h"

#include "checksum.h"
#include "common.h"
#include "controlplane.h"
#include "dataplane.h"
#include "debug_latch.h"
#include "icmp.h"
#include "icmp_translations.h"
#include "metadata.h"
#include "prepare.h"
#include "worker.h"
#include "worker_gc.h"

cControlPlane::cControlPlane(cDataPlane* dataPlane) :
        dataPlane(dataPlane),
        fragmentation_(
                [this](rte_mbuf* pkt, const common::globalBase::tFlow& flow) {
	                sendPacketToSlowWorker(pkt, flow);
                },
                dataPlane->getConfigValues().fragmentation),
        slow_(this),
        dregress(&slow_,
                 dataPlane,
                 dataPlane->getConfigValues().gc_step),
        mempool(nullptr),
        use_kernel_interface(false),
        slowWorker(nullptr),
        prevTimePointForSWRateLimiter(std::chrono::high_resolution_clock::now())
{
	memset(&stats, 0, sizeof(stats));
}

cControlPlane::~cControlPlane()
{
	if (mempool)
	{
		rte_mempool_free(mempool);
	}
}

eResult cControlPlane::init(bool use_kernel_interface)
{
	this->use_kernel_interface = use_kernel_interface;

	eResult result = eResult::success;

	/// init mempool for kernel interfaces and slow worker
	result = initMempool();
	if (result != eResult::success)
	{
		return result;
	}

	gc_step = dataPlane->getConfigValues().gc_step;
	dregress.gc_step = gc_step;

	icmpOutRemainder = dataPlane->config.SWICMPOutRateLimit / dataPlane->config.rateLimitDivisor;

	return result;
}

void cControlPlane::start()
{
	int rc = pthread_barrier_wait(&dataPlane->initPortBarrier);
	if (rc == PTHREAD_BARRIER_SERIAL_THREAD)
	{
		pthread_barrier_destroy(&dataPlane->initPortBarrier);
	}
	else if (rc != 0)
	{
		YADECAP_LOG_ERROR("pthread_barrier_wait() = %d\n", rc);
		/// @todo: stop
		return;
	}

	/// start devices
	for (const auto& portIter : dataPlane->ports)
	{
		const tPortId& portId = portIter.first;

		int rc = rte_eth_dev_start(portId);
		if (rc)
		{
			YADECAP_LOG_ERROR("can't start eth dev(%d, %d): %s\n",
			                  rc,
			                  rte_errno,
			                  rte_strerror(rte_errno));
			abort();
		}

		rte_eth_promiscuous_enable(portId);
	}

	rc = pthread_barrier_wait(&dataPlane->runBarrier);
	if (rc == PTHREAD_BARRIER_SERIAL_THREAD)
	{
		pthread_barrier_destroy(&dataPlane->runBarrier);
	}
	else if (rc != 0)
	{
		YADECAP_LOG_ERROR("pthread_barrier_wait() = %d\n", rc);
		/// @todo: stop
		return;
	}

	mainThread();
}

common::idp::updateGlobalBase::response cControlPlane::updateGlobalBase(const common::idp::updateGlobalBase::request& request)
{
	std::lock_guard<std::mutex> guard(mutex);
	if (!errors.empty())
	{
		return eResult::dataplaneIsBroken;
	}

	YADECAP_MEMORY_BARRIER_COMPILE;

	auto result = eResult::success;
	for (auto& iter : dataPlane->globalBases)
	{
		auto* globalBaseNext = iter.second[dataPlane->currentGlobalBaseId ^ 1];
		DEBUG_LATCH_WAIT(common::idp::debug_latch_update::id::global_base_pre_update);
		result = globalBaseNext->update(request);
		DEBUG_LATCH_WAIT(common::idp::debug_latch_update::id::global_base_post_update);
		if (result != eResult::success)
		{
			++errors["updateGlobalBase"];
			break;
		}
	}

	if (result != eResult::success)
	{
		return result;
	}

	DEBUG_LATCH_WAIT(common::idp::debug_latch_update::id::global_base_switch);

	YADECAP_MEMORY_BARRIER_COMPILE;

	switchGlobalBase();

	YADECAP_MEMORY_BARRIER_COMPILE;

	result = eResult::success;
	for (auto& iter : dataPlane->globalBases)
	{
		auto* globalBaseNext = iter.second[dataPlane->currentGlobalBaseId ^ 1];
		DEBUG_LATCH_WAIT(common::idp::debug_latch_update::id::global_base_pre_update);
		result = globalBaseNext->update(request);
		DEBUG_LATCH_WAIT(common::idp::debug_latch_update::id::global_base_post_update);
		if (result != eResult::success)
		{
			// Practically unreachable.
			++errors["updateGlobalBase"];
			break;
		}
	}

	if (result != eResult::success)
	{
		return result;
	}

	YADECAP_MEMORY_BARRIER_COMPILE;

	waitAllWorkers();

	YADECAP_MEMORY_BARRIER_COMPILE;

	return eResult::success;
}

eResult cControlPlane::updateGlobalBaseBalancer(const common::idp::updateGlobalBaseBalancer::request& request)
{
	if (!errors.empty())
	{
		return eResult::dataplaneIsBroken;
	}

	YADECAP_MEMORY_BARRIER_COMPILE;
	DEBUG_LATCH_WAIT(common::idp::debug_latch_update::id::balancer_update);
	std::lock_guard<std::mutex> guard(balancer_mutex);

	auto result = eResult::success;
	for (auto& iter : dataPlane->globalBases)
	{
		auto current_id = dataPlane->currentGlobalBaseId;
		auto* globalBaseNext = iter.second[current_id];
		result = globalBaseNext->updateBalancer(request);
		if (result != eResult::success)
		{
			++errors["updateGlobalBase"];
			break;
		}

		YADECAP_MEMORY_BARRIER_COMPILE;

		globalBaseNext = iter.second[current_id ^ 1];
		result = globalBaseNext->updateBalancer(request);
		if (result != eResult::success)
		{
			// Practically unreachable.
			++errors["updateGlobalBase"];
			break;
		}
	}

	YADECAP_MEMORY_BARRIER_COMPILE;

	waitAllWorkers();

	YADECAP_MEMORY_BARRIER_COMPILE;

	return eResult::success;
}

common::idp::getGlobalBase::response cControlPlane::getGlobalBase(const common::idp::getGlobalBase::request& request)
{
	std::lock_guard<std::mutex> guard(mutex);

	common::idp::getGlobalBase::response response;

	for (auto& iter : dataPlane->globalBases)
	{
		const tSocketId& socketId = iter.first;
		const auto* globalBase = iter.second[dataPlane->currentGlobalBaseId];

		common::idp::getGlobalBase::globalBase globalBaseResponse;
		if (globalBase->get(request, globalBaseResponse) != eResult::success)
		{
			++errors["getGlobalBase"];
			return {};
		}

		response[socketId] = globalBaseResponse;
	}

	return response;
}

common::idp::getOtherStats::response cControlPlane::getOtherStats()
{
	common::idp::getOtherStats::response response;
	auto& [response_workers] = response;

	/// workers
	{
		for (const auto& iter : dataPlane->workers)
		{
			const tCoreId& coreId = iter.first;
			const cWorker* worker = iter.second;

			std::array<uint64_t, CONFIG_YADECAP_MBUFS_BURST_SIZE + 1> bursts;
			memcpy(&bursts[0], worker->bursts, sizeof(worker->bursts));

			response_workers[coreId] = {bursts};
		}
	}

	return response;
}

common::idp::getWorkerStats::response cControlPlane::getWorkerStats(const common::idp::getWorkerStats::request& request)
{
	/// unsafe

	common::idp::getWorkerStats::response response;

	if (request.size())
	{
		for (const auto& coreId : request)
		{
			/// @todo: check coreId

			const auto& worker = dataPlane->workers.find(coreId)->second;

			std::map<tPortId, common::worker::stats::port> portsStats;
			for (const auto& portIter : dataPlane->ports)
			{
				portsStats[portIter.first] = worker->statsPorts[portIter.first];
			}

			response[coreId] = {worker->iteration,
			                    worker->stats,
			                    portsStats};
		}
	}
	else
	{
		/// all workers

		for (const auto& [coreId, worker] : dataPlane->workers)
		{
			std::map<tPortId, common::worker::stats::port> portsStats;
			for (const auto& portIter : dataPlane->ports)
			{
				portsStats[portIter.first] = worker->statsPorts[portIter.first];
			}

			response[coreId] = {worker->iteration,
			                    worker->stats,
			                    portsStats};
		}
	}

	return response;
}

common::idp::getSlowWorkerStats::response cControlPlane::getSlowWorkerStats()
{
	/// unsafe

	common::idp::getSlowWorkerStats::response response;
	auto& [slowworker_stats, hashtable_gc_stats] = response;

	slowworker_stats = stats;
	/// @todo
	// hashtable_gc_stats.emplace_back(slowWorker->socketId,
	//                                 "dregress",
	//                                 dregress.connections);

	for (const auto& [socket_id, globalbase_atomic] : dataPlane->globalBaseAtomics)
	{
		hashtable_gc_stats.emplace_back(socket_id,
		                                "balancer.ht",
		                                globalbase_atomic->balancer_state_gc.valid_keys,
		                                globalbase_atomic->balancer_state_gc.iterations);
	}

	for (const auto& [core_id, worker] : dataPlane->worker_gcs)
	{
		(void)core_id;

		hashtable_gc_stats.emplace_back(worker->socket_id,
		                                "nat64stateful.lan.state.ht",
		                                worker->nat64stateful_lan_state_gc.valid_keys,
		                                worker->nat64stateful_lan_state_gc.iterations);

		hashtable_gc_stats.emplace_back(worker->socket_id,
		                                "nat64stateful.wan.state.ht",
		                                worker->nat64stateful_wan_state_gc.valid_keys,
		                                worker->nat64stateful_wan_state_gc.iterations);

		hashtable_gc_stats.emplace_back(worker->socket_id,
		                                "acl.state.v4.ht",
		                                worker->fw4_state_gc.valid_keys,
		                                worker->fw4_state_gc.iterations);

		hashtable_gc_stats.emplace_back(worker->socket_id,
		                                "acl.state.v6.ht",
		                                worker->fw6_state_gc.valid_keys,
		                                worker->fw6_state_gc.iterations);
	}

	return response;
}

common::idp::get_worker_gc_stats::response cControlPlane::get_worker_gc_stats()
{
	common::idp::get_worker_gc_stats::response response;

	for (const auto& [core_id, worker] : dataPlane->worker_gcs)
	{
		response[core_id] = {worker->iteration,
		                     worker->stats};
	}

	return response;
}

common::idp::get_dregress_counters::response cControlPlane::get_dregress_counters()
{
	auto guard = dregress.LockCounters();
	common::stream_out_t stream;
	dregress.Counters4().push(stream);
	dregress.Counters6().push(stream);
	dregress.ClearCounters();
	return stream.getBuffer();
}

common::idp::get_ports_stats::response cControlPlane::get_ports_stats()
{
	common::idp::get_ports_stats::response response;

	for (const auto& [portId, port] : dataPlane->ports)
	{
		(void)port;

		rte_eth_stats stats;
		{
			std::lock_guard<std::mutex> guard(dataPlane->dpdk_mutex);
			rte_eth_stats_get(portId, &stats);
		}

		uint64_t physicalPort_egress_drops = 0;
		for (const auto& [coreId, worker] : dataPlane->workers)
		{
			(void)coreId;

			physicalPort_egress_drops += worker->statsPorts[portId].physicalPort_egress_drops;
		}

		response[portId] = {stats.ipackets,
		                    stats.ibytes,
		                    stats.ierrors,
		                    stats.imissed,
		                    stats.opackets,
		                    stats.obytes,
		                    stats.oerrors,
		                    physicalPort_egress_drops};
	}

	return response;
}

common::idp::get_ports_stats_extended::response cControlPlane::get_ports_stats_extended()
{
	/// unsafe

	common::idp::get_ports_stats_extended::response response;

	for (const auto& [portId, _] : dataPlane->ports)
	{
		(void)_;

		auto portStats = dataPlane->getPortStats(portId);
		response[portId] = portStats;
	}

	return response;
}

common::idp::getControlPlanePortStats::response cControlPlane::getControlPlanePortStats(const common::idp::getControlPlanePortStats::request& request)
{
	/// unsafe

	common::idp::getControlPlanePortStats::response response;

	const auto& portmapper = slowWorker->basePermanently.ports;

	if (request.size())
	{
		for (const auto& portId : request)
		{
			if ((!use_kernel_interface) || (!portmapper.ValidDpdk(portId)))
			{
				YANET_LOG_ERROR("Controlplane statistics requested for invalid port id ( %u )", portId);
			}
			const auto& stats = kernel_stats[portmapper.ToLogical(portId)];

			response[portId] = {stats.ipackets,
			                    stats.ibytes,
			                    0,
			                    stats.idropped,
			                    stats.opackets,
			                    stats.obytes,
			                    0,
			                    stats.odropped};
		}
	}
	else
	{
		/// all ports
		if (use_kernel_interface)
		{
			for (tPortId i = 0; i < portmapper.size(); ++i)
			{
				const auto& stats = kernel_stats[i];
				const auto& portId = portmapper.ToDpdk(i);

				response[portId] = {stats.ipackets,
				                    stats.ibytes,
				                    0,
				                    stats.idropped,
				                    stats.opackets,
				                    stats.obytes,
				                    0,
				                    stats.odropped};
			}
		}
	}

	return response;
}

common::idp::getFragmentationStats::response cControlPlane::getFragmentationStats()
{
	return fragmentation_.getStats();
}

common::dregress::stats_t cControlPlane::DregressStats() const
{
	return dregress.Stats();
}

dataplane::hashtable_chain_spinlock_stats_t cControlPlane::DregressConnectionsStats() const
{
	return dregress.Connections()->stats();
}

common::idp::getFWState::response cControlPlane::getFWState()
{
	common::idp::getFWState::response response;

	for (const auto& [core_id, worker_gc] : dataPlane->worker_gcs)
	{
		(void)core_id;

		worker_gc->fw_state_mutex.lock();
		auto fw_state = worker_gc->fw_state;
		worker_gc->fw_state_mutex.unlock();

		for (const auto& [key, value] : fw_state)
		{
			const auto& [owner, flags, last_seen, packets_backward, packets_forward] = value;

			auto it = response.find(key);
			if (it == response.end())
			{
				response.emplace_hint(it, key, value);
			}
			else
			{
				auto& [first_owner, first_flags, first_last_seen, first_packets_backward, first_packets_forward] = it->second;

				if (owner == (uint8_t)dataplane::globalBase::fw_state_owner_e::internal)
				{
					first_owner = owner;
				}

				if (last_seen > first_last_seen)
				{
					first_last_seen = last_seen;
				}

				first_packets_backward += packets_backward;
				first_packets_forward += packets_forward;
				first_flags |= flags;
			}
		}
	}

	return response;
}

common::idp::getFWStateStats::response cControlPlane::getFWStateStats() ///< @todo: DELETE
{
	common::fwstate::stats_t stats{};

	for (auto& [socket_id, globalbase_atomics] : dataPlane->globalBaseAtomics)
	{
		(void)socket_id;

		stats.fwstate4_size = std::max(stats.fwstate4_size, (uint64_t)globalbase_atomics->updater.fw4_state.get_stats().keys_count);
		stats.fwstate6_size = std::max(stats.fwstate6_size, (uint64_t)globalbase_atomics->updater.fw6_state.get_stats().keys_count);
	}

	return stats;
}

eResult cControlPlane::clearFWState()
{
	for (auto& [socketId, globalBaseAtomic] : dataPlane->globalBaseAtomics)
	{
		(void)socketId;

		globalBaseAtomic->fw4_state->clear();
		globalBaseAtomic->fw6_state->clear();
	}
	return common::result_e::success;
}

common::idp::getAclCounters::response cControlPlane::getAclCounters()
{
	std::lock_guard<std::mutex> guard(mutex);

	common::idp::getAclCounters::response response;

	response.resize(YANET_CONFIG_ACL_COUNTERS_SIZE);
	for (const auto& [coreId, worker] : dataPlane->workers)
	{
		(void)coreId;

		for (size_t i = 0; i < YANET_CONFIG_ACL_COUNTERS_SIZE; i++)
		{
			response[i] += worker->aclCounters[i];
		}
	}

	return response;
}

common::idp::getPortStatsEx::response cControlPlane::getPortStatsEx()
{
	common::idp::getPortStatsEx::response response;

	std::lock_guard<std::mutex> guard(mutex);

	for (const auto& portIter : dataPlane->ports)
	{
		const tPortId& portId = portIter.first;
		auto& port = response[portId];

		auto portStats = dataPlane->getPortStats(portId);

		std::get<0>(port) = std::get<0>(portIter.second);
		std::get<1>(port) = (portStats["link_status"] != 0);

		auto& countersIn = std::get<2>(port);
		auto& countersOut = std::get<3>(port);

		std::get<0>(countersIn) = portStats["rx_good_bytes"];
		std::get<1>(countersIn) = portStats["rx_port_unicast_packets"];
		std::get<2>(countersIn) = portStats["rx_port_multicast_packets"];
		std::get<3>(countersIn) = portStats["rx_port_broadcast_packets"];
		std::get<4>(countersIn) = portStats["rx_out_of_buffer"] & 0xFFFFFFFF; ///< bug
		std::get<5>(countersIn) = portStats["rx_errors"];
		std::get<0>(countersOut) = portStats["tx_good_bytes"];
		std::get<1>(countersOut) = portStats["tx_port_unicast_packets"];
		std::get<2>(countersOut) = portStats["tx_port_multicast_packets"];
		std::get<3>(countersOut) = portStats["tx_port_broadcast_packets"];
		std::get<5>(countersOut) = portStats["tx_errors"];
	}

	return response;
}

common::idp::getCounters::response cControlPlane::getCounters(const common::idp::getCounters::request& request)
{
	common::idp::getCounters::response response;
	response.resize(request.size());

	for (size_t i = 0;
	     i < request.size();
	     i++)
	{
		const auto& counter_id = request[i];

		if (counter_id >= YANET_CONFIG_COUNTERS_SIZE)
		{
			std::lock_guard<std::mutex> guard(mutex);
			++errors["getCounters: invalid counterId"];
			continue;
		}

		uint64_t counter = 0;
		for (const auto& [core_id, worker] : dataPlane->workers)
		{
			(void)core_id;
			counter += worker->counters[counter_id];
		}

		response[i] = counter;
	}

	return response;
}

common::idp::getConfig::response cControlPlane::getConfig() const
{
	common::idp::getConfig::response response;
	auto& [response_ports, response_workers, response_values] = response;

	for (const auto& [port_id, port] : dataPlane->ports)
	{
		const auto& [interface_name, rx_queues, tx_queues_count, mac_address, pci, symmetric_mode] = port;
		(void)rx_queues;
		(void)tx_queues_count;
		(void)symmetric_mode;

		response_ports[port_id] = {interface_name,
		                           rte_eth_dev_socket_id(port_id),
		                           mac_address,
		                           pci};
	}

	for (const auto& workerIter : dataPlane->workers)
	{
		const tCoreId& coreId = workerIter.first;
		const cWorker* worker = workerIter.second;

		for (unsigned int worker_port_i = 0;
		     worker_port_i < worker->basePermanently.workerPortsCount;
		     worker_port_i++)
		{
			std::get<0>(response_workers[coreId]).emplace_back(worker->basePermanently.workerPorts[worker_port_i].inPortId);
		}

		std::get<1>(response_workers[coreId]) = worker->socketId;
	}

	/// @todo: worker_gcs

	response_values.resize((unsigned int)common::idp::getConfig::value_type::size);

	return response;
}

common::idp::getErrors::response cControlPlane::getErrors()
{
	std::lock_guard<std::mutex> guard(mutex);
	return errors;
}

common::idp::getReport::response cControlPlane::getReport()
{
	std::lock_guard<std::mutex> guard(mutex);
	return dataPlane->report.getReport().dump(2);
}

/// @todo: rename, move
common::idp::value getLookupValue(const dataplane::globalBase::route_value_t& lpmValue)
{
	common::idp::value result;

	if (lpmValue.type == common::globalBase::eNexthopType::drop)
	{
		std::get<0>(result) = lpmValue.type;
	}
	else if (lpmValue.type == common::globalBase::eNexthopType::interface)
	{
		std::get<0>(result) = lpmValue.type;

		for (unsigned int ecmp_i = 0;
		     ecmp_i < lpmValue.interface.ecmpCount;
		     ecmp_i++)
		{
			const auto& ecmp = lpmValue.interface.nexthops[ecmp_i];

			if (ecmp.labelExpTransport >> 24)
			{
				if (ecmp.labelExpService >> 24)
				{
					std::get<1>(result).emplace_back(ecmp.interfaceId,
					                                 common::idp::labelExp(rte_be_to_cpu_32(ecmp.labelExpTransport) >> 12,
					                                                       rte_be_to_cpu_32(ecmp.labelExpTransport >> 9) & 0x7),
					                                 common::idp::labelExp(rte_be_to_cpu_32(ecmp.labelExpService) >> 12,
					                                                       rte_be_to_cpu_32(ecmp.labelExpService >> 9) & 0x7));
				}
				else
				{
					std::get<1>(result).emplace_back(ecmp.interfaceId,
					                                 common::idp::labelExp(rte_be_to_cpu_32(ecmp.labelExpTransport) >> 12,
					                                                       rte_be_to_cpu_32(ecmp.labelExpTransport >> 9) & 0x7),
					                                 common::idp::labelExp(common::unlabelled,
					                                                       0));
				}
			}
			else
			{
				std::get<1>(result).emplace_back(ecmp.interfaceId,
				                                 common::idp::labelExp(common::unlabelled,
				                                                       0),
				                                 common::idp::labelExp(common::unlabelled,
				                                                       0));
			}
		}
	}
	else if (lpmValue.type == common::globalBase::eNexthopType::controlPlane)
	{
		std::get<0>(result) = lpmValue.type;
	}
	else if (lpmValue.type == common::globalBase::eNexthopType::repeat)
	{
		std::get<0>(result) = lpmValue.type;
	}
	else
	{
		std::get<0>(result) = lpmValue.type;
		YADECAP_LOG_ERROR("invalid nexthop type\n");
	}

	return result;
}

common::idp::lpm4LookupAddress::response cControlPlane::lpm4LookupAddress(const common::idp::lpm4LookupAddress::request& request)
{
	std::lock_guard<std::mutex> guard(mutex);

	common::idp::lpm4LookupAddress::response response;

	const uint32_t ipAddress = rte_cpu_to_be_32(request);

	for (auto& iter : dataPlane->globalBases)
	{
		const tSocketId& socketId = iter.first;
		const auto* globalBase = iter.second[dataPlane->currentGlobalBaseId];

		uint32_t valueId;
		if (globalBase->route_lpm4->lookup(ipAddress, &valueId))
		{
			response[socketId] = {true,
			                      valueId,
			                      getLookupValue(globalBase->route_values[valueId])};
		}
		else
		{
			response[socketId] = {false,
			                      valueId,
			                      {}};
		}
	}

	return response;
}

common::idp::lpm6LookupAddress::response cControlPlane::lpm6LookupAddress(const common::idp::lpm6LookupAddress::request& request)
{
	std::lock_guard<std::mutex> guard(mutex);

	common::idp::lpm6LookupAddress::response response;

	in6_addr ipv6Address;
	memcpy(ipv6Address.__in6_u.__u6_addr8, request.data(), 16);

	for (auto& iter : dataPlane->globalBases)
	{
		const tSocketId& socketId = iter.first;
		const auto* globalBase = iter.second[dataPlane->currentGlobalBaseId];

		uint32_t valueId;
		if (globalBase->route_lpm6->lookup(request, &valueId))
		{
			response[socketId] = {true,
			                      valueId,
			                      getLookupValue(globalBase->route_values[valueId])};
		}
		else
		{
			response[socketId] = {false,
			                      valueId,
			                      {}};
		}
	}

	return response;
}

common::idp::samples::response cControlPlane::samples()
{
	std::set<common::idp::samples::sample_t> samples;
	for (auto& [core_id, worker_gc] : dataPlane->worker_gcs)
	{
		(void)core_id;

		std::lock_guard<std::mutex> guard(worker_gc->samples_mutex);

		if (samples.empty())
		{
			samples.swap(worker_gc->samples);
		}
		else
		{
			samples.merge(worker_gc->samples);
			worker_gc->samples.clear();
		}
	}

	return common::idp::samples::response(samples.begin(), samples.end());
}

eResult cControlPlane::debug_latch_update(const common::idp::debug_latch_update::request& request)
{
	const auto& [latch_id, state] = request;
	if (latch_id >= common::idp::debug_latch_update::id::size)
	{
		YADECAP_LOG_ERROR("invalid latch id %u\n", (uint32_t)latch_id);
	}
	DEBUG_LATCH_UPDATE(latch_id, state);

	return common::result_e::success;
}

common::idp::limits::response cControlPlane::limits()
{
	common::idp::limits::response response;

	if (dataPlane->globalBases.empty() ||
	    dataPlane->globalBaseAtomics.empty())
	{
		return response;
	}

	{
		std::lock_guard<std::mutex> guard(dataPlane->currentGlobalBaseId_mutex);
		for (const auto& [socket_id, generations] : dataPlane->globalBases)
		{
			const auto* globalBase = generations[dataPlane->currentGlobalBaseId];

			globalBase->updater.route_lpm4->limits(response);
			globalBase->updater.route_lpm6->limits(response);
			globalBase->updater.route_tunnel_lpm4->limits(response);
			globalBase->updater.route_tunnel_lpm6->limits(response);

			globalBase->updater.acl.network_table->limits(response);
			globalBase->updater.acl.transport_table->limits(response);
			globalBase->updater.acl.total_table->limits(response);
			globalBase->updater.acl.network_ipv4_source->limits(response);
			globalBase->updater.acl.network_ipv4_destination->limits(response);
			globalBase->updater.acl.network_ipv6_source->limits(response);
			globalBase->updater.acl.network_ipv6_destination_ht->limits(response);
			globalBase->updater.acl.network_ipv6_destination->limits(response);

			limit_insert(response,
			             "tun64.mappings.ht.keys",
			             socket_id,
			             globalBase->tun64mappingsTable.getStats().pairs,
			             globalBase->tun64mappingsTable.keysSize);
			limit_insert(response,
			             "tun64.mappings.ht.extended_chunks",
			             socket_id,
			             globalBase->tun64mappingsTable.getStats().extendedChunksCount,
			             CONFIG_YADECAP_TUN64_HT_EXTENDED_SIZE);
		}
	}

	for (const auto& [core_id, worker_gc] : dataPlane->worker_gcs)
	{
		(void)core_id;
		worker_gc->limits(response);
	}

	auto dregress = this->dregress.limits();

	limit_insert(response,
	             "dregress.ht.keys",
	             dregress.pairs,
	             dregress.keysSize);
	limit_insert(response,
	             "dregress.ht.extended_chunks",
	             dregress.extendedChunksCount,
	             YANET_CONFIG_DREGRESS_HT_EXTENDED_SIZE);

	return response;
}

common::idp::balancer_connection::response cControlPlane::balancer_connection(const common::idp::balancer_connection::request& request)
{
	common::idp::balancer_connection::response response;

	for (auto& [core_id, worker_gc] : dataPlane->worker_gcs)
	{
		(void)core_id;

		auto& response_connections = response[worker_gc->socket_id];

		uint32_t offset = 0;
		worker_gc->run_on_this_thread([&, worker_gc = worker_gc]() {
			const auto& [filter_balancer_id, filter_virtual_ip, filter_proto, filter_virtual_port, filter_real_ip, filter_real_port] = request;

			const auto& base = worker_gc->bases[worker_gc->local_base_id & 1];

			for (auto iter : worker_gc->base_permanently.globalBaseAtomic->updater.balancer_state.range(offset, 64))
			{
				if (iter.is_valid())
				{
					iter.lock();
					const auto key = *iter.key();
					const auto value = *iter.value();
					iter.unlock();

					const auto& balancer_id = key.balancer_id;
					const auto& l3_balancing = key.l3_balancing;
					const auto& virtual_ip = common::ip_address_t(key.addr_type, key.ip_destination.bytes);

					const auto& proto = key.protocol;
					const auto& virtual_port = key.port_destination;
					const auto& real_from_base = base.globalBase->balancer_reals[value.real_unordered_id];
					const auto real_ip_version = (real_from_base.flags & YANET_BALANCER_FLAG_DST_IPV6) ? 6 : 4;
					const auto& real_ip = common::ip_address_t(real_ip_version, real_from_base.destination.bytes);

					const auto& real_port = virtual_port; ///< @todo: get port from real's config
					const auto& client_ip = common::ip_address_t(key.addr_type, key.ip_source.bytes);
					const auto& client_port = key.port_source;

					if (filter_balancer_id &&
					    balancer_id != *filter_balancer_id)
					{
						continue;
					}

					if (filter_virtual_ip &&
					    virtual_ip != *filter_virtual_ip)
					{
						continue;
					}

					if (filter_proto &&
					    proto != *filter_proto)
					{
						continue;
					}

					if (filter_virtual_port &&
					    rte_be_to_cpu_16(virtual_port) != *filter_virtual_port)
					{
						continue;
					}

					if (filter_real_ip &&
					    real_ip != *filter_real_ip)
					{
						continue;
					}

					/// @todo: filter_real_port
					(void)filter_real_port;

					auto& connections = response_connections[{balancer_id,
					                                          virtual_ip,
					                                          proto,
					                                          l3_balancing ? std::nullopt : std::make_optional(rte_be_to_cpu_16(virtual_port)),
					                                          {real_ip, l3_balancing ? std::nullopt : std::make_optional(rte_be_to_cpu_16(real_port))}}];

					connections.emplace_back(client_ip,
					                         l3_balancing ? std::nullopt : std::make_optional(rte_be_to_cpu_16(client_port)),
					                         value.timestamp_create,
					                         value.timestamp_last_packet,
					                         value.timestamp_gc);
				}
			}

			if (offset != 0)
			{
				return false;
			}

			return true;
		});
	}

	return response;
}

common::idp::balancer_service_connections::response cControlPlane::balancer_service_connections()
{
	common::idp::balancer_service_connections::response response;

	for (const auto& [core_id, worker_gc] : dataPlane->worker_gcs)
	{
		(void)core_id;

		auto current_guard = worker_gc->balancer_service_connections.current_lock_guard();
		response[worker_gc->socket_id] = worker_gc->balancer_service_connections.current();
	}

	return response;
}

common::idp::balancer_real_connections::response cControlPlane::balancer_real_connections()
{
	common::idp::balancer_real_connections::response response;

	for (const auto& [core_id, worker_gc] : dataPlane->worker_gcs)
	{
		(void)core_id;

		auto current_guard = worker_gc->balancer_real_connections.current_lock_guard();
		response[worker_gc->socket_id] = worker_gc->balancer_real_connections.current();
	}

	return response;
}

eResult cControlPlane::unrdup_vip_to_balancers(const common::idp::unrdup_vip_to_balancers::request& request)
{
	std::lock_guard<std::mutex> guard(unrdup_mutex);

	uint32_t balancer_id = std::get<0>(request);

	if (vip_to_balancers.size() <= balancer_id)
	{
		vip_to_balancers.resize(balancer_id + 1);
	}

	vip_to_balancers[balancer_id] = std::get<1>(request);

	return eResult::success;
}

eResult cControlPlane::update_vip_vport_proto(const common::idp::update_vip_vport_proto::request& request)
{
	std::lock_guard<std::mutex> guard(vip_vport_proto_mutex);

	uint32_t balancer_id = std::get<0>(request);

	if (vip_vport_proto.size() <= balancer_id)
	{
		vip_vport_proto.resize(balancer_id + 1);
	}

	vip_vport_proto[balancer_id] = std::get<1>(request);

	return eResult::success;
}

common::idp::version::response cControlPlane::version()
{
	return {version_major(),
	        version_minor(),
	        version_revision(),
	        version_hash(),
	        version_custom()};
}

common::idp::get_counter_by_name::response cControlPlane::get_counter_by_name(const common::idp::get_counter_by_name::request& request)
{
	common::idp::get_counter_by_name::response response;

	const auto& [counter_name, optional_core_id] = request;

	if (optional_core_id.has_value())
	{
		std::optional<uint64_t> counter_val = dataPlane->getCounterValueByName(counter_name, optional_core_id.value());
		if (counter_val.has_value())
		{
			response[optional_core_id.value()] = counter_val.value();
		}

		// if counter with provided name does not exist, empty map will be returned, and its emptiness should be checked on another end
		return response;
	}

	// core_id was not specified, return counter for each core_id
	for (const auto& [core_id, worker] : dataPlane->workers)
	{
		(void)worker;
		std::optional<uint64_t> counter_val = dataPlane->getCounterValueByName(counter_name, core_id);
		if (counter_val.has_value())
		{
			response[core_id] = counter_val.value();
		}
	}

	for (const auto& [core_id, worker_gc] : dataPlane->worker_gcs)
	{
		(void)worker_gc;
		std::optional<uint64_t> counter_val = dataPlane->getCounterValueByName(counter_name, core_id);
		if (counter_val.has_value())
		{
			response[core_id] = counter_val.value();
		}
	}

	return response;
}

common::idp::get_shm_info::response cControlPlane::get_shm_info()
{
	common::idp::get_shm_info::response response;
	for (const auto& key : dataPlane->getShmInfo())
	{
		response.emplace_back(key);
	}

	return response;
}

common::idp::get_shm_tsc_info::response cControlPlane::get_shm_tsc_info()
{
	common::idp::get_shm_tsc_info::response response;
	for (const auto& key : dataPlane->getShmTscInfo())
	{
		response.emplace_back(key);
	}

	return response;
}

eResult cControlPlane::dump_physical_port(const common::idp::dump_physical_port::request& request)
{
	const auto& [interface_name, direction, state] = request;

	const auto port_id = dataPlane->interface_name_to_port_id(interface_name);
	if (!port_id)
	{
		return eResult::invalidInterfaceName;
	}

	uint8_t flag = 0;
	if (direction == "in")
	{
		flag = YANET_PHYSICALPORT_FLAG_IN_DUMP;
	}
	else if (direction == "out")
	{
		flag = YANET_PHYSICALPORT_FLAG_OUT_DUMP;
	}
	else if (direction == "drop")
	{
		flag = YANET_PHYSICALPORT_FLAG_DROP_DUMP;
	}
	else
	{
		return eResult::invalidArguments;
	}

	if (state)
	{
		/// start dump traffic to interface
		for (auto& [socket_id, globalbase_atomic] : dataPlane->globalBaseAtomics)
		{
			(void)socket_id;

			__atomic_or_fetch(&globalbase_atomic->physicalPort_flags[*port_id],
			                  (uint8_t)(flag),
			                  __ATOMIC_RELAXED);
		}
	}
	else
	{
		/// stop dump traffic to interface
		for (auto& [socket_id, globalbase_atomic] : dataPlane->globalBaseAtomics)
		{
			(void)socket_id;

			__atomic_and_fetch(&globalbase_atomic->physicalPort_flags[*port_id],
			                   (uint8_t)(~flag),
			                   __ATOMIC_RELAXED);
		}
	}

	return eResult::success;
}

eResult cControlPlane::balancer_state_clear()
{
	for (auto& [core_id, worker_gc] : dataPlane->worker_gcs)
	{
		(void)core_id;
		worker_gc->balancer_state_clear();
	}

	return eResult::success;
}

common::idp::nat64stateful_state::response cControlPlane::nat64stateful_state(const common::idp::nat64stateful_state::request& request)
{
	common::idp::nat64stateful_state::response response;

	for (auto& [core_id, worker_gc] : dataPlane->worker_gcs)
	{
		(void)core_id;
		worker_gc->nat64stateful_state(request, response);
	}

	return response;
}

void cControlPlane::switchBase()
{
	YADECAP_MEMORY_BARRIER_COMPILE;

	for (auto& iter : dataPlane->workers)
	{
		auto* worker = iter.second;

		worker->currentBaseId ^= 1;
	}

	for (auto& iter : dataPlane->worker_gcs)
	{
		auto* worker = iter.second;

		worker->current_base_id ^= 1;
	}

	YADECAP_MEMORY_BARRIER_COMPILE;

	waitAllWorkers();

	YADECAP_MEMORY_BARRIER_COMPILE;

	for (auto& iter : dataPlane->workers)
	{
		auto* worker = iter.second;
		auto& base = worker->bases[worker->currentBaseId];
		auto& baseNext = worker->bases[worker->currentBaseId ^ 1];

		baseNext = base;
	}

	for (auto& iter : dataPlane->worker_gcs)
	{
		auto* worker = iter.second;
		auto& base = worker->bases[worker->current_base_id];
		auto& baseNext = worker->bases[worker->current_base_id ^ 1];

		baseNext = base;
	}

	YADECAP_MEMORY_BARRIER_COMPILE;
}

void cControlPlane::switchGlobalBase()
{
	YADECAP_MEMORY_BARRIER_COMPILE;

	{
		std::lock_guard<std::mutex> guard(dataPlane->currentGlobalBaseId_mutex);
		dataPlane->currentGlobalBaseId ^= 1;
	}

	YADECAP_MEMORY_BARRIER_COMPILE;

	dataPlane->switch_worker_base();

	YADECAP_MEMORY_BARRIER_COMPILE;
}

void cControlPlane::waitAllWorkers()
{
	YADECAP_MEMORY_BARRIER_COMPILE;

	for (const auto& [core_id, worker] : dataPlane->workers)
	{
		(void)core_id;

		uint64_t startIteration = worker->iteration;
		uint64_t nextIteration = startIteration;
		while (nextIteration - startIteration <= (uint64_t)16)
		{
			YADECAP_MEMORY_BARRIER_COMPILE;
			nextIteration = worker->iteration;
		}
	}

	for (const auto& [core_id, worker] : dataPlane->worker_gcs)
	{
		(void)core_id;

		uint64_t startIteration = worker->iteration;
		uint64_t nextIteration = startIteration;
		while (nextIteration - startIteration <= (uint64_t)16)
		{
			YADECAP_MEMORY_BARRIER_COMPILE;
			nextIteration = worker->iteration;
		}
	}

	YADECAP_MEMORY_BARRIER_COMPILE;
}

eResult cControlPlane::initMempool()
{
	mempool = dataPlane->socket_cplane_mempools[rte_lcore_to_socket_id(dataPlane->config.controlPlaneCoreId)];
	return eResult::success;
}

void cControlPlane::flush_kernel_interface(KniPortData& port_data, sKniStats& stats)
{

	uint32_t packetsLength = 0;

	for (uint16_t mbuf_i = 0; mbuf_i < port_data.mbufs_count; mbuf_i++)
	{
		rte_mbuf* mbuf = port_data.mbufs[mbuf_i];
		packetsLength += rte_pktmbuf_pkt_len(mbuf);
	}

	unsigned txSize = rte_eth_tx_burst(port_data.kernel_port_id, 0, port_data.mbufs, port_data.mbufs_count);
	for (uint16_t mbuf_i = txSize; mbuf_i < port_data.mbufs_count; mbuf_i++)
	{
		rte_mbuf* mbuf = port_data.mbufs[mbuf_i];
		packetsLength -= rte_pktmbuf_pkt_len(mbuf);
	}
	auto to_drop = port_data.mbufs_count - txSize;
	rte_pktmbuf_free_bulk(&port_data.mbufs[txSize], to_drop);

	stats.idropped += to_drop;
	stats.ipackets += txSize;
	stats.ibytes += packetsLength;
	port_data.mbufs_count = 0;
}

void cControlPlane::flush_kernel_interface(KniPortData& port_data)
{
	if (!port_data.mbufs_count)
	{
		return;
	}

	unsigned txSize = rte_eth_tx_burst(port_data.kernel_port_id, 0, port_data.mbufs, port_data.mbufs_count);
	rte_pktmbuf_free_bulk(&port_data.mbufs[txSize], port_data.mbufs_count - txSize);

	port_data.mbufs_count = 0;
}

void cControlPlane::mainThread()
{
	rte_mbuf* operational[CONFIG_YADECAP_MBUFS_BURST_SIZE];

	for (;;)
	{
		if (dataPlane->config.SWNormalPriorityRateLimitPerWorker || dataPlane->config.SWICMPOutRateLimit)
		{
			SWRateLimiterTimeTracker();
		}

		slowWorker->slowWorkerBeforeHandlePackets();

		/// dequeue packets from worker's rings
		for (unsigned nIter = 0; nIter < YANET_CONFIG_RING_PRIORITY_RATIO; nIter++)
		{
			for (unsigned hIter = 0; hIter < YANET_CONFIG_RING_PRIORITY_RATIO; hIter++)
			{
				unsigned hProcessed = 0;
				for (const auto& iter : dataPlane->workers)
				{
					cWorker* worker = iter.second;
					hProcessed += ring_handle(worker->ring_toFreePackets, worker->ring_highPriority);
				}
				if (!hProcessed)
				{
					break;
				}
			}

			unsigned nProcessed = 0;
			for (const auto& iter : dataPlane->workers)
			{
				cWorker* worker = iter.second;
				nProcessed += ring_handle(worker->ring_toFreePackets, worker->ring_normalPriority);
			}
			if (!nProcessed)
			{
				break;
			}
		}
		for (const auto& iter : dataPlane->workers)
		{
			cWorker* worker = iter.second;
			ring_handle(worker->ring_toFreePackets, worker->ring_lowPriority);
		}

		if (use_kernel_interface)
		{
			for (int i = 0; i < slowWorker->basePermanently.ports.size(); ++i)
			{
				flush_kernel_interface(kernel_interfaces[i], kernel_stats[i]);
				flush_kernel_interface(in_dump_kernel_interfaces[i]);
				flush_kernel_interface(out_dump_kernel_interfaces[i]);
				flush_kernel_interface(drop_dump_kernel_interfaces[i]);
			}
		}

		/// dequeue packets from worker_gc's ring to slowworker
		rte_mbuf* mbufs[CONFIG_YADECAP_MBUFS_BURST_SIZE];
		unsigned rxSize;
		for (auto& gc : to_gcs_)
		{
			rxSize = gc.process.DequeueBurstSC(mbufs);
			for (uint16_t mbuf_i = 0; mbuf_i < rxSize; mbuf_i++)
			{
				rte_mbuf* mbuf = convertMempool(gc.free._Underlying(), mbufs[mbuf_i]);
				if (!mbuf)
				{
					continue;
				}

				dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

				sendPacketToSlowWorker(mbuf, metadata->flow);
			}
		}

		fragmentation_.handle();
		dregress.handle();

		if (use_kernel_interface)
		{
			/// recv packets from kernel interface and send to physical port
			for (int i = 0; i < slowWorker->basePermanently.ports.size(); ++i)
			{
				auto kernel_port_id = kernel_interfaces[i].kernel_port_id;

				unsigned rxSize = rte_eth_rx_burst(kernel_port_id,
				                                   0,
				                                   operational,
				                                   CONFIG_YADECAP_MBUFS_BURST_SIZE);
				uint64_t bytes = 0;
				for (uint16_t i = 0; i < rxSize; ++i)
				{
					bytes += rte_pktmbuf_pkt_len(operational[i]);
				}
				uint16_t txSize = rte_eth_tx_burst(slowWorker->basePermanently.ports.ToDpdk(i),
				                                   0,
				                                   operational,
				                                   rxSize);
				for (auto i = rxSize; i < txSize; ++i)
				{
					bytes -= rte_pktmbuf_pkt_len(operational[i]);
				}
				auto to_drop = rxSize - txSize;
				rte_pktmbuf_free_bulk(operational + txSize, to_drop);
				sKniStats& stats = kernel_stats[i];
				stats.odropped += to_drop;
				stats.opackets += txSize;
				stats.obytes += bytes;
			}

			/// recv from in.X/out.X/drop.X interfaces and free packets
			for (int i = 0; i < slowWorker->basePermanently.ports.size(); ++i)
			{
				unsigned rxSize;
				rxSize = rte_eth_rx_burst(in_dump_kernel_interfaces[i].kernel_port_id,
				                          0,
				                          operational,
				                          CONFIG_YADECAP_MBUFS_BURST_SIZE);
				rte_pktmbuf_free_bulk(operational, rxSize);

				rxSize = rte_eth_rx_burst(out_dump_kernel_interfaces[i].kernel_port_id,
				                          0,
				                          operational,
				                          CONFIG_YADECAP_MBUFS_BURST_SIZE);
				rte_pktmbuf_free_bulk(operational, rxSize);

				rxSize = rte_eth_rx_burst(drop_dump_kernel_interfaces[i].kernel_port_id,
				                          0,
				                          operational,
				                          CONFIG_YADECAP_MBUFS_BURST_SIZE);
				rte_pktmbuf_free_bulk(operational, rxSize);
			}
		}

		/// push packets to slow worker
		while (!slowWorkerMbufs.empty())
		{
			for (unsigned int i = 0;
			     i < CONFIG_YADECAP_MBUFS_BURST_SIZE;
			     i++)
			{
				if (slowWorkerMbufs.empty())
				{
					break;
				}

				auto& tuple = slowWorkerMbufs.front();
				slowWorker->slowWorkerFlow(std::get<0>(tuple), std::get<1>(tuple));

				slowWorkerMbufs.pop();
			}

			slowWorker->slowWorkerHandlePackets();
		}

		slowWorker->slowWorkerAfterHandlePackets();

		/// @todo: AUTOTEST_CONTROLPLANE

		std::this_thread::yield();

#ifdef CONFIG_YADECAP_AUTOTEST
		std::this_thread::sleep_for(std::chrono::microseconds{1});
#endif // CONFIG_YADECAP_AUTOTEST
	}
}

unsigned cControlPlane::ring_handle(rte_ring* ring_to_free_mbuf,
                                    rte_ring* ring)
{
	rte_mbuf* mbufs[CONFIG_YADECAP_MBUFS_BURST_SIZE];

	unsigned rxSize = rte_ring_sc_dequeue_burst(ring,
	                                            (void**)mbufs,
	                                            CONFIG_YADECAP_MBUFS_BURST_SIZE,
	                                            nullptr);

#ifdef CONFIG_YADECAP_AUTOTEST
	if (rxSize)
	{
		std::this_thread::sleep_for(std::chrono::microseconds{400});
	}
#endif // CONFIG_YADECAP_AUTOTEST

	for (uint16_t mbuf_i = 0; mbuf_i < rxSize; mbuf_i++)
	{
		rte_mbuf* mbuf = convertMempool(ring_to_free_mbuf, mbufs[mbuf_i]);
		if (!mbuf)
		{
			continue;
		}

		dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

		if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_nat64stateless_ingress_icmp)
		{
			handlePacket_icmp_translate_v6_to_v4(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_nat64stateless_ingress_fragmentation)
		{
			metadata->flow.type = common::globalBase::eFlowType::nat64stateless_ingress_checked;
			handlePacket_fragment(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_nat64stateless_egress_icmp)
		{
			handlePacket_icmp_translate_v4_to_v6(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_nat64stateless_egress_fragmentation)
		{
			metadata->flow.type = common::globalBase::eFlowType::nat64stateless_egress_checked;
			handlePacket_fragment(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_dregress)
		{
			handlePacket_dregress(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_nat64stateless_egress_farm)
		{
			handlePacket_farm(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_dump)
		{
			handlePacket_dump(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_repeat)
		{
			handlePacket_repeat(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_fw_sync)
		{
			handlePacket_fw_state_sync(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_balancer_icmp_forward)
		{
			handlePacket_balancer_icmp_forward(mbuf);
		}
		else
		{
			handlePacketFromForwardingPlane(mbuf);
		}
	}
	return rxSize;
}

void cControlPlane::handlePacketFromForwardingPlane(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	if (handlePacket_fw_state_sync_ingress(mbuf))
	{
		stats.fwsync_multicast_ingress_packets++;
		rte_pktmbuf_free(mbuf);
		return;
	}

#ifdef CONFIG_YADECAP_AUTOTEST
	if (metadata->flow.type != common::globalBase::eFlowType::slowWorker_kni_local)
	{
		// drop by default in tests
		stats.slowworker_drops++;
		rte_pktmbuf_free(mbuf);
		return;
	}
	rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf, rte_ether_hdr*);
	memset(ethernetHeader->dst_addr.addr_bytes,
	       0x71,
	       6);

#endif

	if (!use_kernel_interface)
	{
		// TODO stats
		unsigned txSize = rte_eth_tx_burst(metadata->fromPortId, 0, &mbuf, 1);
		if (!txSize)
		{
			rte_pktmbuf_free(mbuf);
		}
		return;
	}
	else
	{
		const auto& portmapper = slowWorker->basePermanently.ports;

		auto& iface = kernel_interfaces[portmapper.ToLogical(metadata->fromPortId)];
		if (iface.mbufs_count == CONFIG_YADECAP_MBUFS_BURST_SIZE)
		{
			flush_kernel_interface(iface, kernel_stats[portmapper.ToLogical(metadata->fromPortId)]);
		}
		iface.mbufs[iface.mbufs_count++] = mbuf;
	}
}

void cControlPlane::handlePacket_icmp_translate_v6_to_v4(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	const auto& base = slowWorker->bases[slowWorker->localBaseId & 1];
	const auto& nat64stateless = base.globalBase->nat64statelesses[metadata->flow.data.nat64stateless.id];
	const auto& translation = base.globalBase->nat64statelessTranslations[metadata->flow.data.nat64stateless.translationId];

	slowWorker->slowWorkerTranslation(mbuf, nat64stateless, translation, true);

	if (dataplane::do_icmp_translate_v6_to_v4(mbuf, translation))
	{
		slowWorker->stats.nat64stateless_ingressPackets++;
		sendPacketToSlowWorker(mbuf, nat64stateless.flow);
	}
	else
	{
		slowWorker->stats.nat64stateless_ingressUnknownICMP++;
		rte_pktmbuf_free(mbuf);
	}
}

void cControlPlane::handlePacket_icmp_translate_v4_to_v6(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	const auto& base = slowWorker->bases[slowWorker->localBaseId & 1];
	const auto& nat64stateless = base.globalBase->nat64statelesses[metadata->flow.data.nat64stateless.id];
	const auto& translation = base.globalBase->nat64statelessTranslations[metadata->flow.data.nat64stateless.translationId];

	slowWorker->slowWorkerTranslation(mbuf, nat64stateless, translation, false);

	if (dataplane::do_icmp_translate_v4_to_v6(mbuf, translation))
	{
		slowWorker->stats.nat64stateless_egressPackets++;
		sendPacketToSlowWorker(mbuf, nat64stateless.flow);
	}
	else
	{
		slowWorker->stats.nat64stateless_egressUnknownICMP++;
		rte_pktmbuf_free(mbuf);
	}
}

void cControlPlane::handlePacket_dregress(rte_mbuf* mbuf)
{
	dregress.insert(mbuf);
}

void cControlPlane::handlePacket_repeat(rte_mbuf* mbuf)
{
	const rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf, rte_ether_hdr*);
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	if (ethernetHeader->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))
	{
		const rte_vlan_hdr* vlanHeader = rte_pktmbuf_mtod_offset(mbuf, rte_vlan_hdr*, sizeof(rte_ether_hdr));

		metadata->flow.data.logicalPortId = CALCULATE_LOGICALPORT_ID(metadata->fromPortId, rte_be_to_cpu_16(vlanHeader->vlan_tci));
	}
	else
	{
		metadata->flow.data.logicalPortId = CALCULATE_LOGICALPORT_ID(metadata->fromPortId, 0);
	}

	/// @todo: opt
	slowWorker->preparePacket(mbuf);

	const auto& base = slowWorker->bases[slowWorker->localBaseId & 1];
	const auto& logicalPort = base.globalBase->logicalPorts[metadata->flow.data.logicalPortId];

	stats.repeat_packets++;
	sendPacketToSlowWorker(mbuf, logicalPort.flow);
}

void cControlPlane::handlePacket_fragment(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	const auto& base = slowWorker->bases[slowWorker->localBaseId & 1];
	const auto& nat64stateless = base.globalBase->nat64statelesses[metadata->flow.data.nat64stateless.id];

	if (nat64stateless.defrag_farm_prefix.empty() || metadata->network_headerType != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) || nat64stateless.farm)
	{
		fragmentation_.insert(mbuf);
		return;
	}

	stats.tofarm_packets++;
	slowWorker->slowWorkerHandleFragment(mbuf);
	sendPacketToSlowWorker(mbuf, nat64stateless.flow);
}

void cControlPlane::handlePacket_farm(rte_mbuf* mbuf)
{
	stats.farm_packets++;
	slowWorker->slowWorkerFarmHandleFragment(mbuf);
}

void cControlPlane::handlePacket_fw_state_sync(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	const auto& base = slowWorker->bases[slowWorker->localBaseId & 1];
	const auto& fw_state_config = base.globalBase->fw_state_sync_configs[metadata->flow.data.aclId];

	metadata->network_headerType = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	metadata->network_headerOffset = sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr);
	metadata->transport_headerType = IPPROTO_UDP;
	metadata->transport_headerOffset = metadata->network_headerOffset + sizeof(rte_ipv6_hdr);

	generic_rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf, generic_rte_ether_hdr*);
	ethernetHeader->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
	rte_ether_addr_copy(&fw_state_config.ether_address_destination, &ethernetHeader->dst_addr);

	rte_vlan_hdr* vlanHeader = rte_pktmbuf_mtod_offset(mbuf, rte_vlan_hdr*, sizeof(rte_ether_hdr));
	vlanHeader->eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

	rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);
	ipv6Header->vtc_flow = rte_cpu_to_be_32(0x6 << 28);
	ipv6Header->payload_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + sizeof(dataplane::globalBase::fw_state_sync_frame_t));
	ipv6Header->proto = IPPROTO_UDP;
	ipv6Header->hop_limits = 64;
	memcpy(ipv6Header->src_addr, fw_state_config.ipv6_address_source.bytes, 16);
	memcpy(ipv6Header->dst_addr, fw_state_config.ipv6_address_multicast.bytes, 16);

	rte_udp_hdr* udpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_udp_hdr*, metadata->network_headerOffset + sizeof(rte_ipv6_hdr));
	udpHeader->src_port = fw_state_config.port_multicast; // IPFW reuses the same port for both src and dst.
	udpHeader->dst_port = fw_state_config.port_multicast;
	udpHeader->dgram_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + sizeof(dataplane::globalBase::fw_state_sync_frame_t));
	udpHeader->dgram_cksum = 0;
	udpHeader->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6Header, udpHeader);

	// Iterate for all interested ports.
	for (unsigned int port_id = 0; port_id < fw_state_config.flows_size; port_id++)
	{
		rte_mbuf* mbuf_clone = rte_pktmbuf_alloc(mempool);
		if (mbuf_clone == nullptr)
		{
			slowWorker->stats.fwsync_multicast_egress_drops++;
			continue;
		}

		*YADECAP_METADATA(mbuf_clone) = *YADECAP_METADATA(mbuf);

		memcpy(rte_pktmbuf_mtod(mbuf_clone, char*),
		       rte_pktmbuf_mtod(mbuf, char*),
		       mbuf->data_len);
		mbuf_clone->data_len = mbuf->data_len;
		mbuf_clone->pkt_len = mbuf->pkt_len;

		const auto& flow = fw_state_config.flows[port_id];
		slowWorker->stats.fwsync_multicast_egress_packets++;
		sendPacketToSlowWorker(mbuf_clone, flow);
	}

	if (!fw_state_config.ipv6_address_unicast.empty())
	{
		memcpy(ipv6Header->src_addr, fw_state_config.ipv6_address_unicast_source.bytes, 16);
		memcpy(ipv6Header->dst_addr, fw_state_config.ipv6_address_unicast.bytes, 16);
		udpHeader->src_port = fw_state_config.port_unicast;
		udpHeader->dst_port = fw_state_config.port_unicast;
		udpHeader->dgram_cksum = 0;
		udpHeader->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6Header, udpHeader);

		rte_mbuf* mbuf_clone = rte_pktmbuf_alloc(mempool);
		if (mbuf_clone == nullptr)
		{
			slowWorker->stats.fwsync_unicast_egress_drops++;
		}
		else
		{
			*YADECAP_METADATA(mbuf_clone) = *YADECAP_METADATA(mbuf);

			memcpy(rte_pktmbuf_mtod(mbuf_clone, char*),
			       rte_pktmbuf_mtod(mbuf, char*),
			       mbuf->data_len);
			mbuf_clone->data_len = mbuf->data_len;
			mbuf_clone->pkt_len = mbuf->pkt_len;

			slowWorker->stats.fwsync_unicast_egress_packets++;
			sendPacketToSlowWorker(mbuf_clone, fw_state_config.ingress_flow);
		}
	}

	rte_pktmbuf_free(mbuf);
}

bool cControlPlane::handlePacket_fw_state_sync_ingress(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	generic_rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf, generic_rte_ether_hdr*);
	if ((ethernetHeader->dst_addr.addr_bytes[0] & 1) == 0)
	{
		return false;
	}

	// Confirmed multicast packet.
	// Try to match against our multicast groups.
	if (ethernetHeader->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))
	{
		return false;
	}

	rte_vlan_hdr* vlanHeader = rte_pktmbuf_mtod_offset(mbuf, rte_vlan_hdr*, sizeof(rte_ether_hdr));
	if (vlanHeader->eth_proto != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
	{
		return false;
	}

	rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr));
	if (metadata->transport_headerType != IPPROTO_UDP)
	{
		return false;
	}

	const auto udp_payload_len = rte_be_to_cpu_16(ipv6Header->payload_len) - sizeof(rte_udp_hdr);
	// Can contain multiple states per sync packet.
	if (udp_payload_len % sizeof(dataplane::globalBase::fw_state_sync_frame_t) != 0)
	{
		return false;
	}

	tAclId aclId;
	{
		std::lock_guard<std::mutex> lock(fw_state_multicast_acl_ids_mutex);
		auto it = fw_state_multicast_acl_ids.find(common::ipv6_address_t(ipv6Header->dst_addr));
		if (it == std::end(fw_state_multicast_acl_ids))
		{
			return false;
		}

		aclId = it->second;
	}

	const auto& base = slowWorker->bases[slowWorker->localBaseId & 1];
	const auto& fw_state_config = base.globalBase->fw_state_sync_configs[aclId];

	if (memcmp(ipv6Header->src_addr, fw_state_config.ipv6_address_source.bytes, 16) == 0)
	{
		// Ignore self-generated packets.
		return false;
	}

	rte_udp_hdr* udpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_udp_hdr*, sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr) + sizeof(rte_ipv6_hdr));
	if (udpHeader->dst_port != fw_state_config.port_multicast)
	{
		return false;
	}

	for (size_t idx = 0; idx < udp_payload_len / sizeof(dataplane::globalBase::fw_state_sync_frame_t); ++idx)
	{
		dataplane::globalBase::fw_state_sync_frame_t* payload = rte_pktmbuf_mtod_offset(
		        mbuf,
		        dataplane::globalBase::fw_state_sync_frame_t*,
		        sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr) + sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) + idx * sizeof(dataplane::globalBase::fw_state_sync_frame_t));

		if (payload->addr_type == 6)
		{
			dataplane::globalBase::fw6_state_key_t key;
			key.proto = payload->proto;
			key.__nap = 0;
			// Swap src and dst addresses.
			memcpy(key.dst_addr.bytes, payload->src_ip6.bytes, 16);
			memcpy(key.src_addr.bytes, payload->dst_ip6.bytes, 16);

			if (payload->proto == IPPROTO_TCP || payload->proto == IPPROTO_UDP)
			{
				// Swap src and dst ports.
				key.dst_port = payload->src_port;
				key.src_port = payload->dst_port;
			}
			else
			{
				key.dst_port = 0;
				key.src_port = 0;
			}

			dataplane::globalBase::fw_state_value_t value;
			value.type = static_cast<dataplane::globalBase::fw_state_type>(payload->proto);
			value.owner = dataplane::globalBase::fw_state_owner_e::external;
			value.last_seen = slowWorker->basePermanently.globalBaseAtomic->currentTime;
			value.flow = fw_state_config.ingress_flow;
			value.acl_id = aclId;
			value.last_sync = slowWorker->basePermanently.globalBaseAtomic->currentTime;
			value.packets_since_last_sync = 0;
			value.packets_backward = 0;
			value.packets_forward = 0;
			value.tcp.unpack(payload->flags);

			uint32_t state_timeout = dataPlane->getConfigValues().stateful_firewall_other_protocols_timeout;
			if (payload->proto == IPPROTO_UDP)
			{
				state_timeout = dataPlane->getConfigValues().stateful_firewall_udp_timeout;
			}
			else if (payload->proto == IPPROTO_TCP)
			{
				state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_timeout;
				uint8_t flags = value.tcp.src_flags | value.tcp.dst_flags;
				if (flags & (uint8_t)common::fwstate::tcp_flags_e::ACK)
				{
					state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_syn_ack_timeout;
				}
				else if (flags & (uint8_t)common::fwstate::tcp_flags_e::SYN)
				{
					state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_syn_timeout;
				}
				if (flags & (uint8_t)common::fwstate::tcp_flags_e::FIN)
				{
					state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_fin_timeout;
				}
			}
			value.state_timeout = state_timeout;

			for (auto& [socketId, globalBaseAtomic] : dataPlane->globalBaseAtomics)
			{
				(void)socketId;

				dataplane::globalBase::fw_state_value_t* lookup_value;
				dataplane::spinlock_nonrecursive_t* locker;
				const uint32_t hash = globalBaseAtomic->fw6_state->lookup(key, lookup_value, locker);
				if (lookup_value)
				{
					// Keep state alive for us even if there were no packets received.
					// Do not reset other counters.
					lookup_value->last_seen = slowWorker->basePermanently.globalBaseAtomic->currentTime;
					lookup_value->tcp.src_flags |= value.tcp.src_flags;
					lookup_value->tcp.dst_flags |= value.tcp.dst_flags;
					lookup_value->state_timeout = std::max(lookup_value->state_timeout, value.state_timeout);
				}
				else
				{
					globalBaseAtomic->fw6_state->insert(hash, key, value);
				}
				locker->unlock();
			}
		}
		else if (payload->addr_type == 4)
		{
			dataplane::globalBase::fw4_state_key_t key;
			key.proto = payload->proto;
			key.__nap = 0;
			// Swap src and dst addresses.
			key.dst_addr.address = payload->src_ip;
			key.src_addr.address = payload->dst_ip;

			if (payload->proto == IPPROTO_TCP || payload->proto == IPPROTO_UDP)
			{
				// Swap src and dst ports.
				key.dst_port = payload->src_port;
				key.src_port = payload->dst_port;
			}
			else
			{
				key.dst_port = 0;
				key.src_port = 0;
			}

			dataplane::globalBase::fw_state_value_t value;
			value.type = static_cast<dataplane::globalBase::fw_state_type>(payload->proto);
			value.owner = dataplane::globalBase::fw_state_owner_e::external;
			value.last_seen = slowWorker->basePermanently.globalBaseAtomic->currentTime;
			value.flow = fw_state_config.ingress_flow;
			value.acl_id = aclId;
			value.last_sync = slowWorker->basePermanently.globalBaseAtomic->currentTime;
			value.packets_since_last_sync = 0;
			value.packets_backward = 0;
			value.packets_forward = 0;
			value.tcp.unpack(payload->flags);

			uint32_t state_timeout = dataPlane->getConfigValues().stateful_firewall_other_protocols_timeout;
			if (payload->proto == IPPROTO_UDP)
			{
				state_timeout = dataPlane->getConfigValues().stateful_firewall_udp_timeout;
			}
			else if (payload->proto == IPPROTO_TCP)
			{
				state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_timeout;
				uint8_t flags = value.tcp.src_flags | value.tcp.dst_flags;
				if (flags & (uint8_t)common::fwstate::tcp_flags_e::ACK)
				{
					state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_syn_ack_timeout;
				}
				else if (flags & (uint8_t)common::fwstate::tcp_flags_e::SYN)
				{
					state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_syn_timeout;
				}
				if (flags & (uint8_t)common::fwstate::tcp_flags_e::FIN)
				{
					state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_fin_timeout;
				}
			}
			value.state_timeout = state_timeout;

			for (auto& [socketId, globalBaseAtomic] : dataPlane->globalBaseAtomics)
			{
				(void)socketId;

				dataplane::globalBase::fw_state_value_t* lookup_value;
				dataplane::spinlock_nonrecursive_t* locker;
				const uint32_t hash = globalBaseAtomic->fw4_state->lookup(key, lookup_value, locker);
				if (lookup_value)
				{
					// Keep state alive for us even if there were no packets received.
					// Do not reset other counters.
					lookup_value->last_seen = slowWorker->basePermanently.globalBaseAtomic->currentTime;
					lookup_value->tcp.src_flags |= value.tcp.src_flags;
					lookup_value->tcp.dst_flags |= value.tcp.dst_flags;
					lookup_value->state_timeout = std::max(lookup_value->state_timeout, value.state_timeout);
				}
				else
				{
					globalBaseAtomic->fw4_state->insert(hash, key, value);
				}
				locker->unlock();
			}
		}
	}

	return true;
}

void cControlPlane::handlePacket_balancer_icmp_forward(rte_mbuf* mbuf)
{
	if (dataPlane->config.SWICMPOutRateLimit != 0)
	{
		if (icmpOutRemainder == 0)
		{
			slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_out_rate_limit_reached]++;
			rte_pktmbuf_free(mbuf);
			return;
		}

		--icmpOutRemainder;
	}

	std::lock_guard<std::mutex> unrdup_guard(unrdup_mutex);
	std::lock_guard<std::mutex> interfaces_ips_guard(interfaces_ips_mutex);
	std::lock_guard<std::mutex> services_guard(vip_vport_proto_mutex);

	const auto& base = slowWorker->bases[slowWorker->localBaseId & 1];

	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	common::ip_address_t original_src_from_icmp_payload;
	common::ip_address_t src_from_ip_header;
	uint16_t original_src_port_from_icmp_payload;

	uint32_t balancer_id = metadata->flow.data.balancer.id;

	dataplane::metadata inner_metadata;

	if (metadata->transport_headerType == IPPROTO_ICMP)
	{
		rte_ipv4_hdr* ipv4Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
		src_from_ip_header = common::ip_address_t(rte_be_to_cpu_32(ipv4Header->src_addr));

		rte_ipv4_hdr* icmpPayloadIpv4Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->transport_headerOffset + sizeof(icmpv4_header_t));
		original_src_from_icmp_payload = common::ip_address_t(rte_be_to_cpu_32(icmpPayloadIpv4Header->src_addr));

		inner_metadata.network_headerType = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		inner_metadata.network_headerOffset = metadata->transport_headerOffset + sizeof(icmpv4_header_t);
	}
	else
	{
		rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);
		src_from_ip_header = common::ip_address_t(ipv6Header->src_addr);

		rte_ipv6_hdr* icmpPayloadIpv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->transport_headerOffset + sizeof(icmpv6_header_t));
		original_src_from_icmp_payload = common::ip_address_t(icmpPayloadIpv6Header->src_addr);

		inner_metadata.network_headerType = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
		inner_metadata.network_headerOffset = metadata->transport_headerOffset + sizeof(icmpv6_header_t);
	}

	if (!prepareL3(mbuf, &inner_metadata))
	{
		/* we are not suppossed to get in here anyway, same check was done earlier by balancer_icmp_forward_handle(),
		   but we needed to call prepareL3() to determine icmp payload original packets transport header offset */
		if (inner_metadata.network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		{
			slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_drop_icmpv4_payload_too_short_ip]++;
		}
		else
		{
			slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_drop_icmpv6_payload_too_short_ip]++;
		}

		rte_pktmbuf_free(mbuf);
		return;
	}

	if (inner_metadata.transport_headerType != IPPROTO_TCP && inner_metadata.transport_headerType != IPPROTO_UDP)
	{
		// not supported protocol for cloning and distributing, drop
		rte_pktmbuf_free(mbuf);
		slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_drop_unexpected_transport_protocol]++;
		return;
	}

	// check whether ICMP payload is too short to contain "offending" packet's IP header and ports is performed earlier by balancer_icmp_forward_handle()
	void* icmpPayloadTransportHeader = rte_pktmbuf_mtod_offset(mbuf, void*, inner_metadata.transport_headerOffset);

	// both TCP and UDP headers have src port (16 bits) as the first field
	original_src_port_from_icmp_payload = rte_be_to_cpu_16(*(uint16_t*)icmpPayloadTransportHeader);

	if (vip_to_balancers.size() <= balancer_id)
	{
		// no vip_to_balancers table for this balancer_id
		rte_pktmbuf_free(mbuf);
		slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_drop_no_unrdup_table_for_balancer_id]++;
		return;
	}

	if (!vip_to_balancers[balancer_id].count(original_src_from_icmp_payload))
	{
		// vip is not listed in unrdup config - neighbor balancers are unknown, drop
		rte_pktmbuf_free(mbuf);
		slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_drop_unrdup_vip_not_found]++;
		return;
	}

	if (vip_vport_proto.size() <= balancer_id)
	{
		// no vip_vport_proto table for this balancer_id
		rte_pktmbuf_free(mbuf);
		slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_drop_no_vip_vport_proto_table_for_balancer_id]++;
		return;
	}

	if (!vip_vport_proto[balancer_id].count({original_src_from_icmp_payload, original_src_port_from_icmp_payload, inner_metadata.transport_headerType}))
	{
		// such combination of vip-vport-protocol is absent, don't clone, drop
		rte_pktmbuf_free(mbuf);
		slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_drop_unknown_service]++;
		return;
	}

	const auto& neighbor_balancers = vip_to_balancers[balancer_id][original_src_from_icmp_payload];

	for (const auto& neighbor_balancer : neighbor_balancers)
	{
		// will not send a cloned packet if source address in "balancer" section of controlplane.conf is absent
		if (neighbor_balancer.is_ipv4() && !base.globalBase->balancers[metadata->flow.data.balancer.id].source_ipv4.address)
		{
			slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_no_balancer_src_ipv4]++;
			continue;
		}

		if (neighbor_balancer.is_ipv6() && base.globalBase->balancers[metadata->flow.data.balancer.id].source_ipv6.empty())
		{
			slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_no_balancer_src_ipv6]++;
			continue;
		}

		rte_mbuf* mbuf_clone = rte_pktmbuf_alloc(mempool);
		if (mbuf_clone == nullptr)
		{
			slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_failed_to_clone]++;
			continue;
		}

		*YADECAP_METADATA(mbuf_clone) = *YADECAP_METADATA(mbuf);
		dataplane::metadata* clone_metadata = YADECAP_METADATA(mbuf_clone);

		rte_memcpy(rte_pktmbuf_mtod(mbuf_clone, char*),
		           rte_pktmbuf_mtod(mbuf, char*),
		           mbuf->data_len);

		if (neighbor_balancer.is_ipv4())
		{
			rte_pktmbuf_prepend(mbuf_clone, sizeof(rte_ipv4_hdr));
			memmove(rte_pktmbuf_mtod(mbuf_clone, char*),
			        rte_pktmbuf_mtod_offset(mbuf_clone, char*, sizeof(rte_ipv4_hdr)),
			        clone_metadata->network_headerOffset);

			rte_ipv4_hdr* outerIpv4Header = rte_pktmbuf_mtod_offset(mbuf_clone, rte_ipv4_hdr*, clone_metadata->network_headerOffset);

			outerIpv4Header->src_addr = base.globalBase->balancers[metadata->flow.data.balancer.id].source_ipv4.address;
			outerIpv4Header->dst_addr = rte_cpu_to_be_32(neighbor_balancer.get_ipv4());

			outerIpv4Header->version_ihl = 0x45;
			outerIpv4Header->type_of_service = 0x00;
			outerIpv4Header->packet_id = rte_cpu_to_be_16(0x01);
			outerIpv4Header->fragment_offset = 0;
			outerIpv4Header->time_to_live = 64;

			outerIpv4Header->total_length = rte_cpu_to_be_16((uint16_t)(mbuf->pkt_len - clone_metadata->network_headerOffset + sizeof(rte_ipv4_hdr)));

			if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
			{
				outerIpv4Header->next_proto_id = IPPROTO_IPIP;
			}
			else
			{
				outerIpv4Header->next_proto_id = IPPROTO_IPV6;
			}

			yanet_ipv4_checksum(outerIpv4Header);

			mbuf_clone->data_len = mbuf->data_len + sizeof(rte_ipv4_hdr);
			mbuf_clone->pkt_len = mbuf->pkt_len + sizeof(rte_ipv4_hdr);

			// might need to change next protocol type in ethernet/vlan header in cloned packet

			rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf_clone, rte_ether_hdr*);
			if (ethernetHeader->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))
			{
				rte_vlan_hdr* vlanHeader = rte_pktmbuf_mtod_offset(mbuf_clone, rte_vlan_hdr*, sizeof(rte_ether_hdr));
				vlanHeader->eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
			}
			else
			{
				ethernetHeader->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
			}
		}
		else if (neighbor_balancer.is_ipv6())
		{
			rte_pktmbuf_prepend(mbuf_clone, sizeof(rte_ipv6_hdr));
			memmove(rte_pktmbuf_mtod(mbuf_clone, char*),
			        rte_pktmbuf_mtod_offset(mbuf_clone, char*, sizeof(rte_ipv6_hdr)),
			        clone_metadata->network_headerOffset);

			rte_ipv6_hdr* outerIpv6Header = rte_pktmbuf_mtod_offset(mbuf_clone, rte_ipv6_hdr*, clone_metadata->network_headerOffset);

			rte_memcpy(outerIpv6Header->src_addr, base.globalBase->balancers[metadata->flow.data.balancer.id].source_ipv6.bytes, sizeof(outerIpv6Header->src_addr));
			if (src_from_ip_header.is_ipv6())
			{
				((uint32_t*)outerIpv6Header->src_addr)[2] = ((uint32_t*)src_from_ip_header.get_ipv6().data())[2] ^ ((uint32_t*)src_from_ip_header.get_ipv6().data())[3];
			}
			else
			{
				((uint32_t*)outerIpv6Header->src_addr)[2] = src_from_ip_header.get_ipv4();
			}
			rte_memcpy(outerIpv6Header->dst_addr, neighbor_balancer.get_ipv6().data(), sizeof(outerIpv6Header->dst_addr));

			outerIpv6Header->vtc_flow = rte_cpu_to_be_32((0x6 << 28));
			outerIpv6Header->payload_len = rte_cpu_to_be_16((uint16_t)(mbuf->pkt_len - clone_metadata->network_headerOffset));
			outerIpv6Header->hop_limits = 64;

			if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
			{
				outerIpv6Header->proto = IPPROTO_IPIP;
			}
			else
			{
				outerIpv6Header->proto = IPPROTO_IPV6;
			}

			mbuf_clone->data_len = mbuf->data_len + sizeof(rte_ipv6_hdr);
			mbuf_clone->pkt_len = mbuf->pkt_len + sizeof(rte_ipv6_hdr);

			// might need to change next protocol type in ethernet/vlan header in cloned packet

			rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf_clone, rte_ether_hdr*);
			if (ethernetHeader->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))
			{
				rte_vlan_hdr* vlanHeader = rte_pktmbuf_mtod_offset(mbuf_clone, rte_vlan_hdr*, sizeof(rte_ether_hdr));
				vlanHeader->eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
			}
			else
			{
				ethernetHeader->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
			}
		}

		slowWorker->counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_clone_forwarded]++;

		const auto& flow = base.globalBase->balancers[metadata->flow.data.balancer.id].flow;

		slowWorker->preparePacket(mbuf_clone);
		sendPacketToSlowWorker(mbuf_clone, flow);
	}

	// packet itself is not going anywhere, only its clones with prepended header
	rte_pktmbuf_free(mbuf);
}

void cControlPlane::handlePacket_dump(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	const auto& portmapper = slowWorker->basePermanently.ports;
	if (!portmapper.ValidDpdk(metadata->flow.data.dump.id))
	{
		stats.unknown_dump_interface++;
		rte_pktmbuf_free(mbuf);
		return;
	}
	const auto local_port_id = portmapper.ToLogical(metadata->flow.data.dump.id);

	auto push = [this, mbuf](KniPortData& iface) {
		if (iface.mbufs_count == CONFIG_YADECAP_MBUFS_BURST_SIZE)
		{
			flush_kernel_interface(iface);
		}
		iface.mbufs[iface.mbufs_count++] = mbuf;
	};

	if (metadata->flow.data.dump.type == common::globalBase::dump_type_e::physicalPort_ingress)
	{
		push(in_dump_kernel_interfaces[local_port_id]);
		return;
	}
	else if (metadata->flow.data.dump.type == common::globalBase::dump_type_e::physicalPort_egress)
	{
		push(out_dump_kernel_interfaces[local_port_id]);
		return;
	}
	else if (metadata->flow.data.dump.type == common::globalBase::dump_type_e::physicalPort_drop)
	{
		push(drop_dump_kernel_interfaces[local_port_id]);
		return;
	}

	stats.unknown_dump_interface++;
	rte_pktmbuf_free(mbuf);
}

rte_mbuf* cControlPlane::convertMempool(rte_ring* ring_to_free_mbuf,
                                        rte_mbuf* old_mbuf)
{
	/// we dont support attached mbufs

	rte_mbuf* mbuf = rte_pktmbuf_alloc(mempool);
	if (!mbuf)
	{
		stats.mempool_is_empty++;

		freeWorkerPacket(ring_to_free_mbuf, old_mbuf);
		return nullptr;
	}

	*YADECAP_METADATA(mbuf) = *YADECAP_METADATA(old_mbuf);

	/// @todo: rte_pktmbuf_append() and check error

	memcpy(rte_pktmbuf_mtod(mbuf, char*),
	       rte_pktmbuf_mtod(old_mbuf, char*),
	       old_mbuf->data_len);

	mbuf->data_len = old_mbuf->data_len;
	mbuf->pkt_len = old_mbuf->pkt_len;

	freeWorkerPacket(ring_to_free_mbuf, old_mbuf);

	if (rte_mbuf_refcnt_read(mbuf) != 1)
	{
		YADECAP_LOG_ERROR("something wrong\n");
	}

	return mbuf;
}

void cControlPlane::sendPacketToSlowWorker(rte_mbuf* mbuf,
                                           const common::globalBase::tFlow& flow)
{
	/// we dont support attached mbufs

	if (slowWorkerMbufs.size() >= 1024) ///< @todo: variable
	{
		stats.slowworker_drops++;
		rte_pktmbuf_free(mbuf);
		return;
	}

	stats.slowworker_packets++;
	slowWorkerMbufs.emplace(mbuf, flow);
}

void cControlPlane::freeWorkerPacket(rte_ring* ring_to_free_mbuf,
                                     rte_mbuf* mbuf)
{
	if (ring_to_free_mbuf == slowWorker->ring_toFreePackets)
	{
		rte_pktmbuf_free(mbuf);
		return;
	}

	while (rte_ring_sp_enqueue(ring_to_free_mbuf, mbuf) != 0)
	{
		std::this_thread::yield();
	}
}

void cControlPlane::SWRateLimiterTimeTracker()
{
	// seem to be sufficiently fast function for slowWorker whose threshold is 200'000 packets per second
	std::chrono::high_resolution_clock::time_point curTimePointForSWRateLimiter = std::chrono::high_resolution_clock::now();

	// is it time to reset icmpPacketsToSW counters?
	if (std::chrono::duration_cast<std::chrono::milliseconds>(curTimePointForSWRateLimiter - prevTimePointForSWRateLimiter) >= std::chrono::milliseconds(1000 / dataPlane->config.rateLimitDivisor))
	{
		// the only place thread-shared variable icmpPacketsToSW is changed
		for (auto& [coreId, worker] : dataPlane->workers)
		{
			(void)coreId;

			if (slowWorker == worker)
			{
				continue;
			}

			__atomic_store_n(&worker->packetsToSWNPRemainder, dataPlane->config.SWNormalPriorityRateLimitPerWorker, __ATOMIC_RELAXED);
		}

		icmpOutRemainder = dataPlane->config.SWICMPOutRateLimit / dataPlane->config.rateLimitDivisor;

		prevTimePointForSWRateLimiter = curTimePointForSWRateLimiter;
	}
}
