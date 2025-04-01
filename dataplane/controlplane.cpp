#include <linux/if.h>
#include <optional>
#include <sys/ioctl.h>
#include <sys/un.h>

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "common.h"
#include "common/version.h"
#include "dataplane.h"
#include "dataplane/worker_gc.h"
#include "debug_latch.h"

cControlPlane::cControlPlane(cDataPlane* dataPlane) :
        dataPlane(dataPlane),
        use_kernel_interface(false)
{
	memset(&stats, 0, sizeof(stats));
}

eResult cControlPlane::init(bool use_kernel_interface)
{
	this->use_kernel_interface = use_kernel_interface;

	eResult result = eResult::success;

	return result;
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

common::idp::getWorkerStats::response cControlPlane::getWorkerStats(const common::idp::getWorkerStats::request& request)
{
	/// unsafe

	common::idp::getWorkerStats::response response;

	auto add_stats_to_response = [this, &response](tCoreId coreId, const cWorker* worker) {
		std::map<tPortId, common::worker::stats::port> portsStats;
		for (const auto& portIter : dataPlane->ports)
		{
			portsStats[portIter.first] = worker->statsPorts[portIter.first];
		}

		response[coreId] = {worker->iteration,
		                    *worker->stats,
		                    portsStats};
	};

	if (!request.empty())
	{
		for (const auto& coreId : request)
		{
			const cWorker* worker{};
			if (auto it = dataPlane->workers.find(coreId); it != dataPlane->workers.end())
			{
				worker = it->second;
			}
			if (!worker)
			{
				if (auto slow = dataPlane->slow_workers.find(coreId); slow != dataPlane->slow_workers.end())
				{
					worker = slow->second->GetWorker();
				}
			}
			if (!worker)
			{
				YANET_LOG_ERROR("Worker stats requested for non-worker core id (%d)\n", coreId);
				continue;
			}

			add_stats_to_response(coreId, worker);
		}
	}
	else
	{
		/// all workers

		for (const cWorker* worker : dataPlane->workers_vector)
		{
			add_stats_to_response(worker->coreId, worker);
		}
	}

	return response;
}

const std::vector<cWorker*>& cControlPlane::workers_vector() const
{
	return dataPlane->workers_vector;
}

const std::map<tCoreId, dataplane::SlowWorker*>& cControlPlane::slow_workers() const
{
	return dataPlane->slow_workers;
}

common::slowworker::stats_t cControlPlane::SlowWorkerStats() const
{
	return accumulateSlowWorkerStats(
	        [](dataplane::SlowWorker* worker) {
		        return worker->Stats();
	        });
}

common::idp::getSlowWorkerStats::response cControlPlane::SlowWorkerStatsResponse()
{
	/// unsafe

	common::idp::getSlowWorkerStats::response response;
	auto& [slowworker_stats, hashtable_gc_stats] = response;

	slowworker_stats = SlowWorkerStats();
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
		GCC_BUG_UNUSED(core_id);

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

eResult cControlPlane::clearWorkerDumpRings()
{
	for (const cWorker* worker : dataPlane->workers_vector)
	{
		for (const auto& [tag, ring_cfg] : dataPlane->config.shared_memory)
		{
			GCC_BUG_UNUSED(ring_cfg);
			YANET_LOG_DEBUG("Cleaning dataplane dump ring %s", tag.data());
			worker->dump_rings[dataPlane->tag_to_id[tag]]->Clear();
		}
	}

	return eResult::success;
}

common::idp::get_worker_gc_stats::response cControlPlane::get_worker_gc_stats()
{
	common::idp::get_worker_gc_stats::response response;

	for (const auto& [core_id, worker] : dataPlane->worker_gcs)
	{
		response[core_id] = {worker->iteration,
		                     *worker->stats};
	}

	return response;
}

common::idp::get_dregress_counters::response cControlPlane::get_dregress_counters()
{
	common::dregress::counters_t counters_v4;
	common::dregress::counters_t counters_v6;
	for (auto& [core, slow] : dataPlane->slow_workers)
	{
		GCC_BUG_UNUSED(core);
		dregress_t& dregress = slow->Dregress();
		auto guard = dregress.LockCounters();
		counters_v4.merge(dregress.Counters4());
		counters_v6.merge(dregress.Counters6());
		dregress.ClearCounters();
	}
	common::stream_out_t stream;
	counters_v4.push(stream);
	counters_v6.push(stream);
	return stream.getBuffer();
}

common::idp::get_ports_stats::response cControlPlane::get_ports_stats()
{
	common::idp::get_ports_stats::response response;

	for (const auto& [portId, port] : dataPlane->ports)
	{
		GCC_BUG_UNUSED(port);

		rte_eth_stats stats;
		{
			std::lock_guard<std::mutex> guard(dataPlane->dpdk_mutex);
			rte_eth_stats_get(portId, &stats);
		}

		uint64_t physicalPort_egress_drops = accumulateWorkerStats(
		        [portId](cWorker* worker) {
			        return worker->statsPorts[portId].physicalPort_egress_drops;
		        });

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
		GCC_BUG_UNUSED(_);

		auto portStats = dataPlane->getPortStats(portId);
		response[portId] = portStats;
	}

	return response;
}

common::idp::getControlPlanePortStats::response cControlPlane::getControlPlanePortStats(const common::idp::getControlPlanePortStats::request& request)
{
	/// unsafe

	common::idp::getControlPlanePortStats::response response;

	if (!use_kernel_interface)
	{
		return response;
	}

	if (request.size())
	{
		for (const auto& portId : request)
		{
			const auto& maybe_stats = KniStats(portId);
			if (!maybe_stats)
			{
				YANET_LOG_ERROR("Controlplane statistics requested for invalid port id ( %u )", portId);
			}
			const dataplane::sKniStats& stats = maybe_stats.value();

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
		for (auto& [core, slow] : dataPlane->slow_workers)
		{
			GCC_BUG_UNUSED(core);
			const auto& kni_worker = slow->KniWorker();

			auto stats = kni_worker.PortsStats().first;
			for (auto [current, end] = kni_worker.PortsIds(); current != end; ++current, ++stats)
			{
				response[*current] = {stats->ipackets,
				                      stats->ibytes,
				                      0,
				                      stats->idropped,
				                      stats->opackets,
				                      stats->obytes,
				                      0,
				                      stats->odropped};
			}
		}
	}

	return response;
}

common::idp::getFragmentationStats::response cControlPlane::getFragmentationStats() const
{
	return accumulateSlowWorkerStats(
	        [](dataplane::SlowWorker* worker) {
		        return worker->Fragmentation().getStats();
	        });
}

common::dregress::stats_t cControlPlane::DregressStats() const
{
	return accumulateSlowWorkerStats(
	        [](dataplane::SlowWorker* worker) {
		        return worker->Dregress().Stats();
	        });
}

std::optional<std::reference_wrapper<const dataplane::sKniStats>> cControlPlane::KniStats(tPortId pid) const
{
	// Dumb iteration over slow workers and their assigned ports, should not be a bottleneck
	for (auto& [core, slow] : dataPlane->slow_workers)
	{
		GCC_BUG_UNUSED(core);
		if (const auto& stats = slow->KniWorker().PortStats(pid))
		{
			return stats;
		}
	}
	return std::nullopt;
}

dataplane::hashtable_chain_spinlock_stats_t cControlPlane::DregressConnectionsStats() const
{
	return accumulateSlowWorkerStats(
	        [](dataplane::SlowWorker* worker) {
		        return worker->Dregress().Connections()->stats();
	        });
}

dregress::LimitsStats cControlPlane::DregressLimitsStats() const
{
	return accumulateSlowWorkerStats(
	        [](dataplane::SlowWorker* worker) {
		        return worker->Dregress().limits();
	        });
}

common::idp::getFWState::response cControlPlane::getFWState()
{
	common::idp::getFWState::response response;

	for (const auto& [core_id, worker_gc] : dataPlane->worker_gcs)
	{
		GCC_BUG_UNUSED(core_id);

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
		GCC_BUG_UNUSED(socket_id);

		stats.fwstate4_size = std::max(stats.fwstate4_size, (uint64_t)globalbase_atomics->updater.fw4_state.get_stats().keys_count);
		stats.fwstate6_size = std::max(stats.fwstate6_size, (uint64_t)globalbase_atomics->updater.fw6_state.get_stats().keys_count);
	}

	return stats;
}

eResult cControlPlane::clearFWState()
{
	for (auto& [socketId, globalBaseAtomic] : dataPlane->globalBaseAtomics)
	{
		GCC_BUG_UNUSED(socketId);

		globalBaseAtomic->fw4_state->clear();
		globalBaseAtomic->fw6_state->clear();
	}
	return common::result_e::success;
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

common::idp::getConfig::response cControlPlane::getConfig() const
{
	common::idp::getConfig::response response;
	auto& [response_ports, response_workers, response_values] = response;

	for (const auto& [port_id, port] : dataPlane->ports)
	{
		const auto& [interface_name, rx_queues, tx_queues_count, mac_address, pci, symmetric_mode] = port;
		GCC_BUG_UNUSED(rx_queues);
		GCC_BUG_UNUSED(tx_queues_count);
		GCC_BUG_UNUSED(symmetric_mode);

		response_ports[port_id] = {interface_name,
		                           rte_eth_dev_socket_id(port_id),
		                           mac_address,
		                           pci};
	}

	for (const cWorker* worker : dataPlane->workers_vector)
	{
		for (const auto& endpoint : worker->basePermanently.rx_points)
		{
			std::get<0>(response_workers[worker->coreId]).emplace_back(endpoint.port);
		}

		std::get<1>(response_workers[worker->coreId]) = worker->socketId;
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

		uint32_t valueId = 0;
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

		uint32_t valueId = 0;
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
		GCC_BUG_UNUSED(core_id);

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

common::idp::hitcount_dump::response cControlPlane::hitcount_dump()
{
	return dataPlane->getHitcountMap();
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
			globalBase->updater.vrf_route_lpm4->limits(response);
			globalBase->updater.vrf_route_lpm6->limits(response);
			globalBase->updater.vrf_route_tunnel_lpm4->limits(response);
			globalBase->updater.vrf_route_tunnel_lpm6->limits(response);

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
		GCC_BUG_UNUSED(core_id);
		worker_gc->limits(response);
	}

	auto dregress = DregressLimitsStats();

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
		GCC_BUG_UNUSED(core_id);

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
					GCC_BUG_UNUSED(filter_real_port);

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
		GCC_BUG_UNUSED(core_id);

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
		GCC_BUG_UNUSED(core_id);

		auto current_guard = worker_gc->balancer_real_connections.current_lock_guard();
		response[worker_gc->socket_id] = worker_gc->balancer_real_connections.current();
	}

	return response;
}

eResult cControlPlane::unrdup_vip_to_balancers(const common::idp::unrdup_vip_to_balancers::request& request)
{
	return vip_to_balancers.apply([&](auto& vtb) {
		uint32_t balancer_id = std::get<0>(request);

		if (vtb.size() <= balancer_id)
		{
			vtb.resize(balancer_id + 1);
		}

		vtb[balancer_id] = std::get<1>(request);
		return eResult::success;
	});
}

eResult cControlPlane::update_vip_vport_proto(const common::idp::update_vip_vport_proto::request& request)
{
	return vip_vport_proto.apply([&](auto& vvp) {
		uint32_t balancer_id = std::get<0>(request);

		if (vvp.size() <= balancer_id)
		{
			vvp.resize(balancer_id + 1);
		}

		vvp[balancer_id] = std::get<1>(request);
		return eResult::success;
	});
}

common::idp::version::response cControlPlane::version()
{
	return {version_major(),
	        version_minor(),
	        version_revision(),
	        version_hash(),
	        version_custom()};
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
			GCC_BUG_UNUSED(socket_id);

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
			GCC_BUG_UNUSED(socket_id);

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
		GCC_BUG_UNUSED(core_id);
		worker_gc->balancer_state_clear();
	}

	return eResult::success;
}

common::idp::nat64stateful_state::response cControlPlane::nat64stateful_state(const common::idp::nat64stateful_state::request& request)
{
	common::idp::nat64stateful_state::response response;

	for (auto& [core_id, worker_gc] : dataPlane->worker_gcs)
	{
		GCC_BUG_UNUSED(core_id);
		worker_gc->nat64stateful_state(request, response);
	}

	return response;
}

void cControlPlane::switchBase()
{
	YADECAP_MEMORY_BARRIER_COMPILE;

	for (cWorker* worker : dataPlane->workers_vector)
	{
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

	for (cWorker* worker : dataPlane->workers_vector)
	{
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

	for (const cWorker* worker : dataPlane->workers_vector)
	{
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
		GCC_BUG_UNUSED(core_id);

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
