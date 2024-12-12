#include "telegraf.h"
#include "controlplane.h"

using common::int64;
using controlplane::module::telegraf;

[[maybe_unused]] static inline double perSecond(const int64_t& valueDiff, const uint64_t& timeDiff)
{
	if (timeDiff == 0)
	{
		return 0;
	}

	return ((double)1000000 * valueDiff) / ((double)timeDiff);
}

static inline double calcUsage(const std::array<uint64_t, CONFIG_YADECAP_MBUFS_BURST_SIZE + 1>& currBursts,
                               const std::array<uint64_t, CONFIG_YADECAP_MBUFS_BURST_SIZE + 1>& prevBursts)
{
	if (currBursts.size() <= 1 ||
	    currBursts.size() != prevBursts.size())
	{
		return 0;
	}

	uint64_t idleDiff = currBursts[0] - prevBursts[0];

	uint64_t currTotal = 0;
	uint64_t prevTotal = 0;
	for (unsigned int i = 1;
	     i < currBursts.size();
	     i++)
	{
		currTotal += currBursts[i];
		prevTotal += prevBursts[i];
	}

	uint64_t totalDiff = currTotal - prevTotal;
	if (totalDiff != 0)
	{
		double usage = ((double)(100) * idleDiff) / ((double)(currBursts.size() - 1) * totalDiff / (double)4 + idleDiff);
		usage = (double)100 - usage;
		return usage;
	}

	return 0;
}

telegraf_t::telegraf_t() :
        flagFirst(true)
{
}

eResult telegraf_t::init()
{
	controlPlane->register_command(common::icp::requestType::telegraf_unsafe, [this]() {
		return telegraf_unsafe();
	});

	controlPlane->register_command(common::icp::requestType::telegraf_dregress, [this]() {
		return telegraf_dregress();
	});

	controlPlane->register_command(common::icp::requestType::telegraf_dregress_traffic, [this]() {
		return telegraf_dregress_traffic();
	});

	controlPlane->register_command(common::icp::requestType::telegraf_balancer_service, [this]() {
		return telegraf_balancer_service();
	});

	controlPlane->register_command(common::icp::requestType::telegraf_other, [this]() {
		return telegraf_other();
	});

	controlPlane->register_command(common::icp::requestType::telegraf_mappings, [this]() {
		return telegraf_mappings();
	});

	return eResult::success;
}

void telegraf_t::reload_before()
{
	generations.next_lock();
}

void telegraf_t::reload(const controlplane::base_t& base_prev,
                        const controlplane::base_t& base_next,
                        [[maybe_unused]] common::idp::updateGlobalBase::request& globalbase)
{
	generations.next().update(base_prev, base_next);
}

void telegraf_t::reload_after()
{
	generations.switch_generation();
	generations.next_unlock();
}

common::icp::telegraf_unsafe::response telegraf_t::telegraf_unsafe()
{
	auto& dataPlane = dataPlaneUnsafe;

	const auto workersStats = dataPlane.getWorkerStats({});
	const auto workerGCsStats = dataPlane.get_worker_gc_stats();
	const auto slowWorkerStats = dataPlane.getSlowWorkerStats();
	const auto fragmentationStats = dataPlane.getFragmentationStats();
	const auto fwstateStats = dataPlane.getFWStateStats();
	const auto tun64Stats = controlPlane->tun64.tunnel_counters.get_counters();

	common::icp::telegraf_unsafe::response response;
	auto& [responseWorkers, responseWorkerGCs, responseSlowWorker, responseFragmentation, responseFWState, responseTun64, response_nat64stateful, responseControlplaneStats] = response;

	for (const auto& [coreId, stats] : workersStats)
	{
		std::map<std::string, common::worker::stats::port> portsStats;
		for (const auto& [portId, portStats] : std::get<2>(stats))
		{
			std::string physicalPortName;
			if (controlPlane->getPhysicalPortName(portId, physicalPortName) != eResult::success)
			{
				YANET_LOG_ERROR("unknown portId: '%u'\n", portId);
				continue;
			}

			portsStats[physicalPortName] = portStats;
		}

		responseWorkers[coreId] = {std::get<0>(stats),
		                           std::get<1>(stats),
		                           portsStats};
	}

	{
		auto current_guard = controlPlane->tun64.generations_config.current_lock_guard();
		for (const auto& [name, tunnel] : controlPlane->tun64.generations_config.current().config_tunnels)
		{
			const auto& [encap_packets, encap_bytes, encap_dropped, decap_packets, decap_bytes, decap_unknown] = tun64Stats.at(name);

			GCC_BUG_UNUSED(tunnel);
			responseTun64[name] = {encap_packets, encap_bytes, encap_dropped, decap_packets, decap_bytes, decap_unknown};
		}
	}

	response_nat64stateful = controlPlane->nat64stateful.module_counters.get_counters();

	{
		responseControlplaneStats["load_config_done"] = controlPlane->loadConfig_done;
		responseControlplaneStats["load_config_failed"] = controlPlane->loadConfig_failed;
		responseControlplaneStats["load_config_status"] = controlPlane->loadConfigStatus ? 1 : 0;
	}

	responseWorkerGCs = workerGCsStats;
	responseSlowWorker = slowWorkerStats;
	responseFragmentation = fragmentationStats;
	responseFWState = fwstateStats;

	return response;
}

common::icp::telegraf_mappings::response telegraf_t::telegraf_mappings()
{
	common::icp::telegraf_mappings::response response;
	const auto counters = controlPlane->tun64.mappings_counters.get_counters();

	{
		auto current_guard = controlPlane->tun64.generations_config.current_lock_guard();
		for (const auto& [name, tunnel] : controlPlane->tun64.generations_config.current().config_tunnels)
		{
			for (const auto& [ipv4_address, mapping] : tunnel.mappings)
			{
				const auto& [ipv6_address, location] = mapping;
				const auto& [encap_packets, encap_bytes, decap_packets, decap_bytes] = counters.at({name, ipv4_address});
				const common::tun64mapping::stats_t stats = {encap_packets, encap_bytes, decap_packets, decap_bytes};

				GCC_BUG_UNUSED(location);
				response.emplace_back(name, ipv4_address, ipv6_address, stats);
			}
		}
	}

	return response;
}

common::icp::telegraf_dregress::response telegraf_t::telegraf_dregress()
{
	auto& dataPlane = dataPlaneDregress;

	const auto dregressCounters = dataPlane.get_dregress_counters();

	generations.current_lock();
	std::map<community_t, std::string> communities = *generations.current().get_communities();
	generations.current_unlock();

	common::icp::telegraf_dregress::response response;

	response = {dregressCounters,
	            communities};

	return response;
}

common::icp::telegraf_dregress_traffic::response telegraf_t::telegraf_dregress_traffic()
{
	common::icp::telegraf_dregress_traffic::response response;
	auto& [response_peer, response_peer_as] = response;

	/// @todo: OPT
	generations.current_lock();
	std::map<uint32_t, std::string> peers = *generations.current().get_peers();
	generations.current_unlock();

	{
		const auto counters = controlPlane->route.tunnel_counter.get_counters();
		for (const auto& [key, value] : counters)
		{
			const auto& [is_ipv4, peer_id, nexthop, origin_as] = key;
			const auto& [packets, bytes] = value;
			GCC_BUG_UNUSED(origin_as);

			auto it = dregress_traffic_counters_prev.find(key);
			if (it != dregress_traffic_counters_prev.end())
			{
				const auto& [packets_prev, bytes_prev] = it->second;

				if (packets > packets_prev)
				{
					auto& [peer_packets, peer_bytes] = route_tunnel_peer_counters[{is_ipv4, peer_id, nexthop}];
					peer_packets += packets - packets_prev;
					peer_bytes += bytes - bytes_prev;

					if (!(peer_id == 0 &&
					      origin_as == 0))
					{
						/// not fallback

						response_peer_as.emplace_back(is_ipv4,
						                              peer_id,
						                              nexthop.toString(),
						                              origin_as,
						                              packets - packets_prev,
						                              bytes - bytes_prev);
					}
				}
			}
		}

		for (const auto& [key, value] : route_tunnel_peer_counters)
		{
			const auto& [is_ipv4, peer_id, nexthop] = key;
			const auto& [packets, bytes] = value;

			response_peer.emplace_back(is_ipv4, peer_id, nexthop.toString(), packets, bytes);
		}

		dregress_traffic_counters_prev = counters;
	}

	return response;
}

common::icp::telegraf_balancer_service::response telegraf_t::telegraf_balancer_service()
{
	common::icp::telegraf_balancer_service::response response;

	controlPlane->balancer.generations_config.current_lock();
	std::map<std::string, balancer_id_t> name_id = controlPlane->balancer.generations_config.current().name_id;
	;
	controlPlane->balancer.generations_config.current_unlock();

	const auto counters = controlPlane->balancer.service_counters.get_counters();

	for (const auto& [key, value] : counters)
	{
		const auto& [module_name, service_key] = key;
		const auto& [virtual_ip, proto, virtual_port] = service_key;
		const auto& [packets, bytes, real_disabled_packets, real_disabled_bytes] = value;

		auto it = name_id.find(module_name);
		if (it != name_id.end())
		{
			response[{it->second, module_name}].emplace_back(virtual_ip,
			                                                 proto,
			                                                 virtual_port,
			                                                 0,
			                                                 packets,
			                                                 bytes,
			                                                 real_disabled_packets,
			                                                 real_disabled_bytes);
		}
	}

	return response;
}

common::icp::telegraf_other::response telegraf_t::telegraf_other()
{
	auto& dataPlane = dataPlaneOther;

	std::map<tCoreId, std::array<uint64_t, CONFIG_YADECAP_MBUFS_BURST_SIZE + 1>> currWorkers;
	const common::sdp::DataPlaneInSharedMemory* sdp_data = controlPlane->getSdpData();
	for (const auto& [coreId, worker_info] : sdp_data->workers)
	{
		std::array<uint64_t, CONFIG_YADECAP_MBUFS_BURST_SIZE + 1> bursts;
		auto* worker_bursts =
		        utils::ShiftBuffer<uint64_t*>(worker_info.buffer, sdp_data->metadata_worker.start_bursts);
		memcpy(&bursts[0], worker_bursts, sizeof(uint64_t) * (CONFIG_YADECAP_MBUFS_BURST_SIZE + 1));
		currWorkers[coreId] = bursts;
	}

	const auto portsStatsExtended = dataPlane.get_ports_stats_extended();

	//

	common::icp::telegraf_other::response response;
	auto& [response_flagFirst, response_workers, response_ports] = response;

	response_flagFirst = flagFirst;

	if (!flagFirst)
	{
		for (const auto& [coreId, workerStats] : currWorkers)
		{
			response_workers[coreId] = {calcUsage(workerStats, prevWorkers[coreId])};
		}
	}
	else
	{
		flagFirst = false;
	}

	for (const auto& [portId, stats] : portsStatsExtended)
	{
		std::string physicalPortName;
		if (controlPlane->getPhysicalPortName(portId, physicalPortName) != eResult::success)
		{
			YANET_LOG_ERROR("unknown portId: '%u'\n", portId);
			continue;
		}

		response_ports[physicalPortName] = stats;
	}

	//

	prevWorkers = currWorkers;

	return response;
}
