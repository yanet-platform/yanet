#include <netinet/in.h>

#include <rte_ethdev.h>
#include <rte_mempool.h>

#include "dataplane.h"
#include "report.h"
#include "worker.h"

namespace
{

template<typename hashtable_chain_T>
nlohmann::json convertHashtable(const hashtable_chain_T& hashtable)
{
	nlohmann::json json;

	const auto& stats = hashtable.getStats();

	json["extendedChunksCount"] = stats.extendedChunksCount;
	json["longestChain"] = stats.longestChain;
	json["pairs"] = stats.pairs;
	json["insertFailed"] = stats.insertFailed;

	return json;
}

template<typename hashtable_mod_T,
         typename stats_T>
nlohmann::json convertHashtable(const hashtable_mod_T& hashtable, const stats_T& stats_generation)
{
	nlohmann::json json;

	{
		auto current_guard = stats_generation.current_lock_guard();

		json["keys"] = stats_generation.current().valid_keys;
		json["keys_size"] = hashtable.pairs_size;
		for (unsigned int i = 0;
		     i < hashtable.keys_in_chunk_size + 1;
		     i++)
		{
			json["keys_in_chunks[" + std::to_string(i) + "]"] = stats_generation.current().keys_in_chunks[i];
		}
	}

	return json;
}

} // namespace

cReport::cReport(cDataPlane* dataPlane) :
        dataPlane(dataPlane)
{
}

nlohmann::json cReport::getReport()
{
	nlohmann::json jsonReport;

	for (const auto& iter : dataPlane->workers)
	{
		const cWorker* worker = iter.second;
		jsonReport["workers"].emplace_back(convertWorker(worker));
	}

	for (const auto& [core_id, worker] : dataPlane->worker_gcs)
	{
		(void)core_id;
		jsonReport["worker_gcs"].emplace_back(convertWorkerGC(worker));
	}

	for (const auto& iter : dataPlane->ports)
	{
		const tPortId& portId = iter.first;
		jsonReport["ports"].emplace_back(convertPort(portId));
	}

	for (const auto& iter : dataPlane->globalBaseAtomics)
	{
		jsonReport["globalBaseAtomics"].emplace_back(convertGlobalBaseAtomic(iter.second));
	}

	{
		std::lock_guard<std::mutex> guard(dataPlane->currentGlobalBaseId_mutex);
		for (const auto& iter : dataPlane->globalBases)
		{
			jsonReport["globalBases"].emplace_back(convertGlobalBase(iter.second[dataPlane->currentGlobalBaseId]));
		}
	}

	jsonReport["controlPlane"] = convertControlPlane(dataPlane->controlPlane.get());
	jsonReport["bus"] = convertBus(&dataPlane->bus);

	dataPlane->neighbor.report(jsonReport);
	dataPlane->memory_manager.report(jsonReport);

	return jsonReport;
}

std::string pointerToHex(const void* pointer)
{
	char buffer[128];
	snprintf(buffer, 128, "%p", pointer);
	return buffer;
}

[[maybe_unused]] static inline std::string convertIPv6AddressToString(const in6_addr& ipv6Address) ///< @todo: to common.h
{
	char buffer[512];
	snprintf(buffer, 512, "%2.2X%2.2X:%2.2X%2.2X:%2.2X%2.2X:%2.2X%2.2X:%2.2X%2.2X:%2.2X%2.2X:%2.2X%2.2X:%2.2X%2.2X", ipv6Address.__in6_u.__u6_addr8[0], ipv6Address.__in6_u.__u6_addr8[1], ipv6Address.__in6_u.__u6_addr8[2], ipv6Address.__in6_u.__u6_addr8[3], ipv6Address.__in6_u.__u6_addr8[4], ipv6Address.__in6_u.__u6_addr8[5], ipv6Address.__in6_u.__u6_addr8[6], ipv6Address.__in6_u.__u6_addr8[7], ipv6Address.__in6_u.__u6_addr8[8], ipv6Address.__in6_u.__u6_addr8[9], ipv6Address.__in6_u.__u6_addr8[10], ipv6Address.__in6_u.__u6_addr8[11], ipv6Address.__in6_u.__u6_addr8[12], ipv6Address.__in6_u.__u6_addr8[13], ipv6Address.__in6_u.__u6_addr8[14], ipv6Address.__in6_u.__u6_addr8[15]);
	return buffer;
}

static inline std::string convertEtherAddressToString(const rte_ether_addr& etherAddress) ///< @todo: to common.h
{
	char buffer[512];
	snprintf(buffer, 512, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X", etherAddress.addr_bytes[0], etherAddress.addr_bytes[1], etherAddress.addr_bytes[2], etherAddress.addr_bytes[3], etherAddress.addr_bytes[4], etherAddress.addr_bytes[5]);
	return buffer;
}

nlohmann::json cReport::convertWorker(const cWorker* worker)
{
	nlohmann::json json;

	json["pointer"] = pointerToHex(worker);
	json["coreId"] = worker->coreId;
	json["socketId"] = worker->socketId;
	json["mempool"] = convertMempool(worker->mempool);
	json["iteration"] = worker->iteration;

	json["stats"]["brokenPackets"] = worker->stats.brokenPackets;
	json["stats"]["dropPackets"] = worker->stats.dropPackets;
	json["stats"]["ring_highPriority_drops"] = worker->stats.ring_highPriority_drops;
	json["stats"]["ring_normalPriority_drops"] = worker->stats.ring_normalPriority_drops;
	json["stats"]["ring_lowPriority_drops"] = worker->stats.ring_lowPriority_drops;
	json["stats"]["decap_packets"] = worker->stats.decap_packets;
	json["stats"]["decap_fragments"] = worker->stats.decap_fragments;
	json["stats"]["decap_unknownExtensions"] = worker->stats.decap_unknownExtensions;
	json["stats"]["interface_lookupMisses"] = worker->stats.interface_lookupMisses;
	json["stats"]["interface_hopLimits"] = worker->stats.interface_hopLimits;
	json["stats"]["interface_neighbor_invalid"] = worker->stats.interface_neighbor_invalid;
	json["stats"]["nat64stateless_ingressPackets"] = worker->stats.nat64stateless_ingressPackets;
	json["stats"]["nat64stateless_ingressFragments"] = worker->stats.nat64stateless_ingressFragments;
	json["stats"]["nat64stateless_ingressUnknownICMP"] = worker->stats.nat64stateless_ingressUnknownICMP;
	json["stats"]["nat64stateless_egressPackets"] = worker->stats.nat64stateless_egressPackets;
	json["stats"]["nat64stateless_egressFragments"] = worker->stats.nat64stateless_egressFragments;
	json["stats"]["nat64stateless_egressUnknownICMP"] = worker->stats.nat64stateless_egressUnknownICMP;
	json["stats"]["balancer_invalid_reals_count"] = worker->stats.balancer_invalid_reals_count;
	json["stats"]["fwsync_multicast_egress_drops"] = worker->stats.fwsync_multicast_egress_drops;
	json["stats"]["fwsync_multicast_egress_packets"] = worker->stats.fwsync_multicast_egress_packets;
	json["stats"]["fwsync_unicast_egress_drops"] = worker->stats.fwsync_unicast_egress_drops;
	json["stats"]["fwsync_unicast_egress_packets"] = worker->stats.fwsync_unicast_egress_packets;
	json["stats"]["fwsync_multicast_egress_imm_packets"] = worker->stats.fwsync_multicast_egress_imm_packets;
	json["stats"]["fwsync_no_config_drops"] = worker->stats.fwsync_no_config_drops;
	json["stats"]["acl_ingress_dropPackets"] = worker->stats.acl_ingress_dropPackets;
	json["stats"]["acl_egress_dropPackets"] = worker->stats.acl_egress_dropPackets;
	json["stats"]["repeat_ttl"] = worker->stats.repeat_ttl;
	json["stats"]["leakedMbufs"] = worker->stats.leakedMbufs;
	json["stats"]["samples_drops"] = worker->sampler.get_drops();
	json["stats"]["logs_packets"] = worker->stats.logs_packets;
	json["stats"]["logs_drops"] = worker->stats.logs_drops;

	for (tPortId portId = 0;
	     portId < dataPlane->ports.size();
	     portId++)
	{
		nlohmann::json jsonPort;

		jsonPort["portId"] = portId;
		jsonPort["physicalPort_egress_drops"] = worker->statsPorts[portId].physicalPort_egress_drops;
		jsonPort["controlPlane_drops"] = worker->statsPorts[portId].controlPlane_drops;

		json["statsPorts"].emplace_back(jsonPort);
	}

	for (unsigned int burst_i = 0;
	     burst_i < CONFIG_YADECAP_MBUFS_BURST_SIZE + 1;
	     burst_i++)
	{
		json["bursts"].emplace_back(worker->bursts[burst_i]);
	}

	/**
	for (tCounterId counterId = 0;
	     counterId < CONFIG_YADECAP_COUNTERS_SIZE;
	     counterId++)
	{
	        json["counters"].emplace_back(worker->counters[counterId]);
	}
	*/

	/// permanently base
	json["permanentlyBase"]["globalBaseAtomic"]["pointer"] = pointerToHex(worker->basePermanently.globalBaseAtomic);
	json["permanentlyBase"]["workerPortsCount"] = worker->basePermanently.workerPortsCount;
	for (unsigned int worker_port_i = 0;
	     worker_port_i < worker->basePermanently.workerPortsCount;
	     worker_port_i++)
	{
		nlohmann::json jsonPort;

		jsonPort["worker_port_i"] = worker_port_i;
		jsonPort["inPortId"] = worker->basePermanently.workerPorts[worker_port_i].inPortId;
		jsonPort["inQueueId"] = worker->basePermanently.workerPorts[worker_port_i].inQueueId;

		json["permanentlyBase"]["workerPorts"].emplace_back(jsonPort);
	}
	json["permanentlyBase"]["outQueueId"] = worker->basePermanently.outQueueId;

	/// base
	const auto& base = worker->bases[worker->currentBaseId];
	json["base"]["globalBase"]["pointer"] = pointerToHex(base.globalBase);

	{
		using common::globalBase::static_counter_type; ///< C++20: using enum

		json["static_counters"]["balancer_state_insert_failed"] = worker->counters[(tCounterId)static_counter_type::balancer_state_insert_failed];
		json["static_counters"]["balancer_state_insert_done"] = worker->counters[(tCounterId)static_counter_type::balancer_state_insert_done];

		json["static_counters"]["balancer_icmp_generated_echo_reply_ipv4"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_generated_echo_reply_ipv4];
		json["static_counters"]["balancer_icmp_generated_echo_reply_ipv6"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_generated_echo_reply_ipv6];
		json["static_counters"]["balancer_icmp_sent_to_real"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_sent_to_real];
		json["static_counters"]["balancer_icmp_drop_icmpv4_payload_too_short_ip"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_drop_icmpv4_payload_too_short_ip];
		json["static_counters"]["balancer_icmp_drop_icmpv4_payload_too_short_port"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_drop_icmpv4_payload_too_short_port];
		json["static_counters"]["balancer_icmp_drop_icmpv6_payload_too_short_ip"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_drop_icmpv6_payload_too_short_ip];
		json["static_counters"]["balancer_icmp_drop_icmpv6_payload_too_short_port"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_drop_icmpv6_payload_too_short_port];
		json["static_counters"]["balancer_icmp_unmatching_src_from_original_ipv4"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_unmatching_src_from_original_ipv4];
		json["static_counters"]["balancer_icmp_unmatching_src_from_original_ipv6"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_unmatching_src_from_original_ipv6];
		json["static_counters"]["balancer_icmp_drop_real_disabled"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_drop_real_disabled];
		json["static_counters"]["balancer_icmp_no_balancer_src_ipv4"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_no_balancer_src_ipv4];
		json["static_counters"]["balancer_icmp_no_balancer_src_ipv6"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_no_balancer_src_ipv6];
		json["static_counters"]["balancer_icmp_drop_already_cloned"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_drop_already_cloned];
		json["static_counters"]["balancer_icmp_out_rate_limit_reached"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_out_rate_limit_reached];
		json["static_counters"]["balancer_icmp_drop_no_unrdup_table_for_balancer_id"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_drop_no_unrdup_table_for_balancer_id];
		json["static_counters"]["balancer_icmp_drop_unrdup_vip_not_found"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_drop_unrdup_vip_not_found];
		json["static_counters"]["balancer_icmp_drop_no_vip_vport_proto_table_for_balancer_id"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_drop_no_vip_vport_proto_table_for_balancer_id];
		json["static_counters"]["balancer_icmp_drop_unexpected_transport_protocol"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_drop_unexpected_transport_protocol];
		json["static_counters"]["balancer_icmp_drop_unknown_service"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_drop_unknown_service];
		json["static_counters"]["balancer_icmp_failed_to_clone"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_failed_to_clone];
		json["static_counters"]["balancer_icmp_clone_forwarded"] = worker->counters[(tCounterId)static_counter_type::balancer_icmp_clone_forwarded];
		json["static_counters"]["balancer_fragment_drops"] = worker->counters[(tCounterId)static_counter_type::balancer_fragment_drops];

		json["static_counters"]["slow_worker_normal_priority_rate_limit_exceeded"] = worker->counters[(tCounterId)static_counter_type::slow_worker_normal_priority_rate_limit_exceeded];
	}

	return json;
}

nlohmann::json cReport::convertWorkerGC(const worker_gc_t* worker)
{
	nlohmann::json json;

	json["mempool"] = convertMempool(worker->mempool);

	json["pointer"] = pointerToHex(worker);
	json["coreId"] = worker->core_id;
	json["socketId"] = worker->socket_id;
	json["iteration"] = worker->iteration;
	json["samples"] = worker->samples.size();

	json["stats"]["broken_packets"] = worker->stats.broken_packets;
	json["stats"]["drop_packets"] = worker->stats.drop_packets;
	json["stats"]["drop_samples"] = worker->stats.drop_samples;
	json["stats"]["fwsync_multicast_egress_packets"] = worker->stats.fwsync_multicast_egress_packets;
	json["stats"]["fwsync_multicast_egress_drops"] = worker->stats.fwsync_multicast_egress_drops;
	json["stats"]["fwsync_unicast_egress_packets"] = worker->stats.fwsync_unicast_egress_packets;
	json["stats"]["fwsync_unicast_egress_drops"] = worker->stats.fwsync_unicast_egress_drops;
	json["stats"]["balancer_state_insert_failed"] = worker->stats.balancer_state_insert_failed;
	json["stats"]["balancer_state_insert_done"] = worker->stats.balancer_state_insert_done;

	/// permanently base
	json["permanentlyBase"]["globalBaseAtomic"]["pointer"] = pointerToHex(worker->base_permanently.globalBaseAtomic);
	json["permanentlyBase"]["workerPortsCount"] = worker->base_permanently.workerPortsCount;
	for (unsigned int worker_port_i = 0;
	     worker_port_i < worker->base_permanently.workerPortsCount;
	     worker_port_i++)
	{
		nlohmann::json jsonPort;

		jsonPort["worker_port_i"] = worker_port_i;
		jsonPort["inPortId"] = worker->base_permanently.workerPorts[worker_port_i].inPortId;
		jsonPort["inQueueId"] = worker->base_permanently.workerPorts[worker_port_i].inQueueId;

		json["permanentlyBase"]["workerPorts"].emplace_back(jsonPort);
	}
	json["permanentlyBase"]["outQueueId"] = worker->base_permanently.outQueueId;

	/// base
	const auto& base = worker->bases[worker->current_base_id];
	json["base"]["globalBase"]["pointer"] = pointerToHex(base.globalBase);

	worker->base_permanently.globalBaseAtomic->updater.balancer_state.report(json["balancer_state"]);

	return json;
}

nlohmann::json cReport::convertMempool(const rte_mempool* mempool)
{
	nlohmann::json json;

	json["pointer"] = pointerToHex(mempool);
	json["avail_count"] = rte_mempool_avail_count(mempool);
	json["in_use_count"] = rte_mempool_in_use_count(mempool);

	return json;
}

nlohmann::json cReport::convertPort(const tPortId& portId)
{
	nlohmann::json json;

	json["portId"] = portId;
	json["interfaceName"] = std::get<0>(dataPlane->ports[portId]);
	json["socketId"] = rte_eth_dev_socket_id(portId);

	rte_eth_link link;
	{
		std::lock_guard<std::mutex> guard(dataPlane->dpdk_mutex);
		rte_eth_link_get_nowait(portId, &link);
	}
	json["link"]["speed"] = link.link_speed;
	json["link"]["duplex"] = (link.link_duplex == 0 ? "half" : "full");
	json["link"]["autoneg"] = (link.link_autoneg == 0 ? "autoneg" : "fixed");
	json["link"]["status"] = (link.link_status == 0 ? "down" : "up");

	rte_eth_stats stats;
	int rc = 1;
	{
		std::lock_guard<std::mutex> guard(dataPlane->dpdk_mutex);
		rc = rte_eth_stats_get(portId, &stats);
	}
	if (!rc)
	{
		json["stats"]["ipackets"] = stats.ipackets;
		json["stats"]["opackets"] = stats.opackets;
		json["stats"]["ibytes"] = stats.ibytes;
		json["stats"]["obytes"] = stats.obytes;
		json["stats"]["imissed"] = stats.imissed;
		json["stats"]["ierrors"] = stats.ierrors;
		json["stats"]["oerrors"] = stats.oerrors;
		json["stats"]["rx_nombuf"] = stats.rx_nombuf;

		/// @todo: per queue stats
	}

	auto portStats = dataPlane->getPortStats(portId);
	for (const auto& [key, value] : portStats)
	{
		json["portStats"][key] = value.value;
	}

	return json;
}

nlohmann::json cReport::convertControlPlane(const cControlPlane* controlPlane)
{
	nlohmann::json json;

	json["mempool"] = convertMempool(controlPlane->mempool);

	for (const auto& iter : controlPlane->kernel_interfaces)
	{
		nlohmann::json jsonKni;

		const tPortId& portId = iter.first;
		const std::string& name = std::get<0>(iter.second);
		const cControlPlane::sKniStats& stats = std::get<2>(iter.second);

		jsonKni["portId"] = portId;
		jsonKni["interfaceName"] = name;
		jsonKni["stats"]["ipackets"] = stats.ipackets;
		jsonKni["stats"]["ibytes"] = stats.ibytes;
		jsonKni["stats"]["idropped"] = stats.idropped;
		jsonKni["stats"]["opackets"] = stats.opackets;
		jsonKni["stats"]["obytes"] = stats.obytes;
		jsonKni["stats"]["odropped"] = stats.odropped;

		json["knis"].emplace_back(jsonKni);
	}

	json["repeat_packets"] = controlPlane->stats.repeat_packets;
	json["tofarm_packets"] = controlPlane->stats.tofarm_packets;
	json["farm_packets"] = controlPlane->stats.farm_packets;
	json["fwsync_multicast_ingress_packets"] = controlPlane->stats.fwsync_multicast_ingress_packets;
	json["slowworker_drops"] = controlPlane->stats.slowworker_drops;
	json["slowworker_packets"] = controlPlane->stats.slowworker_packets;
	json["mempool_is_empty"] = controlPlane->stats.mempool_is_empty;

	json["dregress"]["bad_decap_transport"] = controlPlane->dregress.stats.bad_decap_transport;
	json["dregress"]["fragment"] = controlPlane->dregress.stats.fragment;
	json["dregress"]["bad_transport"] = controlPlane->dregress.stats.bad_transport;
	json["dregress"]["lookup_miss"] = controlPlane->dregress.stats.lookup_miss;
	json["dregress"]["local"] = controlPlane->dregress.stats.local;
	json["dregress"]["tcp_syn"] = controlPlane->dregress.stats.tcp_syn;
	json["dregress"]["tcp_unknown_option"] = controlPlane->dregress.stats.tcp_unknown_option;
	json["dregress"]["tcp_no_option"] = controlPlane->dregress.stats.tcp_no_option;
	json["dregress"]["tcp_insert_sessions"] = controlPlane->dregress.stats.tcp_insert_sessions;
	json["dregress"]["tcp_close_sessions"] = controlPlane->dregress.stats.tcp_close_sessions;
	json["dregress"]["tcp_retransmission"] = controlPlane->dregress.stats.tcp_retransmission;
	json["dregress"]["tcp_ok"] = controlPlane->dregress.stats.tcp_ok;
	json["dregress"]["tcp_timeout_sessions"] = controlPlane->dregress.stats.tcp_timeout_sessions;
	json["dregress"]["tcp_unknown_sessions"] = controlPlane->dregress.stats.tcp_unknown_sessions;
	json["dregress"]["connections"] = convertHashtable(*controlPlane->dregress.connections);

	return json;
}

nlohmann::json cReport::convertBus(const cBus* bus)
{
	nlohmann::json json;

	for (uint32_t request_i = 0;
	     request_i < (uint32_t)common::idp::requestType::size;
	     request_i++)
	{
		nlohmann::json jsonStat;

		jsonStat["type"] = request_i;
		jsonStat["count"] = bus->stats.requests[request_i];

		json["stats"]["request"].emplace_back(jsonStat);
	}

	for (uint32_t error_i = 0;
	     error_i < (uint32_t)common::idp::errorType::size;
	     error_i++)
	{
		nlohmann::json jsonStat;

		jsonStat["type"] = error_i;
		jsonStat["count"] = bus->stats.errors[error_i];

		json["stats"]["error"].emplace_back(jsonStat);
	}

	return json;
}

nlohmann::json cReport::convertGlobalBaseAtomic(const dataplane::globalBase::atomic* globalBaseAtomic)
{
	nlohmann::json json;

	json["pointer"] = pointerToHex(globalBaseAtomic);
	json["socketId"] = globalBaseAtomic->socketId;
	json["currentTime"] = globalBaseAtomic->currentTime;

	globalBaseAtomic->updater.fw4_state.report(json["fw4_state"]);
	globalBaseAtomic->updater.fw6_state.report(json["fw6_state"]);
	globalBaseAtomic->updater.nat64stateful_lan_state.report(json["nat64stateful_lan_state"]);
	globalBaseAtomic->updater.nat64stateful_wan_state.report(json["nat64stateful_wan_state"]);

	return json;
}

/// @todo: move
static inline nlohmann::json convertFlow(const common::globalBase::tFlow& flow)
{
	nlohmann::json result;

	if (flow.type == common::globalBase::eFlowType::drop)
	{
		result["type"] = "drop";
	}
	else if (flow.type == common::globalBase::eFlowType::acl_ingress)
	{
		result["type"] = "acl_ingress";
		result["id"] = flow.data.aclId;
	}
	else if (flow.type == common::globalBase::eFlowType::tun64_ipv4_checked)
	{
		result["type"] = "tun64_ipv4_checked";
		result["id"] = flow.data.tun64Id;
	}
	else if (flow.type == common::globalBase::eFlowType::tun64_ipv6_checked)
	{
		result["type"] = "tun64_ipv6_checked";
		result["id"] = flow.data.tun64Id;
	}
	else if (flow.type == common::globalBase::eFlowType::decap_checked)
	{
		result["type"] = "decap_checked";
		result["id"] = flow.data.decapId;
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateful_lan)
	{
		result["type"] = "nat64stateful_lan";
		result["id"] = flow.data.nat64stateful_id;
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateful_wan)
	{
		result["type"] = "nat64stateful_wan";
		result["id"] = flow.data.nat64stateful_id;
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_ingress_checked)
	{
		result["type"] = "nat64stateless_ingress_checked";
		result["id"] = flow.data.nat64stateless.id;
		result["translationId"] = flow.data.nat64stateless.translationId;
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_ingress_icmp)
	{
		result["type"] = "nat64stateless_ingress_icmp";
		result["id"] = flow.data.nat64stateless.id;
		result["translationId"] = flow.data.nat64stateless.translationId;
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_ingress_fragmentation)
	{
		result["type"] = "nat64stateless_ingress_fragmentation";
		result["id"] = flow.data.nat64stateless.id;
		result["translationId"] = flow.data.nat64stateless.translationId;
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_egress_checked)
	{
		result["type"] = "nat64stateless_egress_checked";
		result["id"] = flow.data.nat64stateless.id;
		result["translationId"] = flow.data.nat64stateless.translationId;
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_egress_icmp)
	{
		result["type"] = "nat64stateless_egress_icmp";
		result["id"] = flow.data.nat64stateless.id;
		result["translationId"] = flow.data.nat64stateless.translationId;
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_egress_fragmentation)
	{
		result["type"] = "nat64stateless_egress_fragmentation";
		result["id"] = flow.data.nat64stateless.id;
		result["translationId"] = flow.data.nat64stateless.translationId;
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_egress_farm)
	{
		result["type"] = "nat64stateless_egress_farm";
		result["id"] = flow.data.nat64stateless.id;
	}
	else if (flow.type == common::globalBase::eFlowType::route)
	{
		result["type"] = "route";
		result["id"] = flow.data.routeId;
	}
	else if (flow.type == common::globalBase::eFlowType::route_tunnel)
	{
		result["type"] = "route_tunnel";
		result["id"] = flow.data.routeId;
	}
	else if (flow.type == common::globalBase::eFlowType::acl_egress)
	{
		result["type"] = "acl_egress";
		result["id"] = flow.data.aclId;
	}
	else if (flow.type == common::globalBase::eFlowType::controlPlane)
	{
		result["type"] = "controlPlane";
	}
	else if (flow.type == common::globalBase::eFlowType::logicalPort_egress)
	{
		result["type"] = "logicalPort_egress";
		result["id"] = flow.data.logicalPortId;
	}
	else
	{
		result["type"] = "error";
	}

	return result;
}

nlohmann::json cReport::convertGlobalBase(const dataplane::globalBase::generation* globalBase)
{
	nlohmann::json json;

	json["pointer"] = pointerToHex(globalBase);
	json["socketId"] = globalBase->socketId;

	for (unsigned int logicalPortId = 0;
	     logicalPortId < CONFIG_YADECAP_LOGICALPORTS_SIZE;
	     logicalPortId++)
	{
		const auto& logicalPort = globalBase->logicalPorts[logicalPortId];

		if (logicalPort.flow.type == common::globalBase::eFlowType::controlPlane)
		{
			continue;
		}

		nlohmann::json jsonLogicalPort;

		jsonLogicalPort["logicalPortId"] = logicalPortId;
		jsonLogicalPort["portId"] = logicalPort.portId;
		jsonLogicalPort["vlanId"] = rte_be_to_cpu_16(logicalPort.vlanId);
		jsonLogicalPort["etherAddress"] = convertEtherAddressToString(logicalPort.etherAddress);
		jsonLogicalPort["flags"] = logicalPort.flags;
		jsonLogicalPort["flow"] = convertFlow(logicalPort.flow);

		json["logicalPorts"].emplace_back(jsonLogicalPort);
	}

	for (unsigned int tun64Id = 0;
	     tun64Id < CONFIG_YADECAP_TUN64_SIZE;
	     tun64Id++)
	{
		const auto& tunnel = globalBase->tun64tunnels[tun64Id];
		in6_addr addr;

		if (tunnel.flow.type == common::globalBase::eFlowType::controlPlane)
		{
			continue;
		}

		nlohmann::json jsonTun64;
		jsonTun64["tun64Id"] = tun64Id;
		jsonTun64["srcRndEnabled"] = tunnel.srcRndEnabled;
		memcpy(&addr, &tunnel.ipv6AddressSource, sizeof(addr));
		jsonTun64["ipv6SourceAddress"] = convertIPv6AddressToString(addr);
		jsonTun64["flow"] = convertFlow(tunnel.flow);

		json["tun64tunnels"].emplace_back(jsonTun64);
	}

	for (unsigned int decapId = 0;
	     decapId < CONFIG_YADECAP_DECAPS_SIZE;
	     decapId++)
	{
		const auto& decap = globalBase->decaps[decapId];

		if (decap.flow.type == common::globalBase::eFlowType::controlPlane)
		{
			continue;
		}

		nlohmann::json jsonDecap;
		jsonDecap["decapId"] = decapId;
		jsonDecap["ipv4DSCPFlags"] = decap.ipv4DSCPFlags;
		jsonDecap["flow"] = convertFlow(decap.flow);

		json["decaps"].emplace_back(jsonDecap);
	}

	for (unsigned int interfaceId = 0;
	     interfaceId < CONFIG_YADECAP_INTERFACES_SIZE;
	     interfaceId++)
	{
		const auto& interface = globalBase->interfaces[interfaceId];

		if (interface.flow.type == common::globalBase::eFlowType::controlPlane)
		{
			continue;
		}

		nlohmann::json jsonInterface;
		jsonInterface["interfaceId"] = interfaceId;
		jsonInterface["flow"] = convertFlow(interface.flow);

		json["interfaces"].emplace_back(jsonInterface);
	}

	{
		auto stats = globalBase->route_lpm4.getStats();
		json["route_lpm4"]["extendedChunksCount"] = stats.extendedChunksCount;
	}

	{
		auto stats = globalBase->route_lpm6.getStats();
		json["route_lpm6"]["extendedChunksCount"] = stats.extendedChunksCount;
	}

	{
		auto stats = globalBase->route_tunnel_lpm4.getStats();
		json["route_tunnel_lpm4"]["extendedChunksCount"] = stats.extendedChunksCount;
	}

	{
		auto stats = globalBase->route_tunnel_lpm6.getStats();
		json["route_tunnel_lpm6"]["extendedChunksCount"] = stats.extendedChunksCount;
	}

	globalBase->updater.acl.network_table->report(json["acl"]["network_table"]);
	globalBase->updater.acl.transport_table->report(json["acl"]["transport_table"]);
	globalBase->updater.acl.total_table->report(json["acl"]["total_table"]);
	globalBase->updater.acl.network_ipv4_source->report(json["acl"]["network"]["ipv4"]["source"]);
	globalBase->updater.acl.network_ipv4_destination->report(json["acl"]["network"]["ipv4"]["destination"]);
	globalBase->updater.acl.network_ipv6_source->report(json["acl"]["network"]["ipv6"]["source"]);
	globalBase->updater.acl.network_ipv6_destination_ht->report(json["acl"]["network"]["ipv6"]["destination_ht"]);
	globalBase->updater.acl.network_ipv6_destination->report(json["acl"]["network"]["ipv6"]["destination"]);

	json["serial"] = globalBase->serial;

	return json;
}
