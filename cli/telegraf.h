#pragma once

#include "common/counters.h"
#include "common/icontrolplane.h"
#include "common/idataplane.h"
#include "common/sdpclient.h"

#include "helper.h"
#include "influxdb_format.h"

namespace telegraf
{

void replaceAll(std::string& string,
                const std::string& search,
                const std::string& replace)
{
	for (auto pos = string.find(search);
	     pos != std::string::npos;
	     pos = string.find(search, pos + replace.length()))
	{
		string.replace(pos, search.length(), replace);
	}
}

void ports_stats()
{
	interface::dataPlane dataplane;
	const auto [ports_cfg, cores_cfg, values] = dataplane.getConfig();
	GCC_BUG_UNUSED(cores_cfg);
	GCC_BUG_UNUSED(values);

	const std::vector<std::tuple<const char*, common::idp::port_stats_t>> ports_stats_per_type{
	        {"port", dataplane.get_ports_stats()},
	        {"controlPlanePort", dataplane.getControlPlanePortStats({})},
	};

	for (const auto& [type, ports_stats] : ports_stats_per_type)
	{
		for (const auto& [port_id, stats] : ports_stats)
		{
			const auto& [interface_name, socket_id, eth_addr, pci] = ports_cfg.at(port_id);
			GCC_BUG_UNUSED(socket_id);
			GCC_BUG_UNUSED(eth_addr);
			GCC_BUG_UNUSED(pci);
			const auto& [rx_packets, rx_bytes, rx_errors, rx_drops, tx_packets, tx_bytes, tx_errors, tx_drops] = stats;

			printf("%s,physicalPortName=%s "
			       "rx_packets=%luu,"
			       "rx_bytes=%luu,"
			       "rx_errors=%luu,"
			       "rx_drops=%luu,"
			       "tx_packets=%luu,"
			       "tx_bytes=%luu,"
			       "tx_errors=%luu,"
			       "tx_drops=%luu\n",
			       type,
			       interface_name.data(),
			       rx_packets,
			       rx_bytes,
			       rx_errors,
			       rx_drops,
			       tx_packets,
			       tx_bytes,
			       tx_errors,
			       tx_drops);
		}
	}
}

std::vector<tCounterId> vector_range(const tCounterId from,
                                     const tCounterId to)
{
	std::vector<tCounterId> response;
	response.reserve(to - from);
	for (tCounterId i = from;
	     i < to;
	     i++)
	{
		response.emplace_back(i);
	}
	return response;
}

void print_static_counters(const std::vector<uint64_t>& static_counters,
                           const std::vector<std::tuple<const char*, common::globalBase::static_counter_type>>& indexes)
{
	std::vector<influxdb_format::value_t> values;
	for (const auto& [name, index] : indexes)
	{
		values.emplace_back(name, static_counters[(tCounterId)index]);
	}

	influxdb_format::print("worker", {}, values);
}

void unsafe()
{
	interface::controlPlane controlplane;
	interface::dataPlane dataplane;
	const auto [responseWorkers, responseWorkerGCs, responseSlowWorkerHashtableGC, responseFragmentation, responseFWState, responseTun64, response_nat64stateful, responseControlplane] = controlplane.telegraf_unsafe();
	const auto& [responseSlowWorker, hashtable_gc] = responseSlowWorkerHashtableGC;

	const auto static_counters = common::sdp::SdpClient::GetCounters(vector_range(0, (tCounterId)common::globalBase::static_counter_type::size));
	const auto neighbor_stats = dataplane.neighbor_stats();
	const auto memory_stats = dataplane.memory_manager_stats();
	const auto& [memory_groups, memory_objects] = memory_stats;

	const auto durations = controlplane.controlplane_durations();
	uint64_t total_acl_ingress_dropPackets = 0, total_acl_egress_dropPackets = 0;

	for (const auto& [coreId, worker] : responseWorkers)
	{
		const auto& [iterations, stats, ports_stats] = worker;
		total_acl_ingress_dropPackets += stats.acl_ingress_dropPackets;
		total_acl_egress_dropPackets += stats.acl_egress_dropPackets;

		printf("worker,coreId=%u "
		       "iterations=%luu,"
		       "brokenPackets=%luu,"
		       "dropPackets=%luu,"
		       "ring_highPriority_drops=%luu,"
		       "ring_normalPriority_drops=%luu,"
		       "ring_lowPriority_drops=%luu,"
		       "ring_highPriority_packets=%luu,"
		       "ring_normalPriority_packets=%luu,"
		       "ring_lowPriority_packets=%luu,"
		       "decap_packets=%luu,"
		       "decap_fragments=%luu,"
		       "decap_unknownExtensions=%luu,"
		       "interface_lookupMisses=%luu,"
		       "interface_hopLimits=%luu,"
		       "interface_neighbor_invalid=%luu,"
		       "nat64stateless_ingressPackets=%luu,"
		       "nat64stateless_ingressFragments=%luu,"
		       "nat64stateless_ingressUnknownICMP=%luu,"
		       "nat64stateless_egressPackets=%luu,"
		       "nat64stateless_egressFragments=%luu,"
		       "nat64stateless_egressUnknownICMP=%luu,"
		       "fwsync_multicast_egress_drops=%luu,"
		       "fwsync_multicast_egress_packets=%luu,"
		       "fwsync_multicast_egress_imm_packets=%luu,"
		       "fwsync_no_config_drops=%luu,"
		       "repeat_ttl=%luu,"
		       "acl_ingress_dropPackets=%luu,"
		       "acl_egress_dropPackets=%luu,"
		       "log_drops=%luu,"
		       "log_packets=%luu\n",
		       coreId,
		       iterations,
		       stats.brokenPackets,
		       stats.dropPackets,
		       stats.ring_highPriority_drops,
		       stats.ring_normalPriority_drops,
		       stats.ring_lowPriority_drops,
		       stats.ring_highPriority_packets,
		       stats.ring_normalPriority_packets,
		       stats.ring_lowPriority_packets,
		       stats.decap_packets,
		       stats.decap_fragments,
		       stats.decap_unknownExtensions,
		       stats.interface_lookupMisses,
		       stats.interface_hopLimits,
		       stats.interface_neighbor_invalid,
		       stats.nat64stateless_ingressPackets,
		       stats.nat64stateless_ingressFragments,
		       stats.nat64stateless_ingressUnknownICMP,
		       stats.nat64stateless_egressPackets,
		       stats.nat64stateless_egressFragments,
		       stats.nat64stateless_egressUnknownICMP,
		       stats.fwsync_multicast_egress_drops,
		       stats.fwsync_multicast_egress_packets,
		       stats.fwsync_multicast_egress_imm_packets,
		       stats.fwsync_no_config_drops,
		       stats.repeat_ttl,
		       stats.acl_ingress_dropPackets,
		       stats.acl_egress_dropPackets,
		       stats.logs_drops,
		       stats.logs_packets);

		printf("worker,coreId=all "
		       "acl_ingress_dropPackets=%luu,"
		       "acl_egress_dropPackets=%luu\n",
		       total_acl_ingress_dropPackets,
		       total_acl_egress_dropPackets);

		for (const auto& [physicalPortName, stats] : ports_stats)
		{
			printf("worker,coreId=%u,physicalPortName=%s "
			       "physicalPort_egress_drops=%luu,"
			       "controlPlane_drops=0\n", // @todo: DELETE
			       coreId,
			       physicalPortName.data(),
			       stats.physicalPort_egress_drops);
		}
	}

	{
		using common::globalBase::static_counter_type; ///< C++20: using enum

		print_static_counters(static_counters,
		                      {{"balancer_state_insert_failed", static_counter_type::balancer_state_insert_failed},
		                       {"balancer_state_insert_done", static_counter_type::balancer_state_insert_done},
		                       {"balancer_icmp_generated_echo_reply_ipv4", static_counter_type::balancer_icmp_generated_echo_reply_ipv4},
		                       {"balancer_icmp_generated_echo_reply_ipv6", static_counter_type::balancer_icmp_generated_echo_reply_ipv6},
		                       {"balancer_icmp_sent_to_real", static_counter_type::balancer_icmp_sent_to_real},
		                       {"balancer_icmp_drop_icmpv4_payload_too_short_ip", static_counter_type::balancer_icmp_drop_icmpv4_payload_too_short_ip},
		                       {"balancer_icmp_drop_icmpv4_payload_too_short_port", static_counter_type::balancer_icmp_drop_icmpv4_payload_too_short_port},
		                       {"balancer_icmp_drop_icmpv6_payload_too_short_ip", static_counter_type::balancer_icmp_drop_icmpv6_payload_too_short_ip},
		                       {"balancer_icmp_drop_icmpv6_payload_too_short_port", static_counter_type::balancer_icmp_drop_icmpv6_payload_too_short_port},
		                       {"balancer_icmp_unmatching_src_from_original_ipv4", static_counter_type::balancer_icmp_unmatching_src_from_original_ipv4},
		                       {"balancer_icmp_unmatching_src_from_original_ipv6", static_counter_type::balancer_icmp_unmatching_src_from_original_ipv6},
		                       {"balancer_icmp_drop_real_disabled", static_counter_type::balancer_icmp_drop_real_disabled},
		                       {"balancer_icmp_no_balancer_src_ipv4", static_counter_type::balancer_icmp_no_balancer_src_ipv4},
		                       {"balancer_icmp_no_balancer_src_ipv6", static_counter_type::balancer_icmp_no_balancer_src_ipv6},
		                       {"balancer_icmp_out_rate_limit_reached", static_counter_type::balancer_icmp_out_rate_limit_reached},
		                       {"balancer_icmp_drop_already_cloned", static_counter_type::balancer_icmp_drop_already_cloned},
		                       {"balancer_icmp_drop_no_unrdup_table_for_balancer_id", static_counter_type::balancer_icmp_drop_no_unrdup_table_for_balancer_id},
		                       {"balancer_icmp_drop_unrdup_vip_not_found", static_counter_type::balancer_icmp_drop_unrdup_vip_not_found},
		                       {"balancer_icmp_drop_no_vip_vport_proto_table_for_balancer_id", static_counter_type::balancer_icmp_drop_no_vip_vport_proto_table_for_balancer_id},
		                       {"balancer_icmp_drop_unexpected_transport_protocol", static_counter_type::balancer_icmp_drop_unexpected_transport_protocol},
		                       {"balancer_icmp_drop_unknown_service", static_counter_type::balancer_icmp_drop_unknown_service},
		                       {"balancer_icmp_failed_to_clone", static_counter_type::balancer_icmp_failed_to_clone},
		                       {"balancer_icmp_clone_forwarded", static_counter_type::balancer_icmp_clone_forwarded},
		                       {"acl_ingress_v4_broken_packet", static_counter_type::acl_ingress_v4_broken_packet},
		                       {"acl_ingress_v6_broken_packet", static_counter_type::acl_ingress_v6_broken_packet},
		                       {"acl_egress_v4_broken_packet", static_counter_type::acl_egress_v4_broken_packet},
		                       {"acl_egress_v6_broken_packet", static_counter_type::acl_egress_v6_broken_packet},
		                       {"slow_worker_normal_priority_rate_limit_exceeded", static_counter_type::slow_worker_normal_priority_rate_limit_exceeded}});
	}

	/// worker gc
	for (const auto& [core_id, worker] : responseWorkerGCs)
	{
		const auto& [iterations, stats] = worker;

		influxdb_format::print("worker_gc",
		                       {{"core_id", core_id}},
		                       {{"iterations", iterations},
		                        {"broken_packets", stats.broken_packets},
		                        {"drop_packets", stats.drop_packets},
		                        {"ring_to_slowworker_packets", stats.ring_to_slowworker_packets},
		                        {"ring_to_slowworker_drops", stats.ring_to_slowworker_drops},
		                        {"fwsync_multicast_egress_packets", stats.fwsync_multicast_egress_packets},
		                        {"fwsync_multicast_egress_drops", stats.fwsync_multicast_egress_drops},
		                        {"drop_samples", stats.drop_samples},
		                        {"balancer_state_insert_failed", stats.balancer_state_insert_failed},
		                        {"balancer_state_insert_done", stats.balancer_state_insert_done}});
	}

	/// slowWorker
	{
		influxdb_format::print("slowWorker",
		                       {},
		                       {{"repeat_packets", responseSlowWorker.repeat_packets},
		                        {"tofarm_packets", responseSlowWorker.tofarm_packets},
		                        {"farm_packets", responseSlowWorker.farm_packets},
		                        {"slowworker_packets", responseSlowWorker.slowworker_packets},
		                        {"slowworker_drops", responseSlowWorker.slowworker_drops},
		                        {"fwsync_multicast_ingress_packets", responseSlowWorker.fwsync_multicast_ingress_packets},
		                        {"mempool_is_empty", responseSlowWorker.mempool_is_empty},
		                        {"unknown_dump_interface", responseSlowWorker.unknown_dump_interface}});
	}

	/// hashtable gc
	{
		for (const auto& [socket_id, name, valid_keys, iterations] : hashtable_gc)
		{
			printf("hashtable_gc,"
			       "socket_id=%uu,"
			       "name=%s "
			       "valid_keys=%luu,"
			       "iterations=%luu\n",
			       socket_id,
			       name.data(),
			       valid_keys,
			       iterations);
		}
	}

	/// fragmentation
	{
		printf("fragmentation "
		       "current_count_packets=%luu,"
		       "total_overflow_packets=%luu,"
		       "not_fragment_packets=%luu,"
		       "empty_packets=%luu,"
		       "flow_overflow_packets=%luu,"
		       "intersect_packets=%luu,"
		       "unknown_network_type_packets=%luu,"
		       "timeout_packets=%luu\n",
		       responseFragmentation.current_count_packets,
		       responseFragmentation.total_overflow_packets,
		       responseFragmentation.not_fragment_packets,
		       responseFragmentation.empty_packets,
		       responseFragmentation.flow_overflow_packets,
		       responseFragmentation.intersect_packets,
		       responseFragmentation.unknown_network_type_packets,
		       responseFragmentation.timeout_packets);
	}

	/// fwstate
	{
		printf("fwstate "
		       "fwstate4_size=%luu,"
		       "fwstate6_size=%luu\n",
		       responseFWState.fwstate4_size,
		       responseFWState.fwstate6_size);
	}

	for (const auto& [moduleName, stats] : responseTun64)
	{
		influxdb_format::print("tun64",
		                       {{"name", moduleName}},
		                       {{"encap_packets", stats.encap_packets},
		                        {"encap_bytes", stats.encap_bytes},
		                        {"encap_dropped", stats.encap_dropped},
		                        {"decap_packets", stats.decap_packets},
		                        {"decap_bytes", stats.decap_bytes},
		                        {"decap_unknown", stats.decap_unknown}});
	}

	for (const auto& [name, stats] : response_nat64stateful)
	{
		using nat64stateful::module_counter; ///< C++20: using enum

		influxdb_format::print("nat64stateful",
		                       {{"name", name}},
		                       {{"lan_packets", stats[(tCounterId)module_counter::lan_packets]},
		                        {"lan_bytes", stats[(tCounterId)module_counter::lan_bytes]},
		                        {"wan_packets", stats[(tCounterId)module_counter::wan_packets]},
		                        {"wan_bytes", stats[(tCounterId)module_counter::wan_bytes]},
		                        {"pool_is_empty", stats[(tCounterId)module_counter::pool_is_empty]},
		                        {"tries_failed", stats[(tCounterId)module_counter::tries_failed]},
		                        {"wan_state_not_found", stats[(tCounterId)module_counter::wan_state_not_found]},
		                        {"wan_state_insert_failed", stats[(tCounterId)module_counter::wan_state_insert_failed]},
		                        {"wan_state_insert_success", stats[(tCounterId)module_counter::wan_state_insert_success]},
		                        {"wan_state_cross_numa_insert_failed", stats[(tCounterId)module_counter::wan_state_cross_numa_insert_failed]},
		                        {"wan_state_cross_numa_insert_success", stats[(tCounterId)module_counter::wan_state_cross_numa_insert_success]},
		                        {"lan_state_insert_failed", stats[(tCounterId)module_counter::lan_state_insert_failed]},
		                        {"lan_state_insert_success", stats[(tCounterId)module_counter::lan_state_insert_success]},
		                        {"lan_state_cross_numa_insert_failed", stats[(tCounterId)module_counter::lan_state_cross_numa_insert_failed]},
		                        {"lan_state_cross_numa_insert_success", stats[(tCounterId)module_counter::lan_state_cross_numa_insert_success]}});

		influxdb_format::print_histogram("nat64stateful",
		                                 {{"name", name}},
		                                 "try",
		                                 "state_insert_collision",
		                                 stats,
		                                 module_counter::tries_array_start,
		                                 module_counter::tries_array_end);
	}

	for (const auto& [name, duration] : durations)
	{
		influxdb_format::print("duration",
		                       {{"name", name}},
		                       {{"duration", duration, ""}});
	}

	for (const auto& [name, counter] : responseControlplane)
	{
		influxdb_format::print("controlplane",
		                       {{"name", name}},
		                       {{"value", counter}});
	}

	const auto nat46clat_stats = controlplane.nat46clat_stats();
	for (const auto& [module_name, stats] : nat46clat_stats)
	{
		using nat46clat::module_counter; ///< C++20: using enum

		influxdb_format::print("nat46clat",
		                       {{"name", module_name}},
		                       {{"lan_packets", stats[(size_t)module_counter::lan_packets]},
		                        {"lan_bytes", stats[(size_t)module_counter::lan_bytes]},
		                        {"wan_packets", stats[(size_t)module_counter::wan_packets]},
		                        {"wan_bytes", stats[(size_t)module_counter::wan_bytes]}});
	}

	influxdb_format::print("neighbor",
	                       {},
	                       {{"hashtable_insert_success", neighbor_stats.hashtable_insert_success},
	                        {"hashtable_insert_error", neighbor_stats.hashtable_insert_error},
	                        {"hashtable_remove_success", neighbor_stats.hashtable_remove_success},
	                        {"hashtable_remove_error", neighbor_stats.hashtable_remove_error},
	                        {"netlink_neighbor_update", neighbor_stats.netlink_neighbor_update},
	                        {"resolve", neighbor_stats.resolve}});

	/// memory
	{
		std::map<std::string, ///< object_name
		         common::uint64> ///< current
		        currents;

		uint64_t total = 0;
		for (const auto& [name, socket_id, current] : memory_objects)
		{
			total += current;

			currents[name] = std::max(currents[name].value,
			                          current);

			influxdb_format::print("memory",
			                       {{"name", name},
			                        {"socket_id", socket_id}},
			                       {{"current", current}});
		}

		influxdb_format::print("memory",
		                       {{"name", "total"}},
		                       {{"current", total}});

		memory_groups.for_each([&](const auto& memory_group,
		                           const std::set<std::string>& object_names) {
			if (memory_group.name.empty())
			{
				return;
			}

			uint64_t group_total = 0;
			for (const auto& object_name : object_names)
			{
				group_total += currents[object_name];
			}

			uint64_t maximum = 0;
			if (memory_group.limit)
			{
				maximum = memory_group.limit;
			}

			influxdb_format::print("memory",
			                       {{"group", memory_group.name}},
			                       {{"current", group_total},
			                        {"maximum", maximum}});
		});
	}
}

void dregress()
{
	interface::controlPlane controlPlane;
	const auto [counters_stream, communities_orig] = controlPlane.telegraf_dregress();

	common::dregress::counters_t counters_v4;
	common::dregress::counters_t counters_v6;

	common::stream_in_t stream(counters_stream);
	stream.pop(counters_v4);
	stream.pop(counters_v6);

	std::map<common::community_t, std::string> communities;
	for (const auto& [community, peer_link_orig] : communities_orig)
	{
		GCC_BUG_UNUSED(peer_link_orig);

		uint32_t link_id = 0;

		if (static_cast<uint32_t>(community) > 0)
		{
			link_id = static_cast<uint32_t>(community) & 0xFFFF;
		}

		communities[community] = std::to_string(link_id);
	}

	counters_v4.convert_update(communities,
	                           {},
	                           {{true, "best"},
	                            {false, "alternative"}},
	                           {},
	                           {},
	                           {},
	                           {});
	counters_v6.convert_update(communities,
	                           {},
	                           {{true, "best"},
	                            {false, "alternative"}},
	                           {},
	                           {},
	                           {},
	                           {});

	counters_v4.print({"link_id",
	                   "nexthop",
	                   "route",
	                   "label",
	                   "peer_as",
	                   "origin_as",
	                   "prefix"},
	                  [](const std::string& key,
	                     const std::array<uint64_t, 4>& values) {
		                  printf("dregress_v4%s ack=%luu,loss=%luu\n",
		                         key.data(),
		                         values[0],
		                         values[1]);

		                  if (values[3])
		                  {
			                  printf("dregress_rtt_v4%s "
			                         "rtt_sum=%luu,"
			                         "rtt_count=%luu\n",
			                         key.data(),
			                         values[2],
			                         values[3]);
		                  }
	                  });

	counters_v6.print({"link_id",
	                   "nexthop",
	                   "route",
	                   "label",
	                   "peer_as",
	                   "origin_as",
	                   "prefix"},
	                  [](const std::string& key,
	                     const std::array<uint64_t, 4>& values) {
		                  printf("dregress_v6%s ack=%luu,loss=%luu\n",
		                         key.data(),
		                         values[0],
		                         values[1]);

		                  if (values[3])
		                  {
			                  printf("dregress_rtt_v6%s "
			                         "rtt_sum=%luu,"
			                         "rtt_count=%luu\n",
			                         key.data(),
			                         values[2],
			                         values[3]);
		                  }
	                  });
}

void dregress_traffic()
{
	interface::controlPlane controlPlane;
	const auto& [peer, peer_as] = controlPlane.telegraf_dregress_traffic();

	for (const auto& [is_ipv4, link_id, nexthop, packets, bytes] : peer)
	{

		influxdb_format::print(is_ipv4 ? "dregress_traffic_v4" : "dregress_traffic_v6",
		                       {{"link_id", link_id},
		                        {"nexthop", nexthop}},
		                       {{"packets", packets},
		                        {"bytes", bytes}});
	}

	std::map<std::tuple<bool, ///< is_ipv4
	                    uint32_t, ///< link_id
	                    std::string>, ///< nexthop
	         std::tuple<common::uint64, ///< packets
	                    common::uint64>>
	        peer_only;
	for (const auto& [is_ipv4, link_id, nexthop, origin_as, packets, bytes] : peer_as)
	{

		influxdb_format::print(is_ipv4 ? "dregress_traffic_as_v4" : "dregress_traffic_as_v6",
		                       {{"link_id", link_id},
		                        {"nexthop", nexthop},
		                        {"origin_as", origin_as}},
		                       {{"packets", packets},
		                        {"bytes", bytes}});

		auto& [peer_only_packets, peer_only_bytes] = peer_only[{is_ipv4, link_id, nexthop}];
		peer_only_packets += packets;
		peer_only_bytes += bytes;
	}

	for (const auto& [key, value] : peer_only)
	{
		const auto& [is_ipv4, link_id, nexthop] = key;
		const auto& [packets, bytes] = value;

		influxdb_format::print(is_ipv4 ? "dregress_traffic_as_v4" : "dregress_traffic_as_v6",
		                       {{"link_id", link_id},
		                        {"nexthop", nexthop}},
		                       {{"packets", packets},
		                        {"bytes", bytes}});
	}
}

void other()
{
	interface::controlPlane controlPlane;
	const auto& [flagFirst, workers, ports] = controlPlane.telegraf_other();
	const auto rib_summary = controlPlane.rib_summary();
	const auto limit_summary = controlPlane.limit_summary();
	GCC_BUG_UNUSED(flagFirst);

	for (const auto& workerIter : workers)
	{
		influxdb_format::print("worker",
		                       {{"coreId", workerIter.first}},
		                       {{"usage", std::get<0>(workerIter.second), ""}});
	}

	for (const auto& [physicalPortName, stats] : ports)
	{
		influxdb_format::print("port",
		                       {{"physicalPortName", physicalPortName}},
		                       {{"ext_", stats}});
	}

	for (const auto& [key, value] : rib_summary)
	{
		const auto& [vrf, priority, protocol, peer, table_name] = key;
		const auto& [prefixes, paths, eor] = value;

		influxdb_format::print("rib",
		                       {{"vrf", vrf},
		                        {"priority", priority},
		                        {"protocol", protocol},
		                        {"peer", peer},
		                        {"table_name", table_name, {.optional_null = "n/s", .string_empty = "n/s"}}},
		                       {{"prefixes", prefixes},
		                        {"paths", paths},
		                        {"eor", (uint32_t)eor}});
	}

	for (const auto& [name, socket_id, current, maximum] : limit_summary)
	{
		influxdb_format::print("limit",
		                       {{"name", name},
		                        {"socket_id", socket_id}},
		                       {{"current", current},
		                        {"maximum", maximum}});
	}
}

void mappings()
{
	interface::controlPlane controlPlane;
	const auto& v = controlPlane.telegraf_mappings();

	for (const auto& mapping : v)
	{
		const auto& [module, ipv4_address, ipv6_address, stats] = mapping;

		influxdb_format::print("tun64",
		                       {{"name", module},
		                        {"ipv4", ipv4_address},
		                        {"ipv6", ipv6_address}},
		                       {{"encap_packets", stats.encap_packets},
		                        {"encap_bytes", stats.encap_bytes},
		                        {"decap_packets", stats.decap_packets},
		                        {"decap_bytes", stats.decap_bytes}});
	}
}

namespace balancer
{

void service()
{
	interface::controlPlane controlPlane;
	const auto& module_name_services = controlPlane.telegraf_balancer_service();

	interface::dataPlane dataplane;
	auto balancer_service_connections = dataplane.balancer_service_connections();

	for (const auto& [module, services] : module_name_services)
	{
		const auto& [module_id, module_name] = module;

		for (const auto& [virtual_ip, proto, virtual_port, nap_connections, packets, bytes, real_disabled_packets, real_disabled_bytes] : services)
		{
			GCC_BUG_UNUSED(nap_connections);

			common::idp::balancer_service_connections::service_key_t key = {module_id,
			                                                                virtual_ip,
			                                                                proto,
			                                                                virtual_port};

			uint32_t connections = 0;
			for (auto& [socket_id, service_connections] : balancer_service_connections)
			{
				GCC_BUG_UNUSED(socket_id);

				const auto& socket_connections = service_connections[key].value;
				if (socket_connections > connections)
				{
					connections = socket_connections;
				}
			}

			influxdb_format::print("balancer_service",
			                       {{"module_name", module_name},
			                        {"virtual_ip", virtual_ip.toString()},
			                        {"proto", controlplane::balancer::from_proto(proto)},
			                        {"virtual_port", virtual_port}},
			                       {{"connections", connections},
			                        {"packets", packets},
			                        {"bytes", bytes},
			                        {"real_disabled_packets", real_disabled_packets},
			                        {"real_disabled_bytes", real_disabled_bytes}});
		}
	}
}

}

void main_counters()
{
	common::sdp::DataPlaneInSharedMemory sdp_data;
	OpenSharedMemoryDataplaneBuffers(sdp_data, true);

	for (const auto& [coreId, worker_info] : sdp_data.workers)
	{
		std::vector<influxdb_format::value_t> values;
		auto* buffer = utils::ShiftBuffer<uint64_t*>(worker_info.buffer,
		                                             sdp_data.metadata_worker.start_counters);
		for (const auto& [name, index] : sdp_data.metadata_worker.counter_positions)
		{
			values.emplace_back(name.data(), buffer[index]);
		}
		influxdb_format::print("worker", {{"coreId", coreId}}, values);
	}

	for (const auto& [coreId, worker_info] : sdp_data.workers_gc)
	{
		std::vector<influxdb_format::value_t> values;
		auto* buffer = utils::ShiftBuffer<uint64_t*>(worker_info.buffer,
		                                             sdp_data.metadata_worker.start_counters);
		for (const auto& [name, index] : sdp_data.metadata_worker_gc.counter_positions)
		{
			values.emplace_back(name.data(), buffer[index]);
		}
		influxdb_format::print("worker_gc", {{"coreId", coreId}}, values);
	}
}

void route()
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_counters();

	for (const auto& [link, nexthop, prefix, counts, size] : response)
	{
		influxdb_format::print("route_counters", {{"link", link}, {"nexthop", nexthop}, {"prefix", prefix}}, {{"counts", counts}, {"size", size}});
	}
}

void route_tunnel()
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_tunnel_counters();

	for (const auto& [link, nexthop, counts, size] : response)
	{
		influxdb_format::print("route_tunnel_counters", {{"link", link}, {"nexthop", nexthop}}, {{"counts", counts}, {"size", size}});
	}
}

inline void acl()
{
	interface::dataPlane dataplane;
	const auto& response = dataplane.hitcount_dump();

	for (const auto& [id, data] : response)
	{
		influxdb_format::print("acl",
		                       {{"name", "counters"},
		                        {"rule", id}},
		                       {{"packets", data.count, "u"},
		                        {"bytes", data.bytes, "u"}});
	}
}
}
