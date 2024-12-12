#include <gtest/gtest.h>

#include "../../common/idp.h"
#include "../../common/sdpclient.h"
#include "../sdpserver.h"

class TestBus
{
public:
	static uint64_t GetSizeForCounters()
	{
		auto count_errors = static_cast<uint32_t>(common::idp::errorType::size);
		auto count_requests = static_cast<uint32_t>(common::idp::requestType::size);
		return (count_errors + 2 * count_requests) * sizeof(uint64_t);
	}

	void SetBufferForCounters(const common::sdp::DataPlaneInSharedMemory& sdp_data)
	{
		auto [requests, errors, durations] = sdp_data.BuffersBus();
		stats.requests = requests;
		stats.errors = errors;
		stats.durations = durations;
	}

	void SetTestValues()
	{
		for (uint32_t index = 0; index < static_cast<uint32_t>(common::idp::requestType::size); index++)
		{
			if (index % 2 == 0)
			{
				stats.requests[index] = index * index;
				stats.durations[index] = index * index * index;
			}
		}

		stats.errors[static_cast<uint32_t>(common::idp::errorType::busRead)] = 19;
	}

	void CompareWithClient(const common::sdp::DataPlaneInSharedMemory& sdp_data_client)
	{
		void* buffer = utils::ShiftBuffer(sdp_data_client.dataplane_data, sdp_data_client.start_bus_section);
		auto count_errors = static_cast<uint32_t>(common::idp::errorType::size);
		auto count_requests = static_cast<uint32_t>(common::idp::requestType::size);
		auto* requests = utils::ShiftBuffer<uint64_t*>(buffer, 0);
		auto* errors = utils::ShiftBuffer<uint64_t*>(buffer, count_requests * sizeof(uint64_t));
		auto* durations = utils::ShiftBuffer<uint64_t*>(buffer, (count_requests + count_errors) * sizeof(uint64_t));

		for (uint32_t index = 0; index < static_cast<uint32_t>(common::idp::requestType::size); index++)
		{
			ASSERT_EQ(stats.requests[index], requests[index]);
			ASSERT_EQ(stats.durations[index], durations[index]);
		}

		for (uint32_t index = 0; index < static_cast<uint32_t>(common::idp::requestType::size); index++)
		{
			ASSERT_EQ(stats.errors[index], errors[index]);
		}
	}

protected:
	struct sStats
	{
		uint64_t* requests; // common::idp::requestType::size
		uint64_t* errors; // common::idp::errorType::size
		uint64_t* durations; // common::idp::requestType::size
	} stats;
};

class TestWorker
{
public:
	static void FillMetadataWorkerCounters(common::sdp::MetadataWorker& metadata)
	{
		metadata.size = 0;
		metadata.start_counters = common::sdp::SdrSever::GetStartData(YANET_CONFIG_COUNTERS_SIZE * sizeof(uint64_t), metadata.size);
		metadata.start_acl_counters = common::sdp::SdrSever::GetStartData(YANET_CONFIG_ACL_COUNTERS_SIZE * sizeof(uint64_t), metadata.size);
		metadata.start_bursts = common::sdp::SdrSever::GetStartData((CONFIG_YADECAP_MBUFS_BURST_SIZE + 1) * sizeof(uint64_t), metadata.size);
		metadata.start_stats = common::sdp::SdrSever::GetStartData(sizeof(common::worker::stats::common), metadata.size);
		metadata.start_stats_ports = common::sdp::SdrSever::GetStartData(sizeof(common::worker::stats::port[CONFIG_YADECAP_PORTS_SIZE]), metadata.size);

		// stats
		std::map<std::string, uint64_t> counters_stats;
		counters_stats["brokenPackets"] = offsetof(common::worker::stats::common, brokenPackets);
		counters_stats["dropPackets"] = offsetof(common::worker::stats::common, dropPackets);
		counters_stats["ring_highPriority_drops"] = offsetof(common::worker::stats::common, ring_highPriority_drops);
		counters_stats["ring_normalPriority_drops"] = offsetof(common::worker::stats::common, ring_normalPriority_drops);
		counters_stats["ring_lowPriority_drops"] = offsetof(common::worker::stats::common, ring_lowPriority_drops);
		counters_stats["ring_highPriority_packets"] = offsetof(common::worker::stats::common, ring_highPriority_packets);
		counters_stats["ring_normalPriority_packets"] = offsetof(common::worker::stats::common, ring_normalPriority_packets);
		counters_stats["ring_lowPriority_packets"] = offsetof(common::worker::stats::common, ring_lowPriority_packets);
		counters_stats["decap_packets"] = offsetof(common::worker::stats::common, decap_packets);
		counters_stats["decap_fragments"] = offsetof(common::worker::stats::common, decap_fragments);
		counters_stats["decap_unknownExtensions"] = offsetof(common::worker::stats::common, decap_unknownExtensions);
		counters_stats["interface_lookupMisses"] = offsetof(common::worker::stats::common, interface_lookupMisses);
		counters_stats["interface_hopLimits"] = offsetof(common::worker::stats::common, interface_hopLimits);
		counters_stats["interface_neighbor_invalid"] = offsetof(common::worker::stats::common, interface_neighbor_invalid);
		counters_stats["nat64stateless_ingressPackets"] = offsetof(common::worker::stats::common, nat64stateless_ingressPackets);
		counters_stats["nat64stateless_ingressFragments"] = offsetof(common::worker::stats::common, nat64stateless_ingressFragments);
		counters_stats["nat64stateless_ingressUnknownICMP"] = offsetof(common::worker::stats::common, nat64stateless_ingressUnknownICMP);
		counters_stats["nat64stateless_egressPackets"] = offsetof(common::worker::stats::common, nat64stateless_egressPackets);
		counters_stats["nat64stateless_egressFragments"] = offsetof(common::worker::stats::common, nat64stateless_egressFragments);
		counters_stats["nat64stateless_egressUnknownICMP"] = offsetof(common::worker::stats::common, nat64stateless_egressUnknownICMP);
		counters_stats["balancer_invalid_reals_count"] = offsetof(common::worker::stats::common, balancer_invalid_reals_count);
		counters_stats["fwsync_multicast_egress_drops"] = offsetof(common::worker::stats::common, fwsync_multicast_egress_drops);
		counters_stats["fwsync_multicast_egress_packets"] = offsetof(common::worker::stats::common, fwsync_multicast_egress_packets);
		counters_stats["fwsync_multicast_egress_imm_packets"] = offsetof(common::worker::stats::common, fwsync_multicast_egress_imm_packets);
		counters_stats["fwsync_no_config_drops"] = offsetof(common::worker::stats::common, fwsync_no_config_drops);
		counters_stats["fwsync_unicast_egress_drops"] = offsetof(common::worker::stats::common, fwsync_unicast_egress_drops);
		counters_stats["fwsync_unicast_egress_packets"] = offsetof(common::worker::stats::common, fwsync_unicast_egress_packets);
		counters_stats["acl_ingress_dropPackets"] = offsetof(common::worker::stats::common, acl_ingress_dropPackets);
		counters_stats["acl_egress_dropPackets"] = offsetof(common::worker::stats::common, acl_egress_dropPackets);
		counters_stats["repeat_ttl"] = offsetof(common::worker::stats::common, repeat_ttl);
		counters_stats["leakedMbufs"] = offsetof(common::worker::stats::common, leakedMbufs);
		counters_stats["logs_packets"] = offsetof(common::worker::stats::common, logs_packets);
		counters_stats["logs_drops"] = offsetof(common::worker::stats::common, logs_drops);
		counters_stats["ttl_exceeded"] = offsetof(common::worker::stats::common, ttl_exceeded);
		for (const auto& iter : counters_stats)
		{
			metadata.counter_positions[iter.first] = (metadata.start_stats + iter.second) / sizeof(uint64_t);
		}

		// counters
		std::map<std::string, common::globalBase::static_counter_type> counters_named;
		counters_named["balancer_state_insert_failed"] = common::globalBase::static_counter_type::balancer_state_insert_failed;
		counters_named["balancer_state_insert_done"] = common::globalBase::static_counter_type::balancer_state_insert_done;
		counters_named["balancer_icmp_generated_echo_reply_ipv4"] = common::globalBase::static_counter_type::balancer_icmp_generated_echo_reply_ipv4;
		counters_named["balancer_icmp_generated_echo_reply_ipv6"] = common::globalBase::static_counter_type::balancer_icmp_generated_echo_reply_ipv6;
		counters_named["balancer_icmp_drop_icmpv4_payload_too_short_ip"] = common::globalBase::static_counter_type::balancer_icmp_drop_icmpv4_payload_too_short_ip;
		counters_named["balancer_icmp_drop_icmpv4_payload_too_short_port"] = common::globalBase::static_counter_type::balancer_icmp_drop_icmpv4_payload_too_short_port;
		counters_named["balancer_icmp_drop_icmpv6_payload_too_short_ip"] = common::globalBase::static_counter_type::balancer_icmp_drop_icmpv6_payload_too_short_ip;
		counters_named["balancer_icmp_drop_icmpv6_payload_too_short_port"] = common::globalBase::static_counter_type::balancer_icmp_drop_icmpv6_payload_too_short_port;
		counters_named["balancer_icmp_unmatching_src_from_original_ipv4"] = common::globalBase::static_counter_type::balancer_icmp_unmatching_src_from_original_ipv4;
		counters_named["balancer_icmp_unmatching_src_from_original_ipv6"] = common::globalBase::static_counter_type::balancer_icmp_unmatching_src_from_original_ipv6;
		counters_named["balancer_icmp_drop_real_disabled"] = common::globalBase::static_counter_type::balancer_icmp_drop_real_disabled;
		counters_named["balancer_icmp_no_balancer_src_ipv4"] = common::globalBase::static_counter_type::balancer_icmp_no_balancer_src_ipv4;
		counters_named["balancer_icmp_no_balancer_src_ipv6"] = common::globalBase::static_counter_type::balancer_icmp_no_balancer_src_ipv6;
		counters_named["balancer_icmp_drop_already_cloned"] = common::globalBase::static_counter_type::balancer_icmp_drop_already_cloned;
		counters_named["balancer_icmp_drop_no_unrdup_table_for_balancer_id"] = common::globalBase::static_counter_type::balancer_icmp_drop_no_unrdup_table_for_balancer_id;
		counters_named["balancer_icmp_drop_unrdup_vip_not_found"] = common::globalBase::static_counter_type::balancer_icmp_drop_unrdup_vip_not_found;
		counters_named["balancer_icmp_drop_no_vip_vport_proto_table_for_balancer_id"] = common::globalBase::static_counter_type::balancer_icmp_drop_no_vip_vport_proto_table_for_balancer_id;
		counters_named["balancer_icmp_drop_unexpected_transport_protocol"] = common::globalBase::static_counter_type::balancer_icmp_drop_unexpected_transport_protocol;
		counters_named["balancer_icmp_drop_unknown_service"] = common::globalBase::static_counter_type::balancer_icmp_drop_unknown_service;
		counters_named["balancer_icmp_failed_to_clone"] = common::globalBase::static_counter_type::balancer_icmp_failed_to_clone;
		counters_named["balancer_icmp_clone_forwarded"] = common::globalBase::static_counter_type::balancer_icmp_clone_forwarded;
		counters_named["balancer_icmp_sent_to_real"] = common::globalBase::static_counter_type::balancer_icmp_sent_to_real;
		counters_named["balancer_icmp_out_rate_limit_reached"] = common::globalBase::static_counter_type::balancer_icmp_out_rate_limit_reached;
		counters_named["slow_worker_normal_priority_rate_limit_exceeded"] = common::globalBase::static_counter_type::slow_worker_normal_priority_rate_limit_exceeded;

		counters_named["acl_ingress_v4_broken_packet"] = common::globalBase::static_counter_type::acl_ingress_v4_broken_packet;
		counters_named["acl_ingress_v6_broken_packet"] = common::globalBase::static_counter_type::acl_ingress_v6_broken_packet;
		counters_named["acl_egress_v4_broken_packet"] = common::globalBase::static_counter_type::acl_egress_v4_broken_packet;
		counters_named["acl_egress_v6_broken_packet"] = common::globalBase::static_counter_type::acl_egress_v6_broken_packet;
		counters_named["balancer_fragment_drops"] = common::globalBase::static_counter_type::balancer_fragment_drops;

		for (const auto& iter : counters_named)
		{
			metadata.counter_positions[iter.first] = metadata.start_counters / sizeof(uint64_t) + static_cast<uint64_t>(iter.second);
		}
	}

	void SetBufferForCounters(void* buffer, const common::sdp::MetadataWorker& metadata)
	{
		counters = utils::ShiftBuffer<uint64_t*>(buffer, metadata.start_counters);
		aclCounters = utils::ShiftBuffer<uint64_t*>(buffer, metadata.start_acl_counters);
		bursts = utils::ShiftBuffer<uint64_t*>(buffer, metadata.start_bursts);
		stats = utils::ShiftBuffer<common::worker::stats::common*>(buffer, metadata.start_stats);
		statsPorts = utils::ShiftBuffer<common::worker::stats::port*>(buffer, metadata.start_stats_ports);
	}

	void SetTestValues(tCoreId coreId)
	{
		// stats
		stats->dropPackets = (coreId + 1) * (coreId + 1);

		// statsPorts
		for (uint32_t index = 0; index < CONFIG_YADECAP_PORTS_SIZE + 1; index++)
		{
			statsPorts[index].controlPlane_drops = 3 * (index + coreId);
			statsPorts[index].physicalPort_egress_drops = 4 * (index + coreId);
		}

		// bursts
		for (uint32_t index = 0; index < CONFIG_YADECAP_MBUFS_BURST_SIZE + 1; index++)
		{
			bursts[index] = 5 * (index + coreId);
		}

		// counters
		for (uint32_t index = YANET_CONFIG_COUNTER_FALLBACK_SIZE; index < YANET_CONFIG_COUNTERS_SIZE; index++)
		{
			counters[index] = (index + coreId) * (index + coreId);
		}

		// aclCounters
		for (uint32_t index = 0; index < YANET_CONFIG_ACL_COUNTERS_SIZE; index++)
		{
			aclCounters[index] = index + coreId;
		}
	}

	void CompareWithClient(tCoreId coreId, const common::sdp::DataPlaneInSharedMemory& sdp_data_client)
	{
		auto iter = sdp_data_client.workers.find(coreId);
		ASSERT_TRUE(iter != sdp_data_client.workers.end());
		void* buffer = iter->second.buffer;

		// stats
		ASSERT_EQ(common::sdp::SdpClient::GetCounterByName(sdp_data_client, "dropPackets", coreId)[coreId], stats->dropPackets);

		// statsPorts
		auto* bufStatsPorts = utils::ShiftBuffer<common::worker::stats::port*>(buffer, sdp_data_client.metadata_worker.start_stats_ports);
		for (uint32_t index = 0; index < CONFIG_YADECAP_PORTS_SIZE + 1; index++)
		{
			ASSERT_EQ(statsPorts[index].controlPlane_drops, bufStatsPorts[index].controlPlane_drops);
			ASSERT_EQ(statsPorts[index].physicalPort_egress_drops, bufStatsPorts[index].physicalPort_egress_drops);
		}

		// bursts
		auto* bufBursts = utils::ShiftBuffer<uint64_t*>(buffer, sdp_data_client.metadata_worker.start_bursts);
		for (uint32_t index = 0; index < CONFIG_YADECAP_MBUFS_BURST_SIZE + 1; index++)
		{
			ASSERT_EQ(bursts[index], bufBursts[index]);
		}

		// counters
		auto* bufCounters = utils::ShiftBuffer<uint64_t*>(buffer, sdp_data_client.metadata_worker.start_counters);
		for (uint32_t index = 0; index < YANET_CONFIG_COUNTERS_SIZE; index++)
		{
			ASSERT_EQ(counters[index], bufCounters[index]);
		}

		// aclCounters
		auto* bufAclCounters = utils::ShiftBuffer<uint64_t*>(buffer, sdp_data_client.metadata_worker.start_acl_counters);
		for (uint32_t index = 0; index < YANET_CONFIG_ACL_COUNTERS_SIZE; index++)
		{
			ASSERT_EQ(aclCounters[index], bufAclCounters[index]);
		}
	}

protected:
	common::worker::stats::common* stats;
	common::worker::stats::port* statsPorts; // CONFIG_YADECAP_PORTS_SIZE
	uint64_t* bursts; // CONFIG_YADECAP_MBUFS_BURST_SIZE + 1
	uint64_t* counters; // YANET_CONFIG_COUNTERS_SIZE
	uint64_t* aclCounters; // YANET_CONFIG_ACL_COUNTERS_SIZE
};

class TestWorkerGc
{
public:
	static void FillMetadataWorkerCounters(common::sdp::MetadataWorkerGc& metadata)
	{
		metadata.size = 0;
		metadata.start_counters = common::sdp::SdrSever::GetStartData(YANET_CONFIG_COUNTERS_SIZE * sizeof(uint64_t), metadata.size);
		metadata.start_stats = common::sdp::SdrSever::GetStartData(sizeof(common::worker_gc::stats_t), metadata.size);

		// stats
		static_assert(std::is_trivially_destructible<common::worker_gc::stats_t>::value, "invalid struct destructible");
		std::map<std::string, uint64_t> counters_stats;
		counters_stats["broken_packets"] = offsetof(common::worker_gc::stats_t, broken_packets);
		counters_stats["drop_packets"] = offsetof(common::worker_gc::stats_t, drop_packets);
		counters_stats["ring_to_slowworker_packets"] = offsetof(common::worker_gc::stats_t, ring_to_slowworker_packets);
		counters_stats["ring_to_slowworker_drops"] = offsetof(common::worker_gc::stats_t, ring_to_slowworker_drops);
		counters_stats["fwsync_multicast_egress_packets"] = offsetof(common::worker_gc::stats_t, fwsync_multicast_egress_packets);
		counters_stats["fwsync_multicast_egress_drops"] = offsetof(common::worker_gc::stats_t, fwsync_multicast_egress_drops);
		counters_stats["fwsync_unicast_egress_packets"] = offsetof(common::worker_gc::stats_t, fwsync_unicast_egress_packets);
		counters_stats["fwsync_unicast_egress_drops"] = offsetof(common::worker_gc::stats_t, fwsync_unicast_egress_drops);
		counters_stats["drop_samples"] = offsetof(common::worker_gc::stats_t, drop_samples);
		counters_stats["balancer_state_insert_failed"] = offsetof(common::worker_gc::stats_t, balancer_state_insert_failed);
		counters_stats["balancer_state_insert_done"] = offsetof(common::worker_gc::stats_t, balancer_state_insert_done);

		for (const auto& iter : counters_stats)
		{
			metadata.counter_positions[iter.first] = (metadata.start_stats + iter.second) / sizeof(uint64_t);
		}
	}

	void SetBufferForCounters(void* buffer, const common::sdp::MetadataWorkerGc& metadata)
	{
		counters = utils::ShiftBuffer<uint64_t*>(buffer, metadata.start_counters);
		stats = utils::ShiftBuffer<common::worker_gc::stats_t*>(buffer, metadata.start_stats);
	}

	void SetTestValues(tCoreId coreId)
	{
		// stats
		stats->drop_samples = 7 * (coreId + 1) * (coreId + 1);

		// counters
		for (uint32_t index = YANET_CONFIG_COUNTER_FALLBACK_SIZE; index < YANET_CONFIG_COUNTERS_SIZE; index++)
		{
			counters[index] = 11 * (index + coreId) * (index + coreId);
		}
	}

	void CompareWithClient(tCoreId coreId, const common::sdp::DataPlaneInSharedMemory& sdp_data_client)
	{
		auto iter = sdp_data_client.workers_gc.find(coreId);
		ASSERT_TRUE(iter != sdp_data_client.workers_gc.end());
		void* buffer = iter->second.buffer;

		// stats
		ASSERT_EQ(common::sdp::SdpClient::GetCounterByName(sdp_data_client, "drop_samples", coreId)[coreId], stats->drop_samples);

		// counters
		auto* bufCounters = utils::ShiftBuffer<uint64_t*>(buffer, sdp_data_client.metadata_worker_gc.start_counters);
		for (uint32_t index = 0; index < YANET_CONFIG_COUNTERS_SIZE; index++)
		{
			ASSERT_EQ(counters[index], bufCounters[index]);
		}
	}

protected:
	uint64_t* counters; // YANET_CONFIG_COUNTERS_SIZE
	common::worker_gc::stats_t* stats;
};

TEST(SDP, FullTests)
{
	bool useHugeMem = false;
	std::vector<tCoreId> workers_id = {1, 2, 5};
	std::vector<tCoreId> workers_gc_id = {0, 3};

	// Initialize server
	common::sdp::DataPlaneInSharedMemory sdp_data_server;
	TestWorker::FillMetadataWorkerCounters(sdp_data_server.metadata_worker);
	TestWorkerGc::FillMetadataWorkerCounters(sdp_data_server.metadata_worker_gc);
	sdp_data_server.size_bus_section = TestBus::GetSizeForCounters();
	ASSERT_EQ(common::sdp::SdrSever::PrepareSharedMemoryData(sdp_data_server, workers_id, workers_gc_id, useHugeMem), eResult::success);

	// Initialize client
	common::sdp::DataPlaneInSharedMemory sdp_data_client;
	ASSERT_EQ(common::sdp::SdpClient::ReadSharedMemoryData(sdp_data_client, true), eResult::success);

	// Check, that server structure = client structure
	ASSERT_EQ(sdp_data_server, sdp_data_client);

	// Test work bus
	TestBus bus;
	bus.SetBufferForCounters(sdp_data_server);
	bus.SetTestValues();
	bus.CompareWithClient(sdp_data_client);

	// Test workers
	std::map<tCoreId, std::shared_ptr<TestWorker>> workers;
	for (tCoreId coreId : workers_id)
	{
		workers[coreId] = std::make_shared<TestWorker>();
		workers[coreId]->SetBufferForCounters(sdp_data_server.workers[coreId].buffer, sdp_data_server.metadata_worker);
		workers[coreId]->SetTestValues(coreId);
	}
	for (tCoreId coreId : workers_id)
	{
		workers[coreId]->CompareWithClient(coreId, sdp_data_client);
	}

	// Test workers_gc
	std::map<tCoreId, std::shared_ptr<TestWorkerGc>> workers_gc;
	for (tCoreId coreId : workers_gc_id)
	{
		workers_gc[coreId] = std::make_shared<TestWorkerGc>();
		workers_gc[coreId]->SetBufferForCounters(sdp_data_server.workers_gc[coreId].buffer, sdp_data_server.metadata_worker_gc);
		workers_gc[coreId]->SetTestValues(coreId);
	}
	for (tCoreId coreId : workers_id)
	{
		workers[coreId]->CompareWithClient(coreId, sdp_data_client);
	}
}
