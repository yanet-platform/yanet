#pragma once

#include <arpa/inet.h>

#include <array>
#include <functional>
#include <map>
#include <mutex>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <rte_ether.h>

#include "common/btree.h"
#include "common/ctree.h"
#include "common/idp.h"
#include "common/result.h"
#include "common/type.h"

#include "dregress.h"
#include "fragmentation.h"
#include "hashtable.h"
#include "type.h"

class cControlPlane ///< @todo: move to cDataPlane
{
public:
	cControlPlane(cDataPlane* dataPlane);
	virtual ~cControlPlane();

	eResult init(bool useKni);
	void start();
	void stop();
	void join();

	common::idp::updateGlobalBase::response updateGlobalBase(const common::idp::updateGlobalBase::request& request);
	eResult updateGlobalBaseBalancer(const common::idp::updateGlobalBaseBalancer::request& request);
	common::idp::getGlobalBase::response getGlobalBase(const common::idp::getGlobalBase::request& request);
	common::idp::getWorkerStats::response getWorkerStats(const common::idp::getWorkerStats::request& request);
	common::idp::getSlowWorkerStats::response getSlowWorkerStats();
	common::idp::get_worker_gc_stats::response get_worker_gc_stats();
	common::idp::get_dregress_counters::response get_dregress_counters();
	common::idp::get_ports_stats::response get_ports_stats();
	common::idp::get_ports_stats_extended::response get_ports_stats_extended();
	common::idp::getControlPlanePortStats::response getControlPlanePortStats(const common::idp::getControlPlanePortStats::request& request);
	common::idp::getPortStatsEx::response getPortStatsEx();
	common::idp::getFragmentationStats::response getFragmentationStats();
	common::idp::getFWState::response getFWState();
	common::idp::getFWStateStats::response getFWStateStats();
	eResult clearFWState();
	common::idp::getAclCounters::response getAclCounters();
	common::idp::getCounters::response getCounters(const common::idp::getCounters::request& request);
	common::idp::getOtherStats::response getOtherStats();
	common::idp::getConfig::response getConfig() const;
	common::idp::getErrors::response getErrors();
	common::idp::getReport::response getReport();
	common::idp::getGlobalBaseStats::response getGlobalBaseStats();
	common::idp::lpm4LookupAddress::response lpm4LookupAddress(const common::idp::lpm4LookupAddress::request& request);
	common::idp::lpm6LookupAddress::response lpm6LookupAddress(const common::idp::lpm6LookupAddress::request& request);
	common::idp::limits::response limits();
	common::idp::samples::response samples();
	common::idp::balancer_connection::response balancer_connection(const common::idp::balancer_connection::request& request);
	common::idp::balancer_service_connections::response balancer_service_connections();
	common::idp::balancer_real_connections::response balancer_real_connections();
	eResult debug_latch_update(const common::idp::debug_latch_update::request& request);
	eResult unrdup_vip_to_balancers(const common::idp::unrdup_vip_to_balancers::request& request);
	eResult update_vip_vport_proto(const common::idp::update_vip_vport_proto::request& request);
	common::idp::version::response version();
	common::idp::get_counter_by_name::response get_counter_by_name(const common::idp::get_counter_by_name::request& request);
	common::idp::nat64stateful_state::response nat64stateful_state(const common::idp::nat64stateful_state::request& request);
	common::idp::get_shm_info::response get_shm_info();

	void switchBase();
	void switchGlobalBase();
	virtual void waitAllWorkers();

	void sendPacketToSlowWorker(rte_mbuf* mbuf, const common::globalBase::tFlow& flow); ///< @todo: remove flow
	void freeWorkerPacket(rte_ring* ring_to_free_mbuf, rte_mbuf* mbuf);

protected:
	eResult initMempool();
	eResult initKnis();

	void mainThread();
	unsigned ring_handle(rte_ring* ring_to_free_mbuf, rte_ring* ring);

	void handlePacketFromForwardingPlane(rte_mbuf* mbuf); ///< @todo: rename
	void handlePacketFromControlPlane(rte_mbuf* mbuf);
	void handlePacket_icmp_translate_v6_to_v4(rte_mbuf* mbuf);
	void handlePacket_icmp_translate_v4_to_v6(rte_mbuf* mbuf);
	void handlePacket_dregress(rte_mbuf* mbuf);
	void handlePacket_repeat(rte_mbuf* mbuf);
	void handlePacket_fragment(rte_mbuf* mbuf);
	void handlePacket_farm(rte_mbuf* mbuf);
	void handlePacket_fw_state_sync(rte_mbuf* mbuf);
	bool handlePacket_fw_state_sync_ingress(rte_mbuf* mbuf);
	void handlePacket_balancer_icmp_forward(rte_mbuf* mbuf);
	void handlePacket_dump(rte_mbuf* mbuf);

	void SWRateLimiterTimeTracker();

	rte_mbuf* convertMempool(rte_ring* ring_to_free_mbuf, rte_mbuf* mbuf);

protected:
	friend class cReport;
	friend class cDataPlane;
	friend class dataplane::globalBase::generation;
	friend class dregress_t;

	struct sKniStats
	{
		sKniStats()
		{
			memset(this, 0, sizeof(*this));
		}

		uint64_t ipackets;
		uint64_t ibytes;
		uint64_t idropped;
		uint64_t opackets;
		uint64_t obytes;
		uint64_t odropped;
	};

	void flushKni(rte_kni* kni, sKniStats& stats, rte_mbuf** mbufs, uint32_t& count);
	void flushDump(rte_kni* kni, rte_mbuf** mbufs, uint32_t& count);

	cDataPlane* dataPlane;

	fragmentation_t fragmentation;
	dregress_t dregress;

	std::mutex mutex;
	std::mutex balancer_mutex;
	std::mutex unrdup_mutex;
	std::mutex interfaces_ips_mutex;
	std::mutex vip_vport_proto_mutex;

	rte_mempool* mempool;
	bool useKni;
	std::map<tPortId, std::tuple<std::string, rte_kni*, sKniStats, std::array<rte_mbuf*, CONFIG_YADECAP_MBUFS_BURST_SIZE>, uint32_t>> knis;

	std::map<tPortId, std::tuple<std::string, rte_kni*, std::array<rte_mbuf*, CONFIG_YADECAP_MBUFS_BURST_SIZE>, uint32_t>> ingress_dump_knis;

	std::map<tPortId, std::tuple<std::string, rte_kni*, std::array<rte_mbuf*, CONFIG_YADECAP_MBUFS_BURST_SIZE>, uint32_t>> egress_dump_knis;

	std::map<tPortId, std::tuple<std::string, rte_kni*, std::array<rte_mbuf*, 64 * CONFIG_YADECAP_MBUFS_BURST_SIZE>, uint32_t>> drop_dump_knis;

	common::slowworker::stats_t stats;
	common::idp::getErrors::response errors; ///< @todo: class errorsManager

	cWorker* slowWorker;
	std::queue<std::tuple<rte_mbuf*,
	                      common::globalBase::tFlow>>
	        slowWorkerMbufs;
	std::mutex fw_state_multicast_acl_ids_mutex;
	std::map<common::ipv6_address_t, tAclId> fw_state_multicast_acl_ids;

	// provided by unrdup.cfg, used to clone some icmp packets to neighbor balancers, index is balancer_id
	std::vector<std::unordered_map<common::ip_address_t, std::unordered_set<common::ip_address_t>>> vip_to_balancers;
	// check presence prior to cloning
	std::vector<std::unordered_set<std::tuple<common::ip_address_t, uint16_t, uint8_t>>> vip_vport_proto;

	std::chrono::high_resolution_clock::time_point prevTimePointForSWRateLimiter;

	uint32_t icmpOutRemainder;

	uint32_t currentTime;
	uint32_t gc_step;
};
