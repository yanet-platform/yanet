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

#include "common/idp.h"
#include "common/result.h"
#include "common/static_vector.h"
#include "common/type.h"

#include "dregress.h"
#include "dpdk.h"
#include "fragmentation.h"
#include "kernel_interface_handle.h"
#include "slow_worker.h"
#include "type.h"

class cControlPlane ///< @todo: move to cDataPlane
{
public:
	cControlPlane(cDataPlane* dataPlane);
	virtual ~cControlPlane();

	eResult init(bool use_kernel_interface);
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
	common::dregress::stats_t DregressStats() const;
	dataplane::hashtable_chain_spinlock_stats_t DregressConnectionsStats() const;
	common::idp::getFWState::response getFWState();
	common::idp::getFWStateStats::response getFWStateStats();
	eResult clearFWState();
	common::idp::getAclCounters::response getAclCounters();
	common::idp::getCounters::response getCounters(const common::idp::getCounters::request& request);
	common::idp::getOtherStats::response getOtherStats();
	common::idp::getConfig::response getConfig() const;
	common::idp::getErrors::response getErrors();
	common::idp::getReport::response getReport();
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
	common::idp::get_shm_tsc_info::response get_shm_tsc_info();
	eResult dump_physical_port(const common::idp::dump_physical_port::request& request);
	eResult balancer_state_clear();

	void switchBase();
	void switchGlobalBase();
	virtual void waitAllWorkers();

	void sendPacketToSlowWorker(rte_mbuf* mbuf, const common::globalBase::tFlow& flow); ///< @todo: remove flow
	void freeWorkerPacket(rte_ring* ring_to_free_mbuf, rte_mbuf* mbuf);

protected:
	eResult initMempool();

	void mainThread();
	unsigned ring_handle(rte_ring* ring_to_free_mbuf, rte_ring* ring);

	void handlePacketFromForwardingPlane(rte_mbuf* mbuf); ///< @todo: rename
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
		uint64_t ipackets = 0;
		uint64_t ibytes = 0;
		uint64_t idropped = 0;
		uint64_t opackets = 0;
		uint64_t obytes = 0;
		uint64_t odropped = 0;
	};

	cDataPlane* dataPlane;

	fragmentation::Fragmentation fragmentation_;
	dataplane::SlowWorker slow_;
	dregress_t dregress;

	std::mutex mutex;
	std::mutex balancer_mutex;
	std::mutex unrdup_mutex;
	std::mutex interfaces_ips_mutex;
	std::mutex vip_vport_proto_mutex;

	rte_mempool* mempool;
	bool use_kernel_interface;

	struct KniHandleBundle
	{
		dataplane::KernelInterfaceHandle forward;
		dataplane::KernelInterfaceHandle in_dump;
		dataplane::KernelInterfaceHandle out_dump;
		dataplane::KernelInterfaceHandle drop_dump;
	};

	struct KniPortData
	{
		std::string interface_name;
		tPortId kernel_port_id;
		rte_mbuf* mbufs[CONFIG_YADECAP_MBUFS_BURST_SIZE];
		uint16_t mbufs_count = 0;
	};

	void flush_kernel_interface(KniPortData& port_data, sKniStats& stats);
	void flush_kernel_interface(KniPortData& port_data);

	std::array<sKniStats, CONFIG_YADECAP_PORTS_SIZE> kernel_stats;
	std::array<KniPortData, CONFIG_YADECAP_PORTS_SIZE> kernel_interfaces;
	std::array<KniPortData, CONFIG_YADECAP_PORTS_SIZE> in_dump_kernel_interfaces;
	std::array<KniPortData, CONFIG_YADECAP_PORTS_SIZE> out_dump_kernel_interfaces;
	std::array<KniPortData, CONFIG_YADECAP_PORTS_SIZE> drop_dump_kernel_interfaces;

	common::slowworker::stats_t stats;
	common::idp::getErrors::response errors; ///< @todo: class errorsManager

public:
	cWorker* slowWorker;

protected:
	utils::StaticVector<dpdk::RingConn<rte_mbuf*>, YANET_CONFIG_NUMA_SIZE> to_gcs_;
	std::queue<std::tuple<rte_mbuf*,
	                      common::globalBase::tFlow>>
	        slowWorkerMbufs;
	std::mutex fw_state_multicast_acl_ids_mutex;
	std::map<common::ipv6_address_t, tAclId> fw_state_multicast_acl_ids;

	// provided by unrdup.cfg, used to clone some icmp packets to neighbor balancers, index is balancer_id
	std::vector<std::unordered_map<common::ip_address_t, std::unordered_set<common::ip_address_t>>> vip_to_balancers;
	// check presence prior to cloning
	std::vector<std::unordered_set<std::tuple<common::ip_address_t, std::optional<uint16_t>, uint8_t>>> vip_vport_proto;

	std::chrono::high_resolution_clock::time_point prevTimePointForSWRateLimiter;

	uint32_t icmpOutRemainder;
	uint32_t gc_step;
};
