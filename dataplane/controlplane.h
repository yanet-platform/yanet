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

#include "dataplane/dregress.h"
#include "dataplane/kernel_interface_handler.h"
#include "kernel_interface_handle.h"
#include "type.h"
#include "utils.h"

class cControlPlane ///< @todo: move to cDataPlane
{
protected:
	struct sKniStats
	{
		uint64_t ipackets = 0;
		uint64_t ibytes = 0;
		uint64_t idropped = 0;
		uint64_t opackets = 0;
		uint64_t obytes = 0;
		uint64_t odropped = 0;
	};

public:
	cControlPlane(cDataPlane* dataPlane);
	virtual ~cControlPlane() = default;

	eResult init(bool use_kernel_interface);
	void stop();
	void join();

	common::idp::updateGlobalBase::response updateGlobalBase(const common::idp::updateGlobalBase::request& request);
	eResult updateGlobalBaseBalancer(const common::idp::updateGlobalBaseBalancer::request& request);
	common::idp::getGlobalBase::response getGlobalBase(const common::idp::getGlobalBase::request& request);
	common::idp::getWorkerStats::response getWorkerStats(const common::idp::getWorkerStats::request& request);
	[[nodiscard]] common::slowworker::stats_t SlowWorkerStats() const;
	common::idp::getSlowWorkerStats::response SlowWorkerStatsResponse();
	eResult clearWorkerDumpRings();
	eResult flushDumpRing(const common::idp::flushDumpRing::request& request);
	common::idp::get_worker_gc_stats::response get_worker_gc_stats();
	common::idp::get_dregress_counters::response get_dregress_counters();
	common::idp::get_ports_stats::response get_ports_stats();
	common::idp::get_ports_stats_extended::response get_ports_stats_extended();
	common::idp::getControlPlanePortStats::response getControlPlanePortStats(const common::idp::getControlPlanePortStats::request& request);
	common::idp::getPortStatsEx::response getPortStatsEx();
	[[nodiscard]] common::idp::getFragmentationStats::response getFragmentationStats() const;
	[[nodiscard]] common::dregress::stats_t DregressStats() const;
	[[nodiscard]] std::optional<std::reference_wrapper<const dataplane::sKniStats>> KniStats(tPortId) const;
	[[nodiscard]] dataplane::hashtable_chain_spinlock_stats_t DregressConnectionsStats() const;
	[[nodiscard]] dregress::LimitsStats DregressLimitsStats() const;
	common::idp::getFWState::response getFWState();
	common::idp::getFWStateStats::response getFWStateStats();
	eResult clearFWState();
	[[nodiscard]] common::idp::getConfig::response getConfig() const;
	common::idp::getErrors::response getErrors();
	common::idp::getReport::response getReport();
	common::idp::lpm4LookupAddress::response lpm4LookupAddress(const common::idp::lpm4LookupAddress::request& request);
	common::idp::lpm6LookupAddress::response lpm6LookupAddress(const common::idp::lpm6LookupAddress::request& request);
	common::idp::limits::response limits();
	common::idp::samples::response samples();
	common::idp::hitcount_dump::response hitcount_dump();
	common::idp::balancer_connection::response balancer_connection(const common::idp::balancer_connection::request& request);
	common::idp::balancer_service_connections::response balancer_service_connections();
	common::idp::balancer_real_connections::response balancer_real_connections();
	eResult debug_latch_update(const common::idp::debug_latch_update::request& request);
	eResult unrdup_vip_to_balancers(const common::idp::unrdup_vip_to_balancers::request& request);
	eResult update_vip_vport_proto(const common::idp::update_vip_vport_proto::request& request);
	common::idp::version::response version();
	common::idp::nat64stateful_state::response nat64stateful_state(const common::idp::nat64stateful_state::request& request);
	common::idp::get_shm_info::response get_shm_info();
	common::idp::get_shm_tsc_info::response get_shm_tsc_info();
	eResult dump_physical_port(const common::idp::dump_physical_port::request& request);
	eResult balancer_state_clear();

	void switchBase();
	void switchGlobalBase();
	virtual void waitAllWorkers();

private:
	[[nodiscard]] const std::vector<cWorker*>& workers_vector() const;
	[[nodiscard]] const std::map<tCoreId, dataplane::SlowWorker*>& slow_workers() const;

	template<typename F>
	// @brief returns sum of results of applying F to all cWorker*s
	auto accumulateWorkerStats(F func) const
	{
		using R = std::invoke_result_t<F, cWorker*>;
		return std::accumulate(
		        workers_vector().begin(),
		        workers_vector().end(),
		        R{},
		        [func](R total, cWorker* worker) {
			        total += func(worker);
			        return total;
		        });
	}

	template<typename F>
	// @brief returns sum of results of applying F to all SlowWorker*s
	auto accumulateSlowWorkerStats(F func) const
	{
		using R = std::invoke_result_t<F, dataplane::SlowWorker*>;
		return std::accumulate(
		        slow_workers().begin(),
		        slow_workers().end(),
		        R{},
		        [&func](R total, const auto& pair) {
			        total += func(pair.second);
			        return total;
		        });
	}

protected:
	friend class cReport;
	friend class cDataPlane;
	friend class dataplane::globalBase::generation;
	friend class dregress_t;

	cDataPlane* dataPlane;

	std::mutex mutex;
	std::mutex balancer_mutex;

	bool use_kernel_interface;

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

	std::queue<std::tuple<rte_mbuf*,
	                      common::globalBase::tFlow>>
	        slowWorkerMbufs;

public:
	using VipToBalancers = std::vector<std::unordered_map<common::ip_address_t, std::unordered_set<common::ip_address_t>>>;
	utils::Sequential<VipToBalancers> vip_to_balancers;
	using VipVportProto = std::vector<std::unordered_set<std::tuple<common::ip_address_t, std::optional<uint16_t>, uint8_t>>>;
	// check presence prior to cloning
	utils::Sequential<VipVportProto> vip_vport_proto;
	using FwStateMulticastAclIds = std::map<common::ipv6_address_t, tAclId>;
	utils::Sequential<FwStateMulticastAclIds> fw_state_multicast_acl_ids;

protected:
	uint32_t gc_step;
};
