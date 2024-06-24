#pragma once

#include <mutex>
#include <queue>

#include "base.h"
#include "common.h"
#include "hashtable.h"
#include "utils.h"

#include "common/generation.h"
#include "common/idp.h"
#include "common/static_vector.h"
#include "hashtable.h"

class worker_gc_t
{
public:
	using PortToSocketArray = std::array<tSocketId, CONFIG_YADECAP_PORTS_SIZE>;
	using SamplersVector = utils::StaticVector<samples::Sampler*, YANET_CONFIG_MAX_SAMPLED_WORKERS_PER_GC>;
	worker_gc_t(const ConfigValues& cfg, const PortToSocketArray& pts, SamplersVector&& samplers);
	~worker_gc_t();

	eResult init(const tCoreId& core_id, const tSocketId& socket_id, const dataplane::base::permanently& base_permanently, const dataplane::base::generation& base);
	void start(pthread_barrier_t* runBarrier);

	void run_on_this_thread(const std::function<bool()>& callback);
	void nat64stateful_state(const common::idp::nat64stateful_state::request& request, common::idp::nat64stateful_state::response& response);
	void balancer_state_clear();

	void limits(common::idp::limits::response& response) const;

	void fillStatsNamesToAddrsTable(std::unordered_map<std::string, uint64_t*>& table);

protected:
	YANET_INLINE_NEVER void thread();
	void handle();
	void handle_nat64stateful_gc();
	void handle_balancer_gc();
	void handle_acl_gc();
	void handle_acl_sync();
	void handle_callbacks();
	void handle_free_mbuf();

	bool is_timeout(const uint32_t timestamp, const uint32_t timeout);
	void correct_timestamp(uint16_t& timestamp, const uint16_t last_seen_max = YANET_CONFIG_STATE_TIMEOUT_MAX);
	uint16_t calc_last_seen(const uint16_t timestamp);

	void nat64stateful_remove_state(const dataplane::globalBase::nat64stateful_lan_key& lan_key, const dataplane::globalBase::nat64stateful_wan_key& wan_key);

	void SendToSlowWorker(rte_mbuf* mbuf);

	void handle_samples();

public:
	[[nodiscard]] std::optional<dpdk::RingConn<rte_mbuf*>> RegisterSlowWorker(const std::string& name,
	                                                                          unsigned int capacity,
	                                                                          unsigned int capacity_to_free,
	                                                                          samples::Sampler* sampler);

	rte_mempool* mempool;
	tCoreId core_id;
	tSocketId socket_id;
	uint64_t iteration;
	uint32_t current_base_id;
	uint32_t local_base_id;
	dataplane::base::permanently base_permanently;
	common::worker_gc::stats_t stats;
	dataplane::base::generation bases[2];

	YADECAP_CACHE_ALIGNED(align1);

	utils::StaticVector<dpdk::Ring<rte_mbuf*>, YANET_CONFIG_MAX_SLOW_WORKERS_PER_GC> toSlowWorkers_;
	utils::StaticVector<dpdk::Ring<rte_mbuf*>, YANET_CONFIG_MAX_SLOW_WORKERS_PER_GC> toFree_;
	utils::RoundRobinIterator<decltype(toSlowWorkers_)::iterator> toSlowWorker_;

	PortToSocketArray port_id_to_socket_id;

	YADECAP_CACHE_ALIGNED(align2);

	SamplersVector samplers_;
	std::set<common::idp::samples::sample_t> samples;
	uint32_t samples_current_base_id;
	std::mutex samples_mutex;

	std::mutex callbacks_mutex;
	unsigned int callback_id;
	std::map<unsigned int, std::function<bool()>> callbacks;

	std::map<unsigned int, std::function<bool()>> callbacks_current;

	std::queue<std::tuple<dataplane::globalBase::fw_state_sync_frame_t, tAclId>> fw_state_sync_events;
	/// Copy of dynamic fw states (both IPv6 and IPv4).
	///
	/// Must be updated STRICTLY during GC.
	std::mutex fw_state_mutex;
	std::vector<std::tuple<common::idp::getFWState::key_t, common::idp::getFWState::value_t>> fw_state_insert_stack;
	std::vector<common::idp::getFWState::key_t> fw_state_remove_stack;
	std::map<common::idp::getFWState::key_t, common::idp::getFWState::value_t> fw_state;

	generation_manager<common::idp::balancer_service_connections::connections> balancer_service_connections;
	generation_manager<common::idp::balancer_real_connections::connections> balancer_real_connections;
	generation_manager<dataplane::hashtable_mod_spinlock_stats> balancer_state_stats;

	uint64_t counters[YANET_CONFIG_COUNTERS_SIZE];

	uint32_t current_time;
	dataplane::hashtable_gc_t nat64stateful_lan_state_gc;
	dataplane::hashtable_gc_t nat64stateful_wan_state_gc;
	dataplane::hashtable_gc_t fw4_state_gc;
	dataplane::hashtable_gc_t fw6_state_gc;
	uint32_t gc_step;
	uint32_t sample_gc_step;
};
