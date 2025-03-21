#pragma once

#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "common/result.h"
#include "common/sdpcommon.h"
#include "common/tsc_deltas.h"
#include "common/type.h"

#include "base.h"
#include "common.h"
#include "dump_rings.h"
#include "globalbase.h"
#include "samples.h"

namespace dataplane
{
template<dataplane::FlowDirection Direction>
struct ActionDispatcher;
}

namespace worker
{

template<unsigned int TSize = CONFIG_YADECAP_MBUFS_BURST_SIZE>
class tStack
{
public:
	tStack() = default;

	inline void insert(rte_mbuf** mbufs, unsigned int mbufsCount)
	{
		memcpy(&this->mbufs[this->mbufsCount], mbufs, mbufsCount * sizeof(rte_mbuf*));
		this->mbufsCount += mbufsCount;
	}

	inline void insert(rte_mbuf* mbuf)
	{
		mbufs[mbufsCount] = mbuf;
		mbufsCount++;
	}

	inline void clear()
	{
		mbufsCount = 0;
	}

	inline void copy_from(tStack& other)
	{
		insert(other.mbufs, other.mbufsCount);
	}

public:
	unsigned int mbufsCount{};
	rte_mbuf* mbufs[TSize];
};

}

class cWorker
{
	unsigned int MempoolSize() const;

public:
	cWorker(cDataPlane* dataPlane);
	~cWorker();

	eResult init(const tCoreId& coreId, const dataplane::base::permanently& basePermanently, const dataplane::base::generation& base);
	void start();

	static void FillMetadataWorkerCounters(common::sdp::MetadataWorker& metadata);
	void SetBufferForCounters(void* buffer, const common::sdp::MetadataWorker& metadata);

	[[nodiscard]] const dataplane::base::generation& current_base() const { return bases[localBaseId & 1]; }

protected:
	eResult sanityCheck();

	YANET_NEVER_INLINE void mainThread();

public:
	void preparePacket(rte_mbuf* mbuf); ///< @todo: inline

protected:
	constexpr static uint32_t translation_ignore = 0xFFFFFFFFu;
	inline void translation_ipv4_to_ipv6(rte_mbuf* mbuf, const ipv6_address_t& ipv6_source, const ipv6_address_t& ipv6_destination, const uint32_t port_source, const uint32_t port_destination, const uint32_t identifier);
	inline void translation_ipv6_to_ipv4(rte_mbuf* mbuf, const ipv4_address_t& ipv4_source, const ipv4_address_t& ipv4_destination, const uint32_t port_source, const uint32_t port_destination, const uint32_t identifier);

	inline void mark_ipv4_dscp(rte_mbuf* mbuf, const uint8_t dscp_flags);

	inline void handlePackets();

	inline void physicalPort_ingress_handle(const dpdk::Endpoint& rx_point);

	inline void physicalPort_egress_handle();

	inline void logicalPort_ingress_handle();
	inline void logicalPort_ingress_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);

	inline void logicalPort_egress_entry(rte_mbuf* mbuf);
	inline void logicalPort_egress_handle();

	inline void early_decap(rte_mbuf* mbuf);
	inline void after_early_decap_entry(rte_mbuf* mbuf);

	inline void acl_ingress_entry(rte_mbuf* mbuf);
	inline void acl_ingress_handle4();
	inline void acl_ingress_handle6();
	inline void acl_ingress_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);

	inline void tun64_ipv4_checked(rte_mbuf* mbuf);
	inline void tun64_ipv6_checked(rte_mbuf* mbuf);
	inline void tun64_ipv4_handle();
	inline void tun64_ipv6_handle();
	inline void tun64_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);

	inline void decap_entry_checked(rte_mbuf* mbuf);
	inline void decap_handle();
	inline void decap_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);
	inline bool decap_cut(rte_mbuf* mbuf);

	inline void route_entry(rte_mbuf* mbuf);
	inline void route_entry_local(rte_mbuf* mbuf);
	inline void route_handle4();
	inline void route_handle6();
	inline void route_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow, tAclId aclId);
	inline void route_nexthop(rte_mbuf* mbuf, const dataplane::globalBase::nexthop& nexthop);
	inline void route_tunnel_entry(rte_mbuf* mbuf);
	inline void route_tunnel_handle4();
	inline void route_tunnel_handle6();
	inline void route_tunnel_nexthop(rte_mbuf* mbuf, const dataplane::globalBase::nexthop_tunnel_t& nexthop);

	/// nat64stateful lan (ipv6)
	inline void nat64stateful_lan_entry(rte_mbuf* mbuf);
	inline void nat64stateful_lan_handle();
	inline void nat64stateful_lan_translation(rte_mbuf* mbuf, const dataplane::globalBase::nat64stateful_t& nat64stateful, const dataplane::globalBase::nat64stateful_lan_value& value);
	inline void nat64stateful_lan_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);

	/// nat64stateful wan (ipv4)
	inline void nat64stateful_wan_entry(rte_mbuf* mbuf);
	inline void nat64stateful_wan_handle();
	inline void nat64stateful_wan_translation(rte_mbuf* mbuf, const dataplane::globalBase::nat64stateful_wan_value& value);
	inline void nat64stateful_wan_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);

	/// nat64stateless lan (ipv6)
	inline void nat64stateless_ingress_entry_checked(rte_mbuf* mbuf);
	inline void nat64stateless_ingress_entry_icmp(rte_mbuf* mbuf);
	inline void nat64stateless_ingress_entry_fragmentation(rte_mbuf* mbuf);
	inline void nat64stateless_ingress_handle();
	inline void nat64stateless_ingress_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);
	inline void nat64stateless_ingress_translation(rte_mbuf* mbuf, const dataplane::globalBase::tNat64stateless& nat64stateless, const dataplane::globalBase::nat64stateless_translation_t& translation);

	/// nat64stateless wan (ipv4)
	inline void nat64stateless_egress_entry_checked(rte_mbuf* mbuf);
	inline void nat64stateless_egress_entry_icmp(rte_mbuf* mbuf);
	inline void nat64stateless_egress_entry_fragmentation(rte_mbuf* mbuf);
	inline void nat64stateless_egress_entry_farm(rte_mbuf* mbuf);
	inline void nat64stateless_egress_handle();
	inline void nat64stateless_egress_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);
	inline void nat64stateless_egress_translation(rte_mbuf* mbuf, const dataplane::globalBase::nat64stateless_translation_t& translation);

	/// nat46clat lan (ipv4)
	inline void nat46clat_lan_entry(rte_mbuf* mbuf);
	inline void nat46clat_lan_handle();
	inline void nat46clat_lan_translation(rte_mbuf* mbuf, const dataplane::globalBase::nat46clat_t& nat46clat);
	inline void nat46clat_lan_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);

	/// nat46clat wan (ipv6)
	inline void nat46clat_wan_entry(rte_mbuf* mbuf);
	inline void nat46clat_wan_handle();
	inline void nat46clat_wan_translation(rte_mbuf* mbuf, const dataplane::globalBase::nat46clat_t& nat46clat);
	inline void nat46clat_wan_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);

	inline void balancer_entry(rte_mbuf* mbuf);
	inline void balancer_icmp_reply_entry(rte_mbuf* mbuf);
	inline void balancer_icmp_forward_entry(rte_mbuf* mbuf);
	inline void balancer_fragment_entry(rte_mbuf* mbuf);
	inline void balancer_handle();
	inline void balancer_tunnel(rte_mbuf* mbuf, const dataplane::globalBase::balancer_service_t& service, const dataplane::globalBase::balancer_real_t& real, const tCounterId& real_counter_id);
	inline void balancer_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);
	inline void balancer_icmp_reply_handle();
	inline void balancer_icmp_forward_handle();
	inline void balancer_ipv6_source(rte_ipv6_hdr* header, const ipv6_address_t& balancer, const dataplane::globalBase::balancer_service_t& service, const rte_ipv4_hdr* ipv4HeaderInner, const rte_ipv6_hdr* ipv6HeaderInner);
	inline void balancer_ipv4_source(rte_ipv4_hdr* header, const ipv4_address_t& balancer, const dataplane::globalBase::balancer_service_t& service);
	inline void balancer_touch_state(rte_mbuf* mbuf, dataplane::metadata* metadata, dataplane::globalBase::balancer_state_value_t* value);

	/// fw state
	using FlowFromState = std::optional<common::globalBase::tFlow>;
	inline FlowFromState acl_checkstate(rte_mbuf* mbuf);
	inline FlowFromState acl_checkstate(rte_mbuf* mbuf, dataplane::globalBase::fw_state_value_t* value, dataplane::spinlock_nonrecursive_t* locker);
	inline FlowFromState acl_egress_checkstate(rte_mbuf* mbuf);
	inline FlowFromState acl_egress_checkstate(rte_mbuf* mbuf, dataplane::globalBase::fw_state_value_t* value, dataplane::spinlock_nonrecursive_t* locker);
	inline void acl_create_state(rte_mbuf* mbuf, tAclId aclId, const common::globalBase::tFlow& flow, std::optional<uint32_t> timeout);
	inline void acl_state_emit(tAclId aclId, const dataplane::globalBase::fw_state_sync_frame_t& frame);

	inline void acl_egress_entry(rte_mbuf* mbuf, tAclId aclId);
	inline void acl_egress_handle4();
	inline void acl_egress_handle6();
	inline void acl_egress_flow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);
	inline void acl_log(rte_mbuf* mbuf, const common::globalBase::tFlow& flow, tAclId aclId);
	inline void acl_touch_state(rte_mbuf* mbuf, dataplane::metadata* metadata, dataplane::globalBase::fw_state_value_t* value);
	inline void acl_fill_state_timeout(rte_mbuf* mbuf, dataplane::metadata* metadata, dataplane::globalBase::fw_state_value_t* value, std::optional<uint32_t> timeout);

	inline void dregress_entry(rte_mbuf* mbuf);

	inline void controlPlane(rte_mbuf* mbuf);
	inline void controlPlane_handle();

	inline void drop(rte_mbuf* mbuf);

	inline void toFreePackets_handle();

	inline void slowWorker_entry_highPriority(rte_mbuf* mbuf, const common::globalBase::eFlowType& flowType); ///< @todo: DELETE and OPT
	inline void slowWorker_entry_normalPriority(rte_mbuf* mbuf, const common::globalBase::eFlowType& flowType); ///< @todo: DELETE and OPT
	inline void slowWorker_entry_lowPriority(rte_mbuf* mbuf); ///< @todo: DELETE and OPT

	inline uint32_t get_tcp_state_timeout(uint8_t flags, const dataplane::globalBase::state_timeout_config_t& state_timeout_config);
	inline uint32_t get_state_timeout(rte_mbuf* mbuf, dataplane::metadata* metadata, const dataplane::globalBase::state_timeout_config_t& state_timeout_config);

	inline void populate_hitcount_map(const std::string& id, rte_mbuf* mbuf);
	inline bool is_expired_ttl(rte_mbuf* mbuf);

protected:
	/// @todo: move to slow_worker_t
public:
	YANET_NEVER_INLINE void slowWorkerBeforeHandlePackets();
	YANET_NEVER_INLINE void slowWorkerHandlePackets();

	YANET_NEVER_INLINE void slowWorkerHandleFragment(rte_mbuf* mbuf);
	YANET_NEVER_INLINE void slowWorkerFarmHandleFragment(rte_mbuf* mbuf);

	YANET_NEVER_INLINE void slowWorkerAfterHandlePackets();

	YANET_NEVER_INLINE void slowWorkerFlow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);
	YANET_NEVER_INLINE void slowWorkerTranslation(rte_mbuf* mbuf, const dataplane::globalBase::tNat64stateless& nat64stateless, const dataplane::globalBase::nat64stateless_translation_t& translation, bool direction); /** true: ingress, false: egress */
	const dataplane::base::generation& CurrentBase() { return bases[localBaseId & 1]; }
	void IncrementCounter(common::globalBase::static_counter_type type) { counters[(uint32_t)type]++; }
	[[nodiscard]] uint32_t CurrentTime() const { return basePermanently.globalBaseAtomic->currentTime; }

	friend class cDataPlane;
	friend class cReport;
	friend class cControlPlane;
	friend class dregress_t;
	friend class worker_gc_t;
	friend class dataplane::globalBase::generation;
	friend struct dataplane::ActionDispatcher<dataplane::FlowDirection::Ingress>;
	friend struct dataplane::ActionDispatcher<dataplane::FlowDirection::Egress>;

	cDataPlane* dataPlane;
	tCoreId coreId;
	tSocketId socketId;

	rte_mempool* mempool;

protected:
	/// variables above are not needed for mainThread()
	YADECAP_CACHE_ALIGNED(align1);

	uint64_t iteration;
	uint32_t currentBaseId;

	YADECAP_CACHE_ALIGNED(align2);

	uint32_t localBaseId;

	dataplane::base::permanently basePermanently;

	uint32_t translation_packet_id;

	uint32_t hashes[CONFIG_YADECAP_MBUFS_BURST_SIZE];

	union
	{
		struct
		{
			uint32_t ipv4[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			ipv6_address_t ipv6[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			tVrfId vrfs[CONFIG_YADECAP_MBUFS_BURST_SIZE];
		} route_keys;
		dataplane::globalBase::tun64mapping_key_t tun64_keys[CONFIG_YADECAP_MBUFS_BURST_SIZE];
		dataplane::globalBase::nat64stateful_lan_key nat64stateful_lan_keys[CONFIG_YADECAP_MBUFS_BURST_SIZE];
		dataplane::globalBase::nat64stateful_wan_key nat64stateful_wan_keys[CONFIG_YADECAP_MBUFS_BURST_SIZE];
		dataplane::globalBase::balancer_state_key_t balancer_keys[CONFIG_YADECAP_MBUFS_BURST_SIZE];
		struct
		{
			ipv4_address_t ipv4_sources[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			ipv4_address_t ipv4_destinations[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			ipv6_address_t ipv6_sources[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			ipv6_address_t ipv6_destinations[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			common::acl::transport_key_t transports[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			common::acl::total_key_t totals[CONFIG_YADECAP_MBUFS_BURST_SIZE];
		} key_acl;
	};

	union
	{
		uint32_t route_ipv4_values[CONFIG_YADECAP_MBUFS_BURST_SIZE];
		uint32_t route_ipv6_values[CONFIG_YADECAP_MBUFS_BURST_SIZE];

		dataplane::globalBase::tun64mapping_t* tun64_values[CONFIG_YADECAP_MBUFS_BURST_SIZE];

		struct
		{
			tAclGroupId ipv4_sources[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			tAclGroupId ipv4_destinations[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			tAclGroupId ipv6_sources[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			tAclGroupId ipv6_destinations[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			tAclGroupId networks[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			tAclGroupId transports[CONFIG_YADECAP_MBUFS_BURST_SIZE];
			tAclGroupId totals[CONFIG_YADECAP_MBUFS_BURST_SIZE];
		} value_acl;
	};

	worker::tStack<> stack;
	worker::tStack<> physicalPort_stack[CONFIG_YADECAP_PORTS_SIZE];
	worker::tStack<> logicalPort_ingress_stack;
	worker::tStack<> logicalPort_egress_stack;
	worker::tStack<> acl_ingress_stack4;
	worker::tStack<> acl_ingress_stack6;
	worker::tStack<> tun64_stack4;
	worker::tStack<> tun64_stack6;
	worker::tStack<> decap_stack;
	worker::tStack<> route_stack4;
	worker::tStack<> route_stack6;
	worker::tStack<> route_tunnel_stack4;
	worker::tStack<> route_tunnel_stack6;
	worker::tStack<> vrf_route_stack4;
	worker::tStack<> vrf_route_stack6;
	worker::tStack<> vrf_route_tunnel_stack4;
	worker::tStack<> vrf_route_tunnel_stack6;
	worker::tStack<> nat64stateful_lan_stack;
	worker::tStack<> nat64stateful_wan_stack;
	worker::tStack<> nat64stateless_ingress_stack;
	worker::tStack<> nat64stateless_egress_stack;
	worker::tStack<> nat46clat_lan_stack;
	worker::tStack<> nat46clat_wan_stack;
	worker::tStack<> balancer_stack;
	worker::tStack<> balancer_icmp_reply_stack;
	worker::tStack<> balancer_icmp_forward_stack;
	worker::tStack<> acl_egress_stack4;
	worker::tStack<> acl_egress_stack6;
	worker::tStack<128> controlPlane_stack; ///< to_linux + ingress_state + egress_state + nap

	worker::tStack<> after_early_decap_stack4;
	worker::tStack<> after_early_decap_stack6;

public:
	rte_ring* ring_highPriority;
	rte_ring* ring_normalPriority;
	rte_ring* ring_lowPriority;
	dataplane::perf::tsc_deltas* tsc_deltas;
	rte_ring* ring_toFreePackets;
	common::worker::stats::common& Stats() { return *stats; }

protected:
	rte_ring* ring_log;

	common::worker::stats::common* stats;
	common::worker::stats::port* statsPorts; // CONFIG_YADECAP_PORTS_SIZE
	uint64_t* bursts; // CONFIG_YADECAP_MBUFS_BURST_SIZE + 1
	uint64_t* counters; // YANET_CONFIG_COUNTERS_SIZE
	uint64_t* aclCounters; // YANET_CONFIG_ACL_COUNTERS_SIZE
	uint64_t roundRobinCounter;

	// will decrease with each new packet sent to slow worker, replenishes each N mseconds
	int32_t packetsToSWNPRemainder;

	using DumpRingBasePtr = std::unique_ptr<dumprings::RingBase>;
	std::array<DumpRingBasePtr, YANET_CONFIG_SHARED_RINGS_NUMBER> dump_rings;

	samples::Sampler sampler;

	dataplane::globalBase::state_timeout_config_t acl_state_config;
	dataplane::globalBase::state_timeout_config_t balancer_state_config;

public:
	/// use this table for pass resolve neighbor MAC
	dataplane::hashtable_mod_spinlock<dataplane::neighbor::key,
	                                  uint32_t, ///< stub
	                                  32,
	                                  8>
	        neighbor_resolve;

protected:
	YADECAP_CACHE_ALIGNED(align3);

	dataplane::base::generation bases[2];
};
