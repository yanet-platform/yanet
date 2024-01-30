#pragma once

#include <mutex>

#include "common/btree.h"
#include "common/idp.h"
#include "common/type.h"

#include "hashtable.h"
#include "type.h"

namespace dregress
{

struct connection_key_t
{
	ipv6_address_t source;
	ipv6_address_t destination;
	uint16_t port_source;
	uint16_t port_destination;
};

struct connection_value_t
{
	uint32_t loss_count;
	uint32_t ack_count;
	ipv6_address_t nexthop;
	uint32_t label;
	uint32_t community;
	ipv6_address_t prefix_address;
	uint32_t peer_as;
	uint32_t origin_as;
	uint16_t timestamp;
	uint8_t flags;
	uint8_t prefix_mask;
};

using direction_t = std::tuple<common::ip_prefix_t, ///< prefix
                               common::ip_address_t, ///< nexthop
                               bool, ///< is_best
                               uint32_t, ///< label
                               common::community_t,
                               uint32_t, ///< peer_as
                               uint32_t>; ///< origin_as

}

class dregress_t
{
public:
	dregress_t(cControlPlane* controlplane, cDataPlane* dataplane);
	~dregress_t();

	void insert(rte_mbuf* mbuf);
	void handle();

	std::optional<dregress::direction_t> lookup(rte_mbuf* mbuf);
	bool tcp_parse(rte_mbuf* mbuf, uint16_t& rtt, uint32_t& loss_count, uint32_t& ack_count);

	common::idp::get_dregress_counters::response get_dregress_counters();
	void limits(common::idp::limits::response& response);

public:
	cControlPlane* controlplane;
	cDataPlane* dataplane;

	constexpr static double median_multiplier = 0.01;

	common::dregress::stats_t stats;
	dataplane::hashtable_chain_spinlock_t<dregress::connection_key_t,
	                                      dregress::connection_value_t,
	                                      YANET_CONFIG_DREGRESS_HT_SIZE,
	                                      YANET_CONFIG_DREGRESS_HT_EXTENDED_SIZE,
	                                      4,
	                                      4>* connections;

	std::mutex prefixes_mutex;
	std::set<common::ipv4_prefix_t> local_prefixes_v4; ///< @todo: set<ip_prefix_t>
	std::set<common::ipv6_prefix_t> local_prefixes_v6;
	common::btree<common::ip_address_t, uint32_t> prefixes;
	std::map<uint32_t, std::set<common::dregress::value_t>> values;

	std::mutex counters_mutex;
	common::dregress::counters_t counters_v4;
	common::dregress::counters_t counters_v6;

	uint32_t gc_step;
};
