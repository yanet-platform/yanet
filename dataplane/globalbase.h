#pragma once

#include <memory>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include "common/idp.h"
#include "common/result.h"
#include "common/tsc_deltas.h"

#include "common.h"
#include "flat.h"
#include "hashtable.h"
#include "lpm.h"
#include "type.h"
#include "updater.h"

/// @todo: move
#define YADECAP_GB_DSCP_FLAG_MARK ((uint8_t)1)
#define YADECAP_GB_DSCP_FLAG_ALWAYS_MARK ((uint8_t)2)

//

namespace dataplane::globalBase
{

namespace acl
{
using ipv4_states_ht = hashtable_mod_spinlock_dynamic<fw4_state_key_t, fw_state_value_t, 16>;
using ipv6_states_ht = hashtable_mod_spinlock_dynamic<fw6_state_key_t, fw_state_value_t, 16>;

struct transport_layer_t
{
	flat<uint8_t> protocol;

	struct
	{
		flat<uint16_t> source;
		flat<uint16_t> destination;
		flat<uint8_t> flags;
	} tcp;

	struct
	{
		flat<uint16_t> source;
		flat<uint16_t> destination;
	} udp;

	struct
	{
		/** @todo:
		        flat<uint8_t> type;
		        flat<uint8_t> code;
		        */
		flat<uint16_t> type_code;
		flat<uint16_t> identifier;
	} icmp;
};

/// @todo: move to config
using network_ipv4_source = dataplane::updater_lpm4_24bit_8bit_id32;
using network_ipv4_destination = dataplane::updater_lpm4_24bit_8bit_id32;
using network_ipv6_source = YANET_CONFIG_ACL_NETWORK_LPM6_TYPE;
using network_ipv6_destination_ht = dataplane::updater_hashtable_mod_id32<ipv6_address_t, 1>;
using network_ipv6_destination = YANET_CONFIG_ACL_NETWORK_LPM6_TYPE;
using network_table = dataplane::updater_dynamic_table<uint32_t>;
using transport_layers = dataplane::updater_array<transport_layer_t>;
using transport_table = dataplane::updater_hashtable_mod_id32<common::acl::transport_key_t, 16>;
using total_table = dataplane::updater_hashtable_mod_id32<common::acl::total_key_t, 16>;
using values = dataplane::updater_array<common::Actions>;
}

namespace nat64stateful
{
using lan_ht = hashtable_mod_spinlock_dynamic<nat64stateful_lan_key, nat64stateful_lan_value, 16>;
using wan_ht = hashtable_mod_spinlock_dynamic<nat64stateful_wan_key, nat64stateful_wan_value, 16>;
}

namespace balancer
{
using state_ht = hashtable_mod_spinlock_dynamic<balancer_state_key_t, balancer_state_value_t, 16>;
}

class atomic
{
public:
	atomic(cDataPlane* dataPlane, const tSocketId& socketId);
	~atomic() = default;

public: ///< @todo
	cDataPlane* dataPlane;
	tSocketId socketId;

	struct
	{
		acl::ipv4_states_ht::updater fw4_state;
		acl::ipv6_states_ht::updater fw6_state;
		nat64stateful::lan_ht::updater nat64stateful_lan_state;
		nat64stateful::wan_ht::updater nat64stateful_wan_state;
		balancer::state_ht::updater balancer_state;
	} updater;

	hashtable_gc_t balancer_state_gc;

	uint64_t counter_shifts[YANET_CONFIG_COUNTERS_SIZE];
	uint64_t gc_counter_shifts[YANET_CONFIG_COUNTERS_SIZE];

	/// variables above are not needed for cWorker::mainThread()
	YADECAP_CACHE_ALIGNED(align11);
	void* nap[1];
	YADECAP_CACHE_ALIGNED(align12);

	uint32_t currentTime;
	uint8_t physicalPort_flags[CONFIG_YADECAP_PORTS_SIZE];

	YADECAP_CACHE_ALIGNED(align2);

	fw_state_config_t fw_state_config;
	acl::ipv4_states_ht* fw4_state;
	acl::ipv6_states_ht* fw6_state;
	nat64stateful::lan_ht* nat64stateful_lan_state;
	nat64stateful::wan_ht* nat64stateful_wan_state;
	balancer::state_ht* balancer_state;

	bool tsc_active_state;
};

//

class generation
{
public:
	generation(cDataPlane* dataPlane, const tSocketId& socketId);
	~generation() = default;

public:
	eResult init();
	eResult update(const common::idp::updateGlobalBase::request& request);
	eResult updateBalancer(const common::idp::updateGlobalBaseBalancer::request& request);
	eResult get(const common::idp::getGlobalBase::request& request, common::idp::getGlobalBase::globalBase& globalBaseResponse) const;

protected:
	eResult clear();
	eResult updateLogicalPort(const common::idp::updateGlobalBase::updateLogicalPort::request& request);
	eResult updateDecap(const common::idp::updateGlobalBase::updateDecap::request& request);
	eResult updateDregress(const common::idp::updateGlobalBase::updateDregress::request& request);
	eResult update_route(const common::idp::updateGlobalBase::update_route::request& request);
	eResult updateInterface(const common::idp::updateGlobalBase::updateInterface::request& request);
	eResult nat64stateful_update(const common::idp::updateGlobalBase::nat64stateful_update::request& request);
	eResult nat64stateful_pool_update(const common::idp::updateGlobalBase::nat64stateful_pool_update::request& request);
	eResult updateNat64stateless(const common::idp::updateGlobalBase::updateNat64stateless::request& request);
	eResult updateNat64statelessTranslation(const common::idp::updateGlobalBase::updateNat64statelessTranslation::request& request);
	eResult nat46clat_update(const common::idp::updateGlobalBase::nat46clat_update::request& request);
	eResult update_balancer(const common::idp::updateGlobalBase::update_balancer::request& request);
	eResult update_balancer_services(const common::idp::updateGlobalBase::update_balancer_services::request& request);
	eResult update_balancer_unordered_real(const common::idp::updateGlobalBaseBalancer::update_balancer_unordered_real::request& request);
	eResult route_lpm_update(const common::idp::updateGlobalBase::route_lpm_update::request& request);
	eResult route_value_update(const common::idp::updateGlobalBase::route_value_update::request& request);
	eResult route_tunnel_lpm_update(const common::idp::updateGlobalBase::route_tunnel_lpm_update::request& request);
	eResult route_tunnel_weight_update(const common::idp::updateGlobalBase::route_tunnel_weight_update::request& request);
	eResult route_tunnel_value_update(const common::idp::updateGlobalBase::route_tunnel_value_update::request& request);
	eResult update_early_decap_flags(const common::idp::updateGlobalBase::update_early_decap_flags::request& request);
	eResult acl_network_ipv4_source(const common::idp::updateGlobalBase::acl_network_ipv4_source::request& request);
	eResult acl_network_ipv4_destination(const common::idp::updateGlobalBase::acl_network_ipv4_destination::request& request);
	eResult acl_network_ipv6_source(const common::idp::updateGlobalBase::acl_network_ipv6_source::request& request);
	eResult acl_network_ipv6_destination_ht(const common::idp::updateGlobalBase::acl_network_ipv6_destination_ht::request& request);
	eResult acl_network_ipv6_destination(const common::idp::updateGlobalBase::acl_network_ipv6_destination::request& request);
	eResult acl_network_table(const common::idp::updateGlobalBase::acl_network_table::request& request);
	eResult acl_network_flags(const common::idp::updateGlobalBase::acl_network_flags::request& request);
	eResult acl_transport_layers(const common::idp::updateGlobalBase::acl_transport_layers::request& request);
	eResult acl_transport_table(const common::idp::updateGlobalBase::acl_transport_table::request& request);
	eResult acl_total_table(const common::idp::updateGlobalBase::acl_total_table::request& request);
	eResult acl_values(const common::idp::updateGlobalBase::acl_values::request& request);
	eResult dump_tags_ids(const common::idp::updateGlobalBase::dump_tags_ids::request& request);
	eResult dregress_prefix_update(const common::idp::updateGlobalBase::dregress_prefix_update::request& request);
	eResult dregress_prefix_remove(const common::idp::updateGlobalBase::dregress_prefix_remove::request& request);
	eResult dregress_prefix_clear();
	eResult dregress_local_prefix_update(const common::idp::updateGlobalBase::dregress_local_prefix_update::request& request);
	eResult dregress_value_update(const common::idp::updateGlobalBase::dregress_value_update::request& request);
	eResult fwstate_synchronization_update(const common::idp::updateGlobalBase::fwstate_synchronization_update::request& request);
	eResult tun64_update(const common::idp::updateGlobalBase::tun64_update::request& request);
	eResult tun64mappings_update(const common::idp::updateGlobalBase::tun64mappings_update::request& request);
	eResult tsc_state_update(const common::idp::updateGlobalBase::tsc_state_update::request& request);
	eResult tscs_base_value_update(const common::idp::updateGlobalBase::tscs_base_value_update::request& request);

	void evaluate_service_ring();
	inline uint64_t count_real_connections(uint32_t counter_id);

public: ///< @todo
	cDataPlane* dataPlane;
	tSocketId socketId;

	struct
	{
		struct
		{
			std::unique_ptr<acl::network_ipv4_source> network_ipv4_source;
			std::unique_ptr<acl::network_ipv4_destination> network_ipv4_destination;
			std::unique_ptr<acl::network_ipv6_source> network_ipv6_source;
			std::unique_ptr<acl::network_ipv6_destination_ht> network_ipv6_destination_ht;
			std::unique_ptr<acl::network_ipv6_destination> network_ipv6_destination;
			std::unique_ptr<acl::network_table> network_table;
			std::unique_ptr<acl::transport_layers> transport_layers;
			std::unique_ptr<acl::transport_table> transport_table;
			std::unique_ptr<acl::total_table> total_table;
			std::unique_ptr<acl::values> values;
		} acl;

		std::unique_ptr<updater_lpm4_24bit_8bit> route_lpm4;
		std::unique_ptr<updater_lpm6_8x16bit> route_lpm6;
		std::unique_ptr<updater_lpm4_24bit_8bit> route_tunnel_lpm4;
		std::unique_ptr<updater_lpm6_8x16bit> route_tunnel_lpm6;
	} updater;

	/// variables above are not needed for cWorker::mainThread()
	YADECAP_CACHE_ALIGNED(align11);
	void* nap[1];
	YADECAP_CACHE_ALIGNED(align12);

	tLogicalPort logicalPorts[CONFIG_YADECAP_LOGICALPORTS_SIZE];
	tDecap decaps[CONFIG_YADECAP_DECAPS_SIZE];
	route_t routes[CONFIG_YADECAP_ROUTES_SIZE];
	tInterface interfaces[CONFIG_YADECAP_INTERFACES_SIZE];
	nat64stateful_t nat64statefuls[YANET_CONFIG_NAT64STATEFULS_SIZE];
	tNat64stateless nat64statelesses[CONFIG_YADECAP_NAT64STATELESSES_SIZE];
	nat46clat_t nat46clats[YANET_CONFIG_NAT46CLATS_SIZE];
	balancer_t balancers[YANET_CONFIG_BALANCERS_SIZE];
	dregress_t dregresses[CONFIG_YADECAP_DREGRESS_SIZE]; ///< @todo: slow global base
	fw_state_sync_config_t fw_state_sync_configs[CONFIG_YADECAP_ACLS_SIZE];
	tun64_t tun64tunnels[CONFIG_YADECAP_TUN64_SIZE];

	uint8_t decap_enabled;
	uint8_t nat64stateful_enabled;
	uint8_t nat64stateless_enabled;
	uint8_t nat46clat_enabled;
	uint8_t balancer_enabled;
	uint8_t acl_egress_enabled;
	uint8_t sampler_enabled;
	uint8_t tun64_enabled;
	uint8_t early_decap_enabled;

	uint32_t serial;

	YADECAP_CACHE_ALIGNED(align2);

	lpm4_24bit_8bit_atomic* route_lpm4;
	lpm6_8x16bit_atomic* route_lpm6;
	route_value_t route_values[YANET_CONFIG_ROUTE_VALUES_SIZE];

	YADECAP_CACHE_ALIGNED(align3);

	lpm4_24bit_8bit_atomic* route_tunnel_lpm4;
	lpm6_8x16bit_atomic* route_tunnel_lpm6;
	uint8_t route_tunnel_weights[YANET_CONFIG_ROUTE_TUNNEL_WEIGHTS_SIZE];
	route_tunnel_value_t route_tunnel_values[YANET_CONFIG_ROUTE_TUNNEL_VALUES_SIZE];
	ipv4_address_t nat64stateful_pool[YANET_CONFIG_NAT64STATEFUL_POOL_SIZE];

	static_assert(YANET_CONFIG_ROUTE_TUNNEL_ECMP_SIZE <= 0xFF, "invalid YANET_CONFIG_ROUTE_TUNNEL_ECMP_SIZE");

	YADECAP_CACHE_ALIGNED(align4);

	struct
	{
		struct
		{
			struct
			{
				acl::network_ipv4_source::object_type* source;
				acl::network_ipv4_destination::object_type* destination;
			} ipv4;

			struct
			{
				acl::network_ipv6_source::object_type* source;
				acl::network_ipv6_destination_ht::object_type* destination_ht;
				acl::network_ipv6_destination::object_type* destination;
			} ipv6;
		} network;

		acl::network_table::object_type* network_table;
		flat<uint8_t> network_flags;
		uint32_t transport_layers_mask;
		acl::transport_layers::object_type* transport_layers;

		acl::transport_table::object_type* transport_table;
		acl::total_table::object_type* total_table;
		acl::values::object_type* values;
	} acl;

	YADECAP_CACHE_ALIGNED(align5);

	hashtable_chain_t<tun64mapping_key_t,
	                  tun64mapping_t,
	                  CONFIG_YADECAP_TUN64_HT_SIZE,
	                  CONFIG_YADECAP_TUN64_HT_EXTENDED_SIZE,
	                  4,
	                  4>
	        tun64mappingsTable;

	nat64stateless_translation_t nat64statelessTranslations[CONFIG_YADECAP_NAT64STATELESS_TRANSLATIONS_SIZE];
	uint32_t balancer_services_count;
	uint32_t balancer_active_services[YANET_CONFIG_BALANCER_SERVICES_SIZE];
	balancer_service_t balancer_services[YANET_CONFIG_BALANCER_SERVICES_SIZE];
	balancer_real_t balancer_reals[YANET_CONFIG_BALANCER_REALS_SIZE];
	balancer_real_id_t balancer_service_reals[YANET_CONFIG_BALANCER_REALS_SIZE];

	balancer_real_state_t balancer_real_states[YANET_CONFIG_BALANCER_REALS_SIZE];
	balancer_service_ring_t balancer_service_ring;

	int64_t dump_id_to_tag[YANET_CONFIG_DUMP_ID_TO_TAG_SIZE];

	bool tscs_active;
	dataplane::perf::tsc_base_values tsc_base_values;
};

}
