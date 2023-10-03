#pragma once

#include "type.h"
#include "module.h"
#include "rib.h"
#include "counter.h"
#include "base.h"

#include "common/idataplane.h"
#include "common/btree.h"
#include "common/weight.h"
#include "common/refarray.h"
#include "common/generation.h"

namespace route
{

using destination_t = std::variant<std::set<std::tuple<ip_address_t,
                                                       std::vector<uint32_t>>>,
                                   uint32_t>; ///< virtual_port_id

using value_key_t = std::tuple<std::tuple<std::string, ///< vrf
                                          uint32_t>, ///< priority
                               route::destination_t,
                               ip_prefix_t>; ///< fallback

using value_interface_t = std::tuple<ip_address_t,
                                     tInterfaceId,
                                     std::string,
                                     std::vector<uint32_t>>;

using lookup_t = std::tuple<ip_address_t, ///< nexthop
                            std::string,
                            std::vector<uint32_t>>; ///< labels

using tunnel_destination_interface_t = std::set<
                                           std::tuple<
                                               ip_address_t, ///< nexthop
                                               uint32_t, ///< label
                                               uint32_t, ///< peer_id
                                               uint32_t, ///< origin_as
                                               uint32_t>>; ///< weight

using tunnel_destination_legacy_t = std::set<ip_address_t>; ///< nexthop

using tunnel_destination_default_t = std::tuple<>;

using tunnel_destination_t = std::variant<
                                 tunnel_destination_interface_t,
                                 tunnel_destination_legacy_t,
                                 tunnel_destination_default_t,
                                 uint32_t>; ///< virtual_port_id

using tunnel_value_key_t = std::tuple<std::tuple<std::string, ///< vrf
                                                 uint32_t>, ///< priority
                                      route::tunnel_destination_t,
                                      ip_prefix_t>; ///< fallback

using tunnel_value_interface_t = std::tuple<ip_address_t, ///< nexthop
                                            tInterfaceId,
                                            uint32_t, ///< label
                                            std::string, ///< interface_name
                                            uint32_t, ///< peer_id
                                            uint32_t, ///< origin_as
                                            uint32_t>; ///< weight

using tunnel_lookup_t = std::tuple<ip_address_t, ///< nexthop
                                   std::string, ///< interface_name
                                   uint32_t, ///< label
                                   uint32_t, ///< peer_id
                                   uint32_t, ///< origin_as
                                   double>; ///< weight_percent

/// @todo: vrf
using tunnel_counter_key_t = std::tuple<bool, ///< is_ipv4
                                        uint32_t, ///< peer_id
                                        uint32_t>; ///< origin_as

class generation_t
{
public:
	generation_t()
	{
	}

	void update(const controlplane::base_t& base_prev,
	            const controlplane::base_t& base_next)
	{
		(void)base_prev;

		routes = base_next.routes;

		for (const auto& [module_name, route] : base_next.routes)
		{
			(void)module_name;

			for (const auto& [interface_name, interface] : route.interfaces)
			{
				if (interface.neighborIPv4Address)
				{
					interface_by_neighbors[*interface.neighborIPv4Address] = {interface.interfaceId, interface_name};
				}

				if (interface.neighborIPv6Address)
				{
					interface_by_neighbors[*interface.neighborIPv6Address] = {interface.interfaceId, interface_name};
				}
			}

			peers.insert(route.peers.begin(), route.peers.end());
		}

		peers[0] = "unknown";
	}

	std::optional<const std::tuple<tInterfaceId, std::string>*> get_interface_by_neighbor(const ip_address_t& address) const
	{
		auto it = interface_by_neighbors.find(address);
		if (it == interface_by_neighbors.end())
		{
			return std::nullopt;
		}

		return &it->second; ///< read only after update
	}

	std::optional<const std::string*> get_vrf(const std::string& route_name) const
	{
		auto it = routes.find(route_name);
		if (it == routes.end())
		{
			return std::nullopt;
		}

		return &it->second.vrf; ///< read only after update
	}

	const std::map<uint32_t, std::string>* get_peers() const
	{
		return &peers;
	}

public:
	std::map<std::string, controlplane::route::config_t> routes;
	std::map<ip_address_t, std::tuple<tInterfaceId, std::string>> interface_by_neighbors;
	std::map<uint32_t, std::string> peers; ///< @todo: VRF
};

class generation_neighbors_t
{
public:
	std::optional<const common::mac_address_t*> get_mac_address(const std::string& route_name, const std::string& interface_name, const common::ip_address_t& neighbor) const
	{
		auto it = mac_addresses.find({route_name, interface_name, neighbor});
		if (it == mac_addresses.end())
		{
			return std::nullopt;
		}

		return &it->second; ///< read only after update
	}

public:
	std::map<std::tuple<std::string, ///< route_name
	                    std::string, ///< interface_name
	                    common::ip_address_t>, ///< neighbor
	         common::mac_address_t> mac_addresses;
};

}

class route_t : public module_t
{
public:
	eResult init() override;
	void limit(common::icp::limit_summary::response& limits) const override;
	void reload_before() override;
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;
	void reload_after() override;
	void mac_addresses_changed() override;

	void prefix_update(const std::tuple<std::string, uint32_t>& vrf_priority, const ip_prefix_t& prefix, const std::vector<rib::pptn_t>& pptns, const std::variant<std::monostate, rib::nexthop_map_t, uint32_t>& value);
	void tunnel_prefix_update(const std::tuple<std::string, uint32_t>& vrf_priority_orig, const ip_prefix_t& prefix, const std::variant<std::monostate, rib::nexthop_map_t, uint32_t, std::tuple<>>& value);

	void prefix_flush();

	common::icp::route_config::response route_config() const;
	common::icp::route_summary::response route_summary() const;
	common::icp::route_lookup::response route_lookup(const common::icp::route_lookup::request& request);
	common::icp::route_get::response route_get(const common::icp::route_get::request& request);
	common::icp::route_interface::response route_interface() const;
	common::icp::route_tunnel_lookup::response route_tunnel_lookup(const common::icp::route_tunnel_lookup::request& request);
	common::icp::route_tunnel_get::response route_tunnel_get(const common::icp::route_tunnel_get::request& request);

	void compile(common::idp::updateGlobalBase::request& globalbase, const route::generation_t& generation);
	void compile_interface(common::idp::updateGlobalBase::request& globalbase, const route::generation_t& generation, route::generation_neighbors_t& generation_neighbors);

protected:
	void prefix_flush_prefixes(common::idp::updateGlobalBase::request& globalbase);
	void prefix_flush_values(common::idp::updateGlobalBase::request& globalbas, const route::generation_t& generation);

	void tunnel_prefix_flush_prefixes(common::idp::updateGlobalBase::request& globalbase);
	void tunnel_prefix_flush_values(common::idp::updateGlobalBase::request& globalbase, const route::generation_t& generation);

	/// @todo: linux_prefix_flush

	std::optional<uint32_t> value_insert(const route::value_key_t& value_key);
	void value_remove(const uint32_t& value_id);
	void value_compile(common::idp::updateGlobalBase::request& globalbase, const route::generation_t& generation, const uint32_t& value_id, const route::value_key_t& value_key);
	void value_compile_label(common::idp::updateGlobalBase::request& globalbase, const route::generation_t& generation, const uint32_t& value_id, const std::vector<uint32_t>& service_labels, std::vector<route::value_interface_t>& request_interface, const ip_address_t& first_nexthop);
	void value_compile_fallback(common::idp::updateGlobalBase::request& globalbase, const route::generation_t& generation, const uint32_t& value_id, std::vector<route::value_interface_t>& request_interface);

	std::optional<uint32_t> tunnel_value_insert(const route::tunnel_value_key_t& value_key);
	void tunnel_value_remove(const uint32_t& value_id);
	void tunnel_value_compile(common::idp::updateGlobalBase::request& globalbase, const route::generation_t& generation, const uint32_t& value_id, const route::tunnel_value_key_t& value);

	std::set<std::string> get_ingress_physical_ports(const tSocketId& socket_id);

	void tunnel_gc_thread();

protected:
	interface::dataPlane dataplane;
	interface::system system;

	generation_manager<route::generation_t> generations;
	generation_manager<route::generation_neighbors_t> generations_neighbors;

	mutable std::recursive_mutex mutex;

	std::map<std::string, ///< vrf
	         std::tuple<std::map<uint32_t, ///< priority
	                             common::btree<ip_address_t,
	                                           uint32_t>>, ///< value_id
	                    common::btree<ip_address_t,
	                                  std::tuple<>>>> prefixes;

	std::map<std::string, ///< vrf
	         std::tuple<std::map<uint32_t, ///< priority
	                             common::btree<ip_address_t,
	                                           uint32_t>>, ///< value_id
	                    common::btree<ip_address_t,
	                                  std::tuple<>>>> tunnel_prefixes;

	common::refarray_t<route::value_key_t, YANET_CONFIG_ROUTE_VALUES_SIZE> values;
	common::refarray_t<route::tunnel_value_key_t, YANET_CONFIG_ROUTE_TUNNEL_VALUES_SIZE> tunnel_values;

	std::map<uint32_t,
	         std::map<tSocketId,
	                  std::vector<route::lookup_t>>> value_lookup;

	std::map<uint32_t,
	         std::map<tSocketId,
	                  std::vector<route::tunnel_lookup_t>>> tunnel_value_lookup;

	common::weight_t<YANET_CONFIG_ROUTE_TUNNEL_WEIGHTS_SIZE> tunnel_weights;

	std::map<ip_prefix_t,
	         std::set<ip_address_t>> linux_routes;

	std::set<ipv4_address_t> tunnel_defaults_v4; ///< @todo: VRF
	std::set<ipv6_address_t> tunnel_defaults_v6; ///< @todo: VRF

	friend class telegraf_t;
	counter_t<route::tunnel_counter_key_t, 2> tunnel_counter;
};
