#include "route.h"
#include "common/icp.h"
#include "controlplane.h"
#include "controlplane/route.h"

uint32_t ExtractPeerIdFromPathInformation(const std::string& path_information)
{
	auto pi_it = path_information.find_last_of(':');
	if (pi_it != std::string::npos)
	{
		try
		{
			return std::stoll(path_information.substr(pi_it + 1), nullptr, 0);
		}
		catch (...)
		{
			YANET_LOG_WARNING("bad peer_id: %s\n", path_information.data());
		}
	}
	return 0;
}

eResult route_t::init()
{
	{
		common::idp::updateGlobalBase::request globalbase;
		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::route_lpm_update,
		                        common::idp::lpm::request({{0, common::idp::lpm::clear()}}));
		dataplane.updateGlobalBase(std::move(globalbase));
	}

	tunnel_counter.init(&controlPlane->counter_manager);
	tunnel_counter.insert({true, 0, ip_address_t(), 0}); ///< fallback v4
	tunnel_counter.insert({false, 0, ip_address_t(), 0}); ///< fallback v6

	route_counter.init(&controlPlane->counter_manager);

	controlPlane->register_command(common::icp::requestType::route_config, [this]() {
		return route_config();
	});

	controlPlane->register_command(common::icp::requestType::route_summary, [this]() {
		return route_summary();
	});

	controlPlane->register_command(common::icp::requestType::route_lookup, [this](const common::icp::request& request) {
		return route_lookup(std::get<common::icp::route_lookup::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::route_get, [this](const common::icp::request& request) {
		return route_get(std::get<common::icp::route_get::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::route_counters, [this]() {
		return route_counters();
	});

	controlPlane->register_command(common::icp::requestType::route_tunnel_counters, [this]() {
		return route_tunnel_counters();
	});

	controlPlane->register_command(common::icp::requestType::route_interface, [this]() {
		return route_interface();
	});

	controlPlane->register_command(common::icp::requestType::route_tunnel_lookup, [this](const common::icp::request& request) {
		return route_tunnel_lookup(std::get<common::icp::route_tunnel_lookup::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::route_tunnel_get, [this](const common::icp::request& request) {
		return route_tunnel_get(std::get<common::icp::route_tunnel_get::request>(std::get<1>(request)));
	});

	funcThreads.emplace_back([this]() {
		tunnel_gc_thread();
	});

	return eResult::success;
}

void route_t::prefix_update(const rib::vrf_priority_t& vrf_priority,
                            const ip_prefix_t& prefix,
                            const std::vector<rib::pptn_t>& pptns,
                            const std::variant<std::monostate, rib::nexthop_map_t, route::directly_connected_destination_t, uint32_t>& value)
{
	const auto& [vrf, priority] = vrf_priority;

	std::optional<route::destination_t> destination_next;
	if (const auto nexthops = std::get_if<rib::nexthop_map_t>(&value))
	{
		std::map<std::tuple<uint32_t,
		                    std::size_t,
		                    std::string,
		                    uint32_t>,
		         route::destination_interface_t>
		        interface_destination_next;
		for (const auto& [pptn_index, path_info_to_nh_ptr] : *nexthops)
		{
			/// @todo: multi route. vrf
			{
				const auto& table_name = std::get<2>(pptns[pptn_index]);
				auto current_guard = generations.current_lock_guard();
				if (generations.current().is_ignored_table(table_name))
				{
					continue;
				}
			}

			for (const auto& [path_info, nh_ptr] : path_info_to_nh_ptr)
			{
				uint32_t peer_id = ExtractPeerIdFromPathInformation(path_info);

				const auto& [nexthop, labels, origin, med, aspath, communities, large_communities, local_preference] = *nh_ptr;
				GCC_BUG_UNUSED(communities);
				GCC_BUG_UNUSED(large_communities);

				interface_destination_next[{std::numeric_limits<decltype(local_preference)>::max() - local_preference,
				                            aspath.size(),
				                            origin,
				                            med}]
				        .emplace(nexthop, peer_id, prefix, labels);
			}
		}

		if (interface_destination_next.size())
		{
			destination_next = interface_destination_next.begin()->second;
		}
	}
	else if (const auto directly_connected = std::get_if<route::directly_connected_destination_t>(&value))
	{
		destination_next = *directly_connected;
	}
	else if (const auto virtual_port_id = std::get_if<uint32_t>(&value))
	{
		destination_next = *virtual_port_id;
	}

	if (destination_next)
	{
		/// insert or update

		std::lock_guard<std::recursive_mutex> guard(mutex);

		auto& [priority_current, update] = prefixes[vrf];
		auto& current = priority_current[priority];

		const auto destination_prev = current.get(prefix);
		if (destination_prev)
		{
			value_remove(*destination_prev);
		}

		const auto value_id = value_insert({vrf_priority,
		                                    *destination_next,
		                                    prefix.get_default()});
		if (value_id)
		{
			current.insert(prefix, *value_id);
			update.insert(prefix, {});
		}
	}
	else
	{
		/// remove

		std::lock_guard<std::recursive_mutex> guard(mutex);

		auto& [priority_current, update] = prefixes[vrf];
		auto& current = priority_current[priority];

		const auto value_id = current.get(prefix);
		if (value_id)
		{
			value_remove(*value_id);

			current.remove(prefix);
			update.insert(prefix, {});
		}
	}
}

void route_t::tunnel_prefix_update(const rib::vrf_priority_t& vrf_priority_orig,
                                   const ip_prefix_t& prefix,
                                   const std::variant<std::monostate, rib::nexthop_map_t, route::directly_connected_destination_t, uint32_t, std::tuple<>>& value)
{
	auto vrf_priority = vrf_priority_orig;
	auto& [vrf, priority] = vrf_priority;

	std::set<ipv4_address_t> tunnel_defaults_v4;
	std::set<ipv6_address_t> tunnel_defaults_v6;

	std::optional<route::tunnel_destination_t> destination_next;
	if (const auto nexthops = std::get_if<rib::nexthop_map_t>(&value))
	{
		using bgp_length = std::tuple<uint32_t,
		                              std::size_t,
		                              std::string,
		                              uint32_t>;

		std::map<bgp_length,
		         route::tunnel_destination_legacy_t>
		        destination_legacy_next;
		std::map<std::variant<uint32_t, ///< override_length
		                      bgp_length>,
		         route::tunnel_destination_interface_t>
		        destination_interface_next;

		for (const auto& [pptn_index, path_info_to_nh_ptr] : *nexthops)
		{
			GCC_BUG_UNUSED(pptn_index);

			for (const auto& [path_information, nh_ptr] : path_info_to_nh_ptr)
			{
				const auto& [nexthop, labels, origin, med, aspath, communities, large_communities, local_preference] = *nh_ptr;
				GCC_BUG_UNUSED(communities);

				if ((prefix.is_ipv4() && nexthop.is_ipv4()) ||
				    (prefix.is_ipv4() && nexthop.is_ipv6()) ||
				    (prefix.is_ipv6() && nexthop.is_ipv6()))
				{
					if (labels.size() == 1)
					{
						uint32_t origin_as = 0;
						uint32_t weight = 0;
						std::optional<uint32_t> override_length;

						if (aspath.size())
						{
							origin_as = aspath.back();
						}

						uint32_t peer_id = ExtractPeerIdFromPathInformation(path_information);

						if (peer_id < 10000 ||
						    peer_id >= 11000)
						{
							continue;
						}

						for (const auto& large_community : large_communities)
						{
							if (large_community.value[0] == YANET_DEFAULT_BGP_AS &&
							    large_community.value[1] == 1) ///< @todo: DEFINE
							{
								weight = large_community.value[2];
							}

							if (large_community.value[0] == YANET_DEFAULT_BGP_AS &&
							    large_community.value[1] == 1000) ///< @todo: DEFINE
							{
								override_length = large_community.value[2];
							}
						}

						if (weight == 0)
						{
							continue;
						}

						if (override_length)
						{
							destination_interface_next[*override_length].emplace(nexthop, labels[0], peer_id, origin_as, weight);
						}
						else
						{
							destination_interface_next[bgp_length(std::numeric_limits<decltype(local_preference)>::max() - local_preference,
							                                      aspath.size(),
							                                      origin,
							                                      med)]
							        .emplace(nexthop, labels[0], peer_id, origin_as, weight);
						}
					}
					else if (labels.size() == 0)
					{
						destination_legacy_next[bgp_length(std::numeric_limits<decltype(local_preference)>::max() - local_preference,
						                                   aspath.size(),
						                                   origin,
						                                   med)]
						        .emplace(nexthop);
					}

					if (prefix.is_default() &&
					    labels.size() == 0)
					{
						if (prefix.is_ipv4())
						{
							tunnel_defaults_v4.emplace(nexthop);
						}
						else
						{
							tunnel_defaults_v6.emplace(nexthop);
						}
					}
				}
			}
		}

		if (destination_interface_next.size())
		{
			/// лукап по дереву с метками
			priority += 5;
			destination_next = destination_interface_next.begin()->second;
		}
		else if (destination_legacy_next.size())
		{
			/// legacy лукап
			destination_next = destination_legacy_next.begin()->second;
		}
	}
	else if (const auto directly_connected = std::get_if<route::directly_connected_destination_t>(&value))
	{
		destination_next = *directly_connected;
	}
	else if (const auto virtual_port_id = std::get_if<uint32_t>(&value))
	{
		destination_next = *virtual_port_id;
	}
	else if (std::get_if<std::tuple<>>(&value))
	{
		/// лукап в legacy дефолт
		destination_next = route::tunnel_destination_default_t();
	}

	if (destination_next)
	{
		/// insert or update

		std::lock_guard<std::recursive_mutex> guard(mutex);

		auto& [priority_current, update] = tunnel_prefixes[vrf];
		auto& current = priority_current[priority];

		const auto destination_prev = current.get(prefix);
		if (destination_prev)
		{
			tunnel_value_remove(*destination_prev);

			current.remove(prefix);
			update.insert(prefix, {});
		}

		const auto value_id = tunnel_value_insert({vrf_priority,
		                                           *destination_next,
		                                           prefix.get_default()});
		if (value_id)
		{
			current.insert(prefix, *value_id);
			update.insert(prefix, {});
		}
	}
	else
	{
		/// remove

		std::lock_guard<std::recursive_mutex> guard(mutex);

		auto& [priority_current, update] = tunnel_prefixes[vrf];

		/// проверяем priority и priority + 5 (legacy лукап + лукап по дереву с метками)
		uint32_t priority_max = priority + 5;
		for (;
		     priority <= priority_max;
		     priority += 5)
		{
			auto& current = priority_current[priority];

			const auto value_id = current.get(prefix);
			if (value_id)
			{
				tunnel_value_remove(*value_id);

				current.remove(prefix);
				update.insert(prefix, {});
			}
		}
	}

	if (prefix.is_default())
	{
		std::lock_guard<std::recursive_mutex> guard(mutex);

		if (prefix.is_ipv4())
		{
			this->tunnel_defaults_v4 = tunnel_defaults_v4;
		}
		else
		{
			this->tunnel_defaults_v6 = tunnel_defaults_v6;
		}
	}
}

void route_t::prefix_flush()
{
	common::idp::updateGlobalBase::request globalbase;

	generations.next_lock();
	generations_neighbors.next_lock();

	tunnel_counter.allocate();
	route_counter.allocate();

	compile(globalbase, generations.current());
	dataplane.updateGlobalBase(globalbase); ///< может вызвать исключение, которое никто не поймает, и это приведёт к abort()

	tunnel_counter.release();
	route_counter.release();

	generations_neighbors.next_unlock();
	generations.next_unlock();
}

common::icp::route_config::response route_t::route_config() const
{
	auto current_guard = generations.current_lock_guard();
	return generations.current().routes;
}

common::icp::route_summary::response route_t::route_summary() const
{
	common::icp::route_summary::response response;

	{
		auto current_guard = generations.current_lock_guard();
		for (const auto& [route_name, route] : generations.current().routes)
		{
			response.emplace_back(route_name, route.vrf);
		}
	}

	return response;
}

common::icp::route_lookup::response route_t::route_lookup(const common::icp::route_lookup::request& request)
{
	common::icp::route_lookup::response result;

	const auto& [request_route_name, request_address] = request;

	{
		std::lock_guard<std::recursive_mutex> guard(mutex);

		std::string vrf;
		{
			auto current_guard = generations.current_lock_guard();
			auto current_vrf = generations.current().get_vrf(request_route_name);
			if (!current_vrf)
			{
				return result;
			}

			vrf = **current_vrf;
		}

		if (exist(prefixes, vrf))
		{
			const auto& [priority_current, update] = prefixes[vrf];
			GCC_BUG_UNUSED(update);

			for (auto it = priority_current.rbegin();
			     it != priority_current.rend();
			     ++it)
			{
				const auto& current = it->second;

				auto value_mask = current.lookup(request_address);
				if (value_mask)
				{
					const auto& [value_id, mask] = *value_mask;

					for (const auto& [socket_id, destinations] : value_lookup[value_id])
					{
						std::set<std::string> ingress_physical_ports = get_ingress_physical_ports(socket_id);

						for (const auto& [nexthop, egress_interface_name, labels] : destinations)
						{
							result.emplace(ingress_physical_ports,
							               ip_prefix_t(request_address.applyMask(mask), mask),
							               nexthop,
							               egress_interface_name,
							               labels);
						}
					}

					return result;
				}
			}
		}
	}

	return result;
}

common::icp::route_get::response route_t::route_get(const common::icp::route_get::request& request)
{
	common::icp::route_get::response result;

	const auto& [request_route_name, request_prefix] = request;

	{
		std::lock_guard<std::recursive_mutex> guard(mutex);

		std::string vrf;
		{
			auto current_guard = generations.current_lock_guard();
			auto current_vrf = generations.current().get_vrf(request_route_name);
			if (!current_vrf)
			{
				return result;
			}

			vrf = **current_vrf;
		}

		if (exist(prefixes, vrf))
		{
			const auto& [priority_current, update] = prefixes[vrf];
			GCC_BUG_UNUSED(update);

			for (auto it = priority_current.rbegin();
			     it != priority_current.rend();
			     ++it)
			{
				const auto& current = it->second;

				auto value = current.get(request_prefix);
				if (value)
				{
					const auto& value_id = *value;

					for (const auto& [socket_id, destinations] : value_lookup[value_id])
					{
						std::set<std::string> ingress_physical_ports = get_ingress_physical_ports(socket_id);

						for (const auto& [nexthop, egress_interface_name, labels] : destinations)
						{
							result.emplace(ingress_physical_ports,
							               request_prefix,
							               nexthop,
							               egress_interface_name,
							               labels);
						}
					}

					return result;
				}
			}
		}
	}

	return result;
}

common::icp::route_counters::response route_t::route_counters()
{
	common::icp::route_counters::response result;

	auto current_guard = generations.current_lock_guard();
	auto counter_values = route_counter.get_counters();

	for (const auto& [key, counts] : counter_values)
	{
		const auto [link_id, nexthop, prefix] = key;
		if (counts[0] != 0 || counts[1] != 0)
		{
			result.emplace_back(link_id, nexthop, prefix, counts[0], counts[1]);
		}
	}

	return result;
}

common::icp::route_tunnel_counters::response route_t::route_tunnel_counters()
{
	common::icp::route_tunnel_counters::response result;

	auto current_guard = generations.current_lock_guard();
	auto counter_values = tunnel_counter.get_counters();

	for (const auto& [key, counts] : counter_values)
	{
		const auto [is_ipv4, link_id, nexthop, origin_as] = key;
		GCC_BUG_UNUSED(is_ipv4);
		GCC_BUG_UNUSED(origin_as);
		if (counts[0] != 0 || counts[1] != 0)
		{
			result.emplace_back(link_id, nexthop, counts[0], counts[1]);
		}
	}

	return result;
}

common::icp::route_interface::response route_t::route_interface() const
{
	common::icp::route_interface::response response;

	{
		auto current_guard = generations.current_lock_guard();
		auto neighbors_current_guard = generations_neighbors.current_lock_guard();

		for (const auto& [route_name, route] : generations.current().routes)
		{
			for (const auto& [interface_name, interface] : route.interfaces)
			{
				auto& [prefixes, neighbor_v4, neighbor_v6, neighbor_mac_address_v4, neighbor_mac_address_v6, next_module] = response[{route_name, interface_name}];

				prefixes = interface.ip_prefixes;
				neighbor_v4 = interface.neighborIPv4Address;
				neighbor_v6 = interface.neighborIPv6Address;

				if (interface.neighborIPv4Address)
				{
					auto mac_address = generations_neighbors.current().get_mac_address(route_name, interface_name, *interface.neighborIPv4Address);
					if (mac_address)
					{
						neighbor_mac_address_v4 = **mac_address;
					}
				}

				if (interface.neighborIPv6Address)
				{
					auto mac_address = generations_neighbors.current().get_mac_address(route_name, interface_name, *interface.neighborIPv6Address);
					if (mac_address)
					{
						neighbor_mac_address_v6 = **mac_address;
					}
				}

				next_module = interface.nextModule;
			}
		}
	}

	return response;
}

common::icp::route_tunnel_lookup::response route_t::route_tunnel_lookup(const common::icp::route_tunnel_lookup::request& request)
{
	common::icp::route_tunnel_lookup::response result;

	const auto& [request_route_name, request_address] = request;

	{
		std::lock_guard<std::recursive_mutex> guard(mutex);

		std::string vrf;
		{
			auto current_guard = generations.current_lock_guard();
			auto current_vrf = generations.current().get_vrf(request_route_name);
			if (!current_vrf)
			{
				return result;
			}

			vrf = **current_vrf;
		}

		generations.current_lock();
		std::map<uint32_t, std::string> peers = *generations.current().get_peers();
		generations.current_unlock();

		if (exist(tunnel_prefixes, vrf))
		{
			const auto& [priority_current, update] = tunnel_prefixes[vrf];
			GCC_BUG_UNUSED(update);

			for (auto it = priority_current.rbegin();
			     it != priority_current.rend();
			     ++it)
			{
				const auto& current = it->second;

				auto value_mask = current.lookup(request_address);
				if (value_mask)
				{
					const auto& [value_id, mask] = *value_mask;

					for (const auto& [socket_id, destinations] : tunnel_value_lookup[value_id])
					{
						std::set<std::string> ingress_physical_ports = get_ingress_physical_ports(socket_id);

						for (const auto& [nexthop, egress_interface_name, label, peer_id, origin_as, weight_percent] : destinations)
						{
							GCC_BUG_UNUSED(origin_as);

							std::optional<uint32_t> result_label;
							std::optional<std::string> result_peer;
							if (label != 3) ///< @todo: DEFINE
							{
								result_label = label;
								/* raw number replaced string peers[peer_id]
								   as peer_id has 10000 addend (unlike that from peers.conf) */
								result_peer = std::to_string(peer_id);
							}

							result.emplace(ingress_physical_ports,
							               ip_prefix_t(request_address.applyMask(mask), mask),
							               nexthop,
							               result_label,
							               egress_interface_name,
							               result_peer,
							               weight_percent);
						}
					}

					return result;
				}
			}
		}
	}

	return result;
}

common::icp::route_tunnel_get::response route_t::route_tunnel_get(const common::icp::route_tunnel_get::request& request)
{
	common::icp::route_tunnel_get::response result;

	const auto& [request_route_name, request_prefix] = request;

	{
		std::lock_guard<std::recursive_mutex> guard(mutex);

		std::string vrf;
		{
			auto current_guard = generations.current_lock_guard();
			auto current_vrf = generations.current().get_vrf(request_route_name);
			if (!current_vrf)
			{
				return result;
			}

			vrf = **current_vrf;
		}

		generations.current_lock();
		std::map<uint32_t, std::string> peers = *generations.current().get_peers();
		generations.current_unlock();

		if (exist(tunnel_prefixes, vrf))
		{
			const auto& [priority_current, update] = tunnel_prefixes[vrf];
			GCC_BUG_UNUSED(update);

			for (auto it = priority_current.rbegin();
			     it != priority_current.rend();
			     ++it)
			{
				const auto& current = it->second;

				auto value = current.get(request_prefix);
				if (value)
				{
					const auto& value_id = *value;

					for (const auto& [socket_id, destinations] : tunnel_value_lookup[value_id])
					{
						std::set<std::string> ingress_physical_ports = get_ingress_physical_ports(socket_id);

						for (const auto& [nexthop, egress_interface_name, label, peer_id, origin_as, weight_percent] : destinations)
						{
							GCC_BUG_UNUSED(origin_as);

							std::optional<uint32_t> result_label;
							std::optional<std::string> result_peer;
							if (label != 3) ///< @todo: DEFINE
							{
								result_label = label;
								result_peer = peers[peer_id];
							}

							result.emplace(ingress_physical_ports,
							               request_prefix,
							               nexthop,
							               result_label,
							               egress_interface_name,
							               result_peer,
							               weight_percent);
						}
					}

					return result;
				}
			}
		}
	}

	return result;
}

void route_t::compile(common::idp::updateGlobalBase::request& globalbase,
                      const route::generation_t& generation)
{
	std::lock_guard<std::recursive_mutex> guard(mutex);

	prefix_flush_prefixes(globalbase);
	prefix_flush_values(globalbase, generation);

	tunnel_prefix_flush_prefixes(globalbase);
	tunnel_prefix_flush_values(globalbase, generation);
}

void route_t::compile_interface(common::idp::updateGlobalBase::request& globalbase,
                                const route::generation_t& generation,
                                route::generation_neighbors_t& generation_neighbors)
{
	{
		common::idp::neighbor_update_interfaces::request request;
		for (const auto& [route_name, route] : generation.routes)
		{
			for (auto& [interface_name, interface] : route.interfaces)
			{
				request.emplace_back(interface.interfaceId,
				                     route_name,
				                     interface_name);
			}
		}
		dataplane.neighbor_update_interfaces(request);
	}

	for (const auto& [route_name, route] : generation.routes)
	{
		for (auto& [interface_name, interface] : route.interfaces)
		{
			std::optional<mac_address_t> neighbor_mac_address_v4;
			std::optional<mac_address_t> neighbor_mac_address_v6;

			if (interface.neighborIPv4Address)
			{
				if (interface.static_neighbor_mac_address_v4)
				{
					neighbor_mac_address_v4 = *interface.static_neighbor_mac_address_v4;
				}
			}

			if (interface.neighborIPv6Address)
			{
				if (interface.static_neighbor_mac_address_v6)
				{
					neighbor_mac_address_v6 = *interface.static_neighbor_mac_address_v6;
				}
			}

			if (neighbor_mac_address_v4)
			{
				generation_neighbors.mac_addresses[{route_name, interface_name, *interface.neighborIPv4Address}] = *neighbor_mac_address_v4;
				dataplane.neighbor_insert({route_name,
				                           interface_name,
				                           *interface.neighborIPv4Address,
				                           *neighbor_mac_address_v4});
			}

			if (neighbor_mac_address_v6)
			{
				generation_neighbors.mac_addresses[{route_name, interface_name, *interface.neighborIPv6Address}] = *neighbor_mac_address_v6;
				dataplane.neighbor_insert({route_name,
				                           interface_name,
				                           *interface.neighborIPv6Address,
				                           *neighbor_mac_address_v6});
			}

			globalbase.emplace_back(common::idp::updateGlobalBase::requestType::updateInterface,
			                        common::idp::updateGlobalBase::updateInterface::request{interface.interfaceId,
			                                                                                interface.aclId,
			                                                                                interface.flow});
		}
	}
}

void route_t::limit(common::icp::limit_summary::response& limits) const
{
	limit_insert(limits, "route.values", values.stats());
	limit_insert(limits, "route.tunnel.values", tunnel_values.stats());
	limit_insert(limits, "route.tunnel.weights", tunnel_weights.stats());
}

void route_t::reload_before()
{
	generations.next_lock();
	generations_neighbors.next_lock();
}

void route_t::reload(const controlplane::base_t& base_prev,
                     const controlplane::base_t& base_next,
                     common::idp::updateGlobalBase::request& globalbase)
{
	generations.next().update(base_prev, base_next);

	{
		std::lock_guard<std::recursive_mutex> guard(mutex);

		for (const auto& [module_name, nat64stateless] : base_prev.nat64statelesses)
		{
			GCC_BUG_UNUSED(module_name);

			for (const auto& prefix : nat64stateless.nat64_prefixes)
			{
				prefix_update({YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_ROUTE_REPEAT},
				              prefix.get_prefix(),
				              {}, // TODO: get rid of third parameter
				              std::monostate());

				tunnel_prefix_update({YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_ROUTE_REPEAT},
				                     prefix.get_prefix(),
				                     std::monostate());
			}
		}

		for (const auto& [module_name, nat64stateless] : base_next.nat64statelesses)
		{
			GCC_BUG_UNUSED(module_name);

			for (const auto& prefix : nat64stateless.nat64_prefixes)
			{
				prefix_update({YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_ROUTE_REPEAT},
				              prefix.get_prefix(),
				              {}, // TODO: get rid of third parameter
				              uint32_t(0)); ///< @todo: VIRTUAL_PORT

				tunnel_prefix_update({YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_ROUTE_REPEAT},
				                     prefix.get_prefix(),
				                     uint32_t(0)); ///< @todo: VIRTUAL_PORT
			}
		}

		for (const auto& [config_module_name, config_module] : base_prev.routes)
		{
			GCC_BUG_UNUSED(config_module_name);

			for (const auto& prefix : config_module.local_prefixes)
			{
				tunnel_prefix_update({YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_ROUTE_TUNNEL_FALLBACK},
				                     prefix,
				                     std::monostate());
			}
		}

		for (const auto& [config_module_name, config_module] : base_next.routes)
		{
			GCC_BUG_UNUSED(config_module_name);

			for (const auto& prefix : config_module.local_prefixes)
			{
				tunnel_prefix_update({YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_ROUTE_TUNNEL_FALLBACK},
				                     prefix,
				                     std::tuple<>());
			}
		}

		for (const auto& [config_module_name, config_module] : base_prev.routes)
		{
			GCC_BUG_UNUSED(config_module_name);

			for (const auto& [interface_name, interface] : config_module.interfaces)
			{
				GCC_BUG_UNUSED(interface_name);

				for (const auto& ip_prefix : interface.ip_prefixes)
				{
					if (!ip_prefix.is_host())
					{
						prefix_update({YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_ROUTE_REPEAT},
						              ip_prefix.applyMask(ip_prefix.mask()),
						              {},
						              std::monostate());

						tunnel_prefix_update({"default", YANET_RIB_PRIORITY_ROUTE_REPEAT},
						                     ip_prefix.applyMask(ip_prefix.mask()),
						                     std::monostate());
					}
				}
			}
		}

		for (const auto& [config_module_name, config_module] : base_next.routes)
		{
			GCC_BUG_UNUSED(config_module_name);

			for (const auto& [interface_name, interface] : config_module.interfaces)
			{
				for (const auto& ip_prefix : interface.ip_prefixes)
				{
					if (!ip_prefix.is_host())
					{
						route::directly_connected_destination_t directly_connected = {interface.interfaceId,
						                                                              interface_name};

						prefix_update({YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_ROUTE_REPEAT},
						              ip_prefix.applyMask(ip_prefix.mask()),
						              {},
						              directly_connected);

						tunnel_prefix_update({"default", YANET_RIB_PRIORITY_ROUTE_REPEAT},
						                     ip_prefix.applyMask(ip_prefix.mask()),
						                     directly_connected);
					}
				}
			}
		}
	}

#ifdef CONFIG_YADECAP_AUTOTEST
#else // CONFIG_YADECAP_AUTOTEST
	for (const auto& [prefix, route] : linux_routes)
	{
		system.updateRoute(prefix, route); ///< @todo: unlock
	}
#endif // CONFIG_YADECAP_AUTOTEST

	tunnel_counter.allocate();
	route_counter.allocate();

	compile(globalbase, generations.next());
	compile_interface(globalbase, generations.next(), generations_neighbors.next());
}

void route_t::reload_after()
{
	tunnel_counter.release();
	route_counter.release();
	generations_neighbors.switch_generation();
	generations.switch_generation();
	generations_neighbors.next_unlock();
	generations.next_unlock();
}

void route_t::prefix_flush_prefixes(common::idp::updateGlobalBase::request& globalbase)
{
	common::idp::lpm::request lpm_request;

	for (auto& [vrf, priority_current_update] : prefixes)
	{
		std::optional<tVrfId> vrfId = controlPlane->getVrfIdsStorage().GetOrCreate(vrf);
		if (!vrfId.has_value())
		{
			YANET_LOG_DEBUG("Can't get id for vrf: '%s'\n", vrf.c_str());
			continue;
		}

		auto& [priority_current, update] = priority_current_update;

		const auto update_prefixes = update.get_all_top();
		update.clear();

		{
			common::idp::lpm::remove lpm_remove;

			for (const auto& update_prefix : update_prefixes)
			{
				lpm_remove.emplace_back(update_prefix);
			}

			if (lpm_remove.size())
			{
				lpm_request.emplace_back(*vrfId, lpm_remove);
			}
		}

		{
			common::idp::lpm::insert lpm_insert;

			for (const auto& [priority, current] : priority_current)
			{
				GCC_BUG_UNUSED(priority);

				for (const auto& update_prefix : update_prefixes)
				{
					current.lookup_deep(update_prefix,
					                    [&lpm_insert](const ip_prefix_t& prefix, const uint32_t& value_id) {
						                    lpm_insert.emplace_back(prefix, value_id);
					                    });
				}
			}

			if (lpm_insert.size())
			{
				lpm_request.emplace_back(*vrfId, lpm_insert);
			}
		}
	}

	if (lpm_request.size())
	{
		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::route_lpm_update,
		                        lpm_request);
	}
}

void route_t::prefix_flush_values(common::idp::updateGlobalBase::request& globalbase,
                                  const route::generation_t& generation)
{
	for (const auto& [value_id, value] : values)
	{
		value_compile(globalbase, generation, value_id, value);
	}
}

void route_t::tunnel_prefix_flush_prefixes(common::idp::updateGlobalBase::request& globalbase)
{
	common::idp::lpm::request lpm_request;

	for (auto& [vrf, priority_current_update] : tunnel_prefixes)
	{
		std::optional<tVrfId> vrfId = controlPlane->getVrfIdsStorage().GetOrCreate(vrf);
		if (!vrfId.has_value())
		{
			YANET_LOG_DEBUG("Can't get id for vrf: '%s'\n", vrf.c_str());
			continue;
		}

		auto& [priority_current, update] = priority_current_update;

		const auto update_prefixes = update.get_all_top();
		update.clear();

		{
			common::idp::lpm::remove lpm_remove;

			for (const auto& update_prefix : update_prefixes)
			{
				lpm_remove.emplace_back(update_prefix);
			}

			if (lpm_remove.size())
			{
				lpm_request.emplace_back(*vrfId, lpm_remove);
			}
		}

		{
			common::idp::lpm::insert lpm_insert;

			for (const auto& [priority, current] : priority_current)
			{
				GCC_BUG_UNUSED(priority);

				for (const auto& update_prefix : update_prefixes)
				{
					current.lookup_deep(update_prefix,
					                    [&lpm_insert](const ip_prefix_t& prefix, const uint32_t& value_id) {
						                    lpm_insert.emplace_back(prefix, value_id);
					                    });
				}
			}

			if (lpm_insert.size())
			{
				lpm_request.emplace_back(*vrfId, lpm_insert);
			}
		}
	}

	if (lpm_request.size())
	{
		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::route_tunnel_lpm_update,
		                        lpm_request);
	}
}

void route_t::tunnel_prefix_flush_values(common::idp::updateGlobalBase::request& globalbase,
                                         const route::generation_t& generation)
{
	tunnel_weights.clear();

	for (const auto& [value_id, value] : tunnel_values)
	{
		tunnel_value_compile(globalbase, generation, value_id, value);
	}

	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::route_tunnel_weight_update,
	                        tunnel_weights.data());
}

std::optional<uint32_t> route_t::value_insert(const route::value_key_t& value_key)
{
	if (values.exist_value(value_key))
	{
		values.update(value_key);
		return values.get_id(value_key);
	}

	auto value_id = values.insert(value_key);
	if (!value_id)
	{
		return std::nullopt;
	}

	const auto& [vrf_priority, destination, fallback] = value_key;
	GCC_BUG_UNUSED(vrf_priority);
	GCC_BUG_UNUSED(fallback);

	/// counters
	if (const auto nexthops = std::get_if<route::destination_interface_t>(&destination))
	{
		for (const auto& [nexthop, peer_id, prefix, labels] : *nexthops)
		{
			GCC_BUG_UNUSED(labels);

			route_counter.insert({peer_id, nexthop, prefix});
		}
	}

	return value_id;
}

void route_t::value_remove(const uint32_t& value_id)
{
	auto value_key = values.remove_id(value_id);
	if (value_key)
	{
		const auto& [vrf_priority, destination, fallback] = *value_key;
		GCC_BUG_UNUSED(vrf_priority);
		GCC_BUG_UNUSED(fallback);

		/// counters
		if (const auto nexthops = std::get_if<route::destination_interface_t>(&destination))
		{
			for (const auto& [nexthop, peer_id, prefix, labels] : *nexthops)
			{
				GCC_BUG_UNUSED(labels);

				route_counter.remove({peer_id, nexthop, prefix}, 20);
			}
		}
	}
}

void route_t::value_compile(common::idp::updateGlobalBase::request& globalbase,
                            const route::generation_t& generation,
                            const uint32_t& value_id,
                            const route::value_key_t& value_key)
{
	std::vector<route::value_interface_t> request_interface;

	const auto& [vrf_priority, destination, fallback] = value_key;
	const auto& [vrf, priority] = vrf_priority;

	value_lookup[value_id].clear();

	if (const auto virtual_port_id = std::get_if<uint32_t>(&destination))
	{
		controlPlane->forEachSocket([this, &value_id, &globalbase](const tSocketId& socket_id) {
			globalbase.emplace_back(common::idp::updateGlobalBase::requestType::route_value_update,
			                        common::idp::updateGlobalBase::route_value_update::request(value_id,
			                                                                                   socket_id,
			                                                                                   common::globalBase::eNexthopType::repeat,
			                                                                                   {})); ///< @todo: VIRTUAL_PORT

			value_lookup[value_id][socket_id].emplace_back(ip_address_t(),
			                                               "repeat",
			                                               std::vector<uint32_t>());
		});

		return;
	}
	else if (const auto directly_connected = std::get_if<route::directly_connected_destination_t>(&destination))
	{
		const auto& [interface_id, interface_name] = *directly_connected;

		request_interface.emplace_back(ipv4_address_t(), ///< default
		                               interface_id,
		                               interface_name,
		                               std::vector<uint32_t>(),
		                               ipv4_address_t(), ///< default
		                               0,
		                               fallback);
	}
	else
	{
		for (const auto& destination_iter : std::get<0>(destination)) ///< interface
		{
			const auto& [nexthop, peer_id, prefix, labels] = destination_iter;

			if (nexthop.is_default())
			{
				controlPlane->forEachSocket([this, &value_id, &globalbase](const tSocketId& socket_id) {
					globalbase.emplace_back(common::idp::updateGlobalBase::requestType::route_value_update,
					                        common::idp::updateGlobalBase::route_value_update::request(value_id,
					                                                                                   socket_id,
					                                                                                   common::globalBase::eNexthopType::controlPlane,
					                                                                                   {}));

					value_lookup[value_id][socket_id].emplace_back(ip_address_t(),
					                                               "linux",
					                                               std::vector<uint32_t>());
				});

				return;
			}

			auto interface = generation.get_interface_by_neighbor(nexthop);
			if (interface)
			{
				const auto& [interface_id, interface_name] = **interface;

				if (labels.size() > 2)
				{
					YANET_LOG_WARNING("wrong labels count '%lu'\n",
					                  labels.size());
					continue;
				}

				request_interface.emplace_back(nexthop,
				                               interface_id,
				                               interface_name,
				                               labels,
				                               nexthop,
				                               peer_id,
				                               prefix);

				continue;
			}

			if (labels.size() > 1)
			{
				YANET_LOG_WARNING("wrong labels count '%lu'\n",
				                  labels.size());
				continue;
			}

			ip_prefix_t prefix_next;
			if (nexthop.is_ipv4())
			{
				prefix_next = {nexthop, 32};
			}
			else
			{
				prefix_next = {nexthop, 128};
			}

			auto& [priority_current, update] = prefixes[vrf];
			auto& current = priority_current[priority];
			GCC_BUG_UNUSED(update);

			const auto value_id_label = current.get(prefix_next);
			if (value_id_label)
			{
				value_compile_label(globalbase,
				                    generation,
				                    *value_id_label,
				                    labels,
				                    request_interface,
				                    nexthop);
			}
			else
			{
				/// @todo: stats
			}
		}
	}

	if (request_interface.empty())
	{
		auto& [priority_current, update] = prefixes[vrf];
		auto& current = priority_current[priority];
		GCC_BUG_UNUSED(update);

		const auto value_id_fallback = current.get(fallback);
		if (value_id_fallback)
		{
			value_compile_fallback(globalbase, generation, *value_id_fallback, request_interface);
		}
		else
		{
			/// @todo: stats
		}

		if (request_interface.empty())
		{
			/// @todo: stats

			controlPlane->forEachSocket([this, &value_id, &globalbase](const tSocketId& socket_id) {
				globalbase.emplace_back(common::idp::updateGlobalBase::requestType::route_value_update,
				                        common::idp::updateGlobalBase::route_value_update::request(value_id,
				                                                                                   socket_id,
				                                                                                   common::globalBase::eNexthopType::controlPlane,
				                                                                                   {}));

				value_lookup[value_id][socket_id].emplace_back(ip_address_t(),
				                                               "linux",
				                                               std::vector<uint32_t>());
			});

			return;
		}
		else
		{
			/// @todo: stats
		}
	}

	if (request_interface.size() > CONFIG_YADECAP_GB_ECMP_SIZE)
	{
		/// @todo: stats

		request_interface.resize(CONFIG_YADECAP_GB_ECMP_SIZE);
	}

	generation.for_each_socket([this, &value_id, &request_interface, &globalbase](const tSocketId& socket_id, const std::set<tInterfaceId>& interfaces) {
		common::idp::updateGlobalBase::route_value_update::interface update_interface;

		/// same numa
		for (const auto& item : request_interface)
		{
			const auto& [nexthop, egress_interface_id, egress_interface_name, labels, neighbor_address, peer, prefix] = item;

			if (exist(interfaces, egress_interface_id))
			{
				const auto counter_id = route_counter.get_id({peer, nexthop, prefix});

				uint16_t flags = 0;
				if (neighbor_address.is_default())
				{
					flags |= YANET_NEXTHOP_FLAG_DIRECTLY;
				}

				update_interface.emplace_back(egress_interface_id, counter_id, labels, neighbor_address, flags);

				value_lookup[value_id][socket_id].emplace_back(nexthop,
				                                               egress_interface_name,
				                                               labels);
			}
		}

		/// all numa
		if (update_interface.empty())
		{
			for (const auto& item : request_interface)
			{
				const auto& [nexthop, egress_interface_id, egress_interface_name, labels, neighbor_address, peer, prefix] = item;

				const auto counter_id = route_counter.get_id({peer, nexthop, prefix});

				uint16_t flags = 0;
				if (neighbor_address.is_default())
				{
					flags |= YANET_NEXTHOP_FLAG_DIRECTLY;
				}

				update_interface.emplace_back(egress_interface_id, counter_id, labels, neighbor_address, flags);

				value_lookup[value_id][socket_id].emplace_back(nexthop,
				                                               egress_interface_name,
				                                               labels);
			}
		}

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::route_value_update,
		                        common::idp::updateGlobalBase::route_value_update::request(value_id,
		                                                                                   socket_id,
		                                                                                   common::globalBase::eNexthopType::interface,
		                                                                                   update_interface));
	});
}

void route_t::value_compile_label(common::idp::updateGlobalBase::request& globalbase,
                                  const route::generation_t& generation,
                                  const uint32_t& value_id,
                                  const std::vector<uint32_t>& service_labels,
                                  std::vector<route::value_interface_t>& request_interface,
                                  const ip_address_t& first_nexthop)
{
	const auto& value_key = values.get_value(value_id);
	const auto& [vrf_priority, destination, fallback] = value_key;
	GCC_BUG_UNUSED(globalbase);
	GCC_BUG_UNUSED(vrf_priority);
	GCC_BUG_UNUSED(fallback);

	if (const auto virtual_port_id = std::get_if<uint32_t>(&destination))
	{
		/// @todo: stats
		return;
	}

	for (const auto& destination_iter : std::get<0>(destination)) ///< interface
	{
		auto [nexthop, peer_id, prefix, labels] = destination_iter;

		if (labels.size() != 1)
		{
			/// @todo: stats
			continue;
		}

		if (service_labels.size() == 1)
		{
			labels.emplace_back(service_labels[0]);
		}

		auto interface = generation.get_interface_by_neighbor(nexthop);
		if (interface)
		{
			const auto& [interface_id, interface_name] = **interface;

			request_interface.emplace_back(first_nexthop,
			                               interface_id,
			                               interface_name,
			                               labels,
			                               nexthop,
			                               peer_id,
			                               prefix);
		}
		else
		{
			/// @todo: stats
			continue;
		}
	}
}

void route_t::value_compile_fallback(common::idp::updateGlobalBase::request& globalbase,
                                     const route::generation_t& generation,
                                     const uint32_t& value_id,
                                     std::vector<route::value_interface_t>& request_interface)
{
	const auto& value_key = values.get_value(value_id);
	const auto& [vrf_priority, destination, fallback] = value_key;
	GCC_BUG_UNUSED(globalbase);
	GCC_BUG_UNUSED(vrf_priority);
	GCC_BUG_UNUSED(fallback);

	if (const auto virtual_port_id = std::get_if<uint32_t>(&destination))
	{
		/// @todo: stats
		return;
	}

	for (const auto& destination_iter : std::get<0>(destination)) ///< interface
	{
		const auto& [nexthop, peer_id, prefix, labels] = destination_iter;

		auto interface = generation.get_interface_by_neighbor(nexthop);
		if (interface)
		{
			const auto& [interface_id, interface_name] = **interface;

			if (labels.size() > 2)
			{
				YANET_LOG_WARNING("wrong labels count '%lu'\n",
				                  labels.size());
				continue;
			}

			request_interface.emplace_back(nexthop,
			                               interface_id,
			                               interface_name,
			                               labels,
			                               nexthop,
			                               peer_id,
			                               prefix);
		}
	}
}

std::optional<uint32_t> route_t::tunnel_value_insert(const route::tunnel_value_key_t& value_key)
{
	if (tunnel_values.exist_value(value_key))
	{
		tunnel_values.update(value_key);
		return tunnel_values.get_id(value_key);
	}

	auto value_id = tunnel_values.insert(value_key);
	if (!value_id)
	{
		return std::nullopt;
	}

	const auto& [vrf_priority, destination, fallback] = value_key;
	GCC_BUG_UNUSED(vrf_priority);

	/// counters
	if (const auto nexthops = std::get_if<route::tunnel_destination_interface_t>(&destination))
	{
		for (const auto& [nexthop, label, peer_id, origin_as, weight] : *nexthops)
		{
			GCC_BUG_UNUSED(label);
			GCC_BUG_UNUSED(weight);

			tunnel_counter.insert({fallback.is_ipv4(), peer_id, nexthop, origin_as});
		}
	}

	return value_id;
}

void route_t::tunnel_value_remove(const uint32_t& value_id)
{
	auto value_key = tunnel_values.remove_id(value_id);
	if (value_key)
	{
		const auto& [vrf_priority, destination, fallback] = *value_key;
		GCC_BUG_UNUSED(vrf_priority);

		/// counters
		if (const auto nexthops = std::get_if<route::tunnel_destination_interface_t>(&destination))
		{
			for (const auto& [nexthop, label, peer_id, origin_as, weight] : *nexthops)
			{
				GCC_BUG_UNUSED(label);
				GCC_BUG_UNUSED(weight);

				tunnel_counter.remove({fallback.is_ipv4(), peer_id, nexthop, origin_as}, 20);
			}
		}
	}
}

void route_t::tunnel_value_compile(common::idp::updateGlobalBase::request& globalbase,
                                   const route::generation_t& generation,
                                   const uint32_t& value_id,
                                   const route::tunnel_value_key_t& value_key)
{
	std::vector<route::tunnel_value_interface_t> request_interface;

	const auto& [vrf_priority, destination, fallback] = value_key;
	GCC_BUG_UNUSED(vrf_priority); ///< @todo: VRF

	tunnel_value_lookup[value_id].clear();

	auto request_for_each_socket = [this, &globalbase, value_id](common::globalBase::eNexthopType nexthop) {
		controlPlane->forEachSocket([this, value_id, nexthop, &globalbase](const tSocketId& socket_id) {
			tunnel_value_lookup[value_id][socket_id].emplace_back(ip_address_t(),
			                                                      common::globalBase::InterfaceName(nexthop),
			                                                      3, ///< @todo: DEFINE
			                                                      0,
			                                                      0,
			                                                      1.00);

			globalbase.emplace_back(common::idp::updateGlobalBase::requestType::route_tunnel_value_update,
			                        common::idp::updateGlobalBase::route_tunnel_value_update::request(value_id,
			                                                                                          socket_id,
			                                                                                          nexthop,
			                                                                                          {}));
		});
	};

	if (const auto nexthops = std::get_if<route::tunnel_destination_interface_t>(&destination))
	{
		for (const auto& [nexthop, label, peer_id, origin_as, weight] : *nexthops)
		{
			if (nexthop.is_default())
			{
				request_for_each_socket(common::globalBase::eNexthopType::controlPlane);
				return;
			}

			if (nexthop.is_ipv4())
			{
				for (const auto& default_nexthop : tunnel_defaults_v4)
				{
					auto interface = generation.get_interface_by_neighbor(default_nexthop);
					if (interface)
					{
						const auto& [interface_id, interface_name] = **interface;

						request_interface.emplace_back(nexthop,
						                               interface_id,
						                               label,
						                               interface_name,
						                               peer_id,
						                               origin_as,
						                               weight,
						                               default_nexthop);
					}
				}
			}
			else
			{
				for (const auto& default_nexthop : tunnel_defaults_v6)
				{
					auto interface = generation.get_interface_by_neighbor(default_nexthop);
					if (interface)
					{
						const auto& [interface_id, interface_name] = **interface;

						request_interface.emplace_back(nexthop,
						                               interface_id,
						                               label,
						                               interface_name,
						                               peer_id,
						                               origin_as,
						                               weight,
						                               default_nexthop);
					}
				}
			}
		}
	}
	else if (const auto nexthops = std::get_if<route::tunnel_destination_legacy_t>(&destination))
	{
		for (const auto& nexthop : *nexthops)
		{
			if (nexthop.is_default())
			{
				request_for_each_socket(common::globalBase::eNexthopType::controlPlane);
				return;
			}

			auto interface = generation.get_interface_by_neighbor(nexthop);
			if (interface)
			{
				const auto& [interface_id, interface_name] = **interface;

				request_interface.emplace_back(nexthop,
				                               interface_id,
				                               3, ///< @todo: DEFINE
				                               interface_name,
				                               0,
				                               0,
				                               1,
				                               nexthop);
			}
		}
	}
	else if (const auto directly_connected = std::get_if<route::directly_connected_destination_t>(&destination))
	{
		const auto& [interface_id, interface_name] = *directly_connected;

		request_interface.emplace_back(ipv4_address_t(), ///< default
		                               interface_id,
		                               3, ///< @todo: DEFINE
		                               interface_name,
		                               0,
		                               0,
		                               1,
		                               ipv4_address_t()); ///< default
	}
	else if (const auto virtual_port_id = std::get_if<uint32_t>(&destination))
	{
		request_for_each_socket(common::globalBase::eNexthopType::repeat);
		return;
	}
	else if (std::get_if<route::tunnel_destination_default_t>(&destination))
	{
		if (fallback.is_ipv4())
		{
			for (const auto& default_nexthop : tunnel_defaults_v4)
			{
				auto interface = generation.get_interface_by_neighbor(default_nexthop);
				if (interface)
				{
					const auto& [interface_id, interface_name] = **interface;

					request_interface.emplace_back(default_nexthop,
					                               interface_id,
					                               3, ///< @todo: DEFINE
					                               interface_name,
					                               0,
					                               0,
					                               1,
					                               default_nexthop);
				}
			}
		}
		else
		{
			for (const auto& default_nexthop : tunnel_defaults_v6)
			{
				auto interface = generation.get_interface_by_neighbor(default_nexthop);
				if (interface)
				{
					const auto& [interface_id, interface_name] = **interface;

					request_interface.emplace_back(default_nexthop,
					                               interface_id,
					                               3, ///< @todo: DEFINE
					                               interface_name,
					                               0,
					                               0,
					                               1,
					                               default_nexthop);
				}
			}
		}
	}

	if (request_interface.size() > YANET_CONFIG_ROUTE_TUNNEL_ECMP_SIZE)
	{
		/// @todo: stats
		YANET_LOG_ERROR("YANET_CONFIG_ROUTE_TUNNEL_ECMP_SIZE exceeded, truncated from %ld to %d",
		                request_interface.size(),
		                YANET_CONFIG_ROUTE_TUNNEL_ECMP_SIZE);
		request_interface.resize(YANET_CONFIG_ROUTE_TUNNEL_ECMP_SIZE);
	}

	if (request_interface.empty())
	{
		request_for_each_socket(common::globalBase::eNexthopType::controlPlane);
		return;
	}

	generation.for_each_socket([this, &value_id, &request_interface, &fallback = fallback, &globalbase](const tSocketId& socket_id, const std::set<tInterfaceId>& interfaces) {
		common::idp::updateGlobalBase::route_tunnel_value_update::interface update_interface;
		auto& [update_weight_start, update_weight_size, update_nexthops] = update_interface;

		std::vector<uint32_t> weights;
		uint64_t weight_total = 0;

		/// same numa
		for (const auto& item : request_interface)
		{
			const auto& [nexthop, egress_interface_id, label, egress_interface_name, peer_id, origin_as, weight, neighbor_address] = item;
			GCC_BUG_UNUSED(egress_interface_name);

			if (exist(interfaces, egress_interface_id))
			{
				const auto counter_id = tunnel_counter.get_id({fallback.is_ipv4(), peer_id, nexthop, origin_as});

				uint16_t flags = 0;
				if (neighbor_address.is_default())
				{
					flags |= YANET_NEXTHOP_FLAG_DIRECTLY;
				}

				update_nexthops.emplace_back(egress_interface_id, counter_id, label, nexthop, neighbor_address, flags);
				weights.emplace_back(weight);

				tunnel_value_lookup[value_id][socket_id].emplace_back(nexthop,
				                                                      egress_interface_name,
				                                                      label,
				                                                      peer_id,
				                                                      origin_as,
				                                                      weight);

				weight_total += weight;
			}
		}

		/// all numa
		if (update_nexthops.empty())
		{
			for (const auto& item : request_interface)
			{
				const auto& [nexthop, egress_interface_id, label, egress_interface_name, peer_id, origin_as, weight, neighbor_address] = item;
				GCC_BUG_UNUSED(egress_interface_name);

				const auto counter_id = tunnel_counter.get_id({fallback.is_ipv4(), peer_id, nexthop, origin_as});

				uint16_t flags = 0;
				if (neighbor_address.is_default())
				{
					flags |= YANET_NEXTHOP_FLAG_DIRECTLY;
				}

				update_nexthops.emplace_back(egress_interface_id, counter_id, label, nexthop, neighbor_address, flags);
				weights.emplace_back(weight);

				tunnel_value_lookup[value_id][socket_id].emplace_back(nexthop,
				                                                      egress_interface_name,
				                                                      label,
				                                                      peer_id,
				                                                      origin_as,
				                                                      weight);

				weight_total += weight;
			}
		}

		const auto& [weight_start, weight_size, weight_is_fallback] = tunnel_weights.insert(weights);
		update_weight_start = weight_start;
		update_weight_size = weight_size;

		if (weight_is_fallback)
		{
			tunnel_value_lookup[value_id][socket_id].resize(weight_size);
			weight_total = weight_size;
		}

		for (auto& [nexthop, egress_interface_name, label, peer_id, origin_as, weight_percent] : tunnel_value_lookup[value_id][socket_id])
		{
			GCC_BUG_UNUSED(socket_id);
			GCC_BUG_UNUSED(nexthop);
			GCC_BUG_UNUSED(egress_interface_name);
			GCC_BUG_UNUSED(label);
			GCC_BUG_UNUSED(peer_id);
			GCC_BUG_UNUSED(origin_as);

			if (weight_is_fallback)
			{
				weight_percent = 1;
			}

			weight_percent /= (double)weight_total;
		}

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::route_tunnel_value_update,
		                        common::idp::updateGlobalBase::route_tunnel_value_update::request(value_id,
		                                                                                          socket_id,
		                                                                                          common::globalBase::eNexthopType::interface,
		                                                                                          update_interface));
	});
}

std::set<std::string> route_t::get_ingress_physical_ports(const tSocketId& socket_id)
{
	std::set<std::string> ingress_physical_ports;

	/// @todo: use function
	const auto& [dataplane_physicalports, dataplane_workers, dataplane_values] = controlPlane->dataPlaneConfig;
	GCC_BUG_UNUSED(dataplane_workers);
	GCC_BUG_UNUSED(dataplane_values);

	for (const auto& [dataplane_physicalport_id, dataplane_physicalport] : dataplane_physicalports)
	{
		GCC_BUG_UNUSED(dataplane_physicalport_id);

		const auto& [physicalport_name, dataplane_socket_id, mac_address, pci] = dataplane_physicalport;
		GCC_BUG_UNUSED(mac_address);
		GCC_BUG_UNUSED(pci);

		if (socket_id != dataplane_socket_id)
		{
			continue;
		}

		ingress_physical_ports.emplace(physicalport_name);
	}

	return ingress_physical_ports;
}

void route_t::tunnel_gc_thread()
{
	while (!flagStop)
	{
		tunnel_counter.gc();
		route_counter.gc();
		std::this_thread::sleep_for(std::chrono::seconds(3));
	}
}
