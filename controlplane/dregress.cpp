#include "dregress.h"
#include "controlplane.h"

dregress_t::dregress_t() :
        update_neighbors(false)
{
}

eResult dregress_t::init()
{
	dataplane.updateGlobalBase(
		{
			{common::idp::updateGlobalBase::requestType::dregress_prefix_clear, std::tuple<>()},
			{common::idp::updateGlobalBase::requestType::dregress_local_prefix_update,
				common::idp::updateGlobalBase::dregress_local_prefix_update::request()}
		}
	);

	controlPlane->register_command(common::icp::requestType::dregress_config, [this]()
	{
		return dregress_config();
	});

	return eResult::success;
}

void dregress_t::prefix_insert(const std::tuple<std::string, uint32_t>& vrf_priority, const ip_prefix_t& prefix, const rib::nexthop_map_t& nexthops)
{
	std::lock_guard<std::mutex> guard(mutex);

	if (prefix.is_default())
	{
		if (prefix.is_ipv4())
		{
			defaults_v4.clear();
		}
		else
		{
			defaults_v6.clear();
		}

		update_neighbors = true;
	}

	generations.current_lock();
	std::set<uint32_t> our_as = generations.current().our_as;
	generations.current_unlock();

	std::map<std::tuple<uint32_t, std::size_t, std::string, uint32_t>,
	         std::set<dregress::destination_t>> destination_next;

	for (const auto& [pptn_index, path_info_to_nh_ptr] : nexthops)
	{
		(void)pptn_index;

		for (const auto& [path_info, nexthop_stuff_ptr] : path_info_to_nh_ptr)
		{
			const auto& [nexthop, labels, origin, med, aspath, nexthop_communities, large_communities, local_preference] = *nexthop_stuff_ptr;
			(void)large_communities;

			if ((prefix.is_ipv4() && nexthop.is_ipv4()) ||
				(prefix.is_ipv6() && nexthop.is_ipv6()))
			{
				if (labels.size() == 1)
				{
					uint32_t peer_as = 0;
					uint32_t origin_as = 0;
					if (aspath.size())
					{
						for (const auto& as : aspath)
						{
							if (!our_as.count(as))
							{
								peer_as = as;
								break;
							}
						}

						origin_as = aspath.back();
					}

					auto communities = nexthop_communities;
					auto pi_it = path_info.find(':');
					if (pi_it != std::string::npos)
					{
						try
						{
							communities.emplace(13238, std::stoll(path_info.substr(pi_it + 1), nullptr, 0)); ///< @todo: remove 13238, and use RD
						}
						catch (...)
						{
							YANET_LOG_WARNING("bad peer_id: %s\n", path_info.data());
						}
					}

					destination_next[{std::numeric_limits<decltype(local_preference)>::max() - local_preference,
									aspath.size(),
									origin,
									med}].emplace(nexthop,
													labels[0],
													communities,
													peer_as,
													origin_as);
				}
			}

			if (prefix.is_default() &&
				labels.size() == 0) ///< @todo: get from route_t
			{
				if (prefix.is_ipv4() &&
					nexthop.is_ipv4())
				{
					defaults_v4.emplace(nexthop);
				}
				else if (prefix.is_ipv6() &&
						nexthop.is_ipv6())
				{
					defaults_v6.emplace(nexthop);
				}
			}
		}
	}

	if (exist(prefixes[vrf_priority], prefix))
	{
		const auto& destination_prev = prefixes[vrf_priority][prefix];

		if (destination_next == destination_prev)
		{
			return;
		}

		value_remove({vrf_priority,
		              destination_prev});
	}

	{
		const auto value_id = value_insert({vrf_priority,
		                                    destination_next});

		prefixes[vrf_priority][prefix] = destination_next;

		if (value_id)
		{
			{
				auto it = dregress_prefix_remove.find(prefix);
				if (it != dregress_prefix_remove.end())
				{
					dregress_prefix_remove.erase(it);
				}
			}

			dregress_prefix_update[prefix] = *value_id;
		}
	}
}

void dregress_t::prefix_remove(const std::tuple<std::string, uint32_t>& vrf_priority, const ip_prefix_t& prefix)
{
	std::lock_guard<std::mutex> guard(mutex);

	if (prefix.is_default())
	{
		if (prefix.is_ipv4())
		{
			defaults_v4.clear();
		}
		else
		{
			defaults_v6.clear();
		}

		update_neighbors = true;
	}

	if (exist(prefixes, vrf_priority) &&
	    exist(prefixes[vrf_priority], prefix))
	{
		value_remove({vrf_priority,
		              prefixes[vrf_priority][prefix]});

		prefixes[vrf_priority].erase(prefix);

		{
			auto it = dregress_prefix_update.find(prefix);
			if (it != dregress_prefix_update.end())
			{
				dregress_prefix_update.erase(it);
			}
		}

		dregress_prefix_remove.emplace(prefix);
	}
}

void dregress_t::prefix_flush()
{
	common::idp::updateGlobalBase::request globalbase;

	auto current_guard = generations.current_lock_guard();

	{
		std::lock_guard<std::mutex> guard(mutex);
		compile(globalbase, generations.current());
		compile_neighbors(globalbase, generations.current());
	}

	dataplane.updateGlobalBase(globalbase);
}

common::icp::dregress_config::response dregress_t::dregress_config() const
{
	auto current_guard = generations.current_lock_guard();
	return generations.current().dregresses;
}

void dregress_t::compile(common::idp::updateGlobalBase::request& globalbase,
                         const dregress::generation_t& generation)
{
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::dregress_prefix_update,
	                        dregress_prefix_update);
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::dregress_prefix_remove,
	                        dregress_prefix_remove);
	dregress_prefix_update.clear();
	dregress_prefix_remove.clear();

	for (const auto& value_id : value_ids_updated)
	{
		if (values.exist_id(value_id))
		{
			value_compile(globalbase, generation, value_id, values.get_value(value_id));
		}
	}
	value_ids_updated.clear();

	for (const auto& [config_module_name, config_module] : generation.dregresses)
	{
		(void)config_module_name;

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::dregress_local_prefix_update,
		                        config_module.localPrefixes);

		break; ///< @todo: VRF
	}
}

void dregress_t::compile_neighbors(common::idp::updateGlobalBase::request& globalbase,
                                   const dregress::generation_t& generation)
{
	if (!update_neighbors)
	{
		return;
	}

	common::idp::updateGlobalBase::dregress_neighbor_update::request dregress_neighbor_update;
	auto& [neighbor_v4, neighbor_v6] = dregress_neighbor_update;

	for (const auto& [route_name, route] : generation.routes)
	{
		(void)route_name;

		for (auto& [interface_name, interface] : route.interfaces)
		{
			if (interface.neighborIPv4Address)
			{
				if (exist(defaults_v4, *interface.neighborIPv4Address))
				{
					std::optional<mac_address_t> neighbor_mac_address_v4;

					if (interface.static_neighbor_mac_address_v4)
					{
						neighbor_mac_address_v4 = *interface.static_neighbor_mac_address_v4;
					}
					else
					{
						neighbor_mac_address_v4 = controlPlane->get_mac_address(route.vrf, interface_name, *interface.neighborIPv4Address);
					}

					if (neighbor_mac_address_v4)
					{
						neighbor_v4.emplace(*neighbor_mac_address_v4, interface.flow);
					}
				}
			}

			if (interface.neighborIPv6Address)
			{
				if (exist(defaults_v6, *interface.neighborIPv6Address))
				{
					std::optional<mac_address_t> neighbor_mac_address_v6;

					if (interface.static_neighbor_mac_address_v6)
					{
						neighbor_mac_address_v6 = *interface.static_neighbor_mac_address_v6;
					}
					else
					{
						neighbor_mac_address_v6 = controlPlane->get_mac_address(route.vrf, interface_name, *interface.neighborIPv6Address);
					}

					if (neighbor_mac_address_v6)
					{
						neighbor_v6.emplace(*neighbor_mac_address_v6, interface.flow);
					}
				}
			}
		}
	}

	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::dregress_neighbor_update,
	                        dregress_neighbor_update);

	update_neighbors = false;
}

void dregress_t::limit(common::icp::limit_summary::response& limits) const
{
	limit_insert(limits, "dregress.values", values.stats());
}

void dregress_t::reload_before()
{
	generations.next_lock();
}

void dregress_t::reload(const controlplane::base_t& base_prev,
                        const controlplane::base_t& base_next,
                        common::idp::updateGlobalBase::request& globalbase)
{
	generations.next().update(base_prev, base_next);

	{
		std::lock_guard<std::mutex> guard(mutex);
		update_neighbors = true;
		compile(globalbase, generations.next());
		compile_neighbors(globalbase, generations.next());
	}
}

void dregress_t::reload_after()
{
	generations.switch_generation();
	generations.next_unlock();
}

void dregress_t::mac_addresses_changed()
{
	common::idp::updateGlobalBase::request globalbase;

	auto current_guard = generations.current_lock_guard();

	{
		std::lock_guard<std::mutex> guard(mutex);
		update_neighbors = true;
		compile_neighbors(globalbase, generations.current());
	}

	dataplane.updateGlobalBase(globalbase);
}

std::optional<uint32_t> dregress_t::value_insert(const dregress::value_key_t& value_key)
{
	auto value_id = values.update_or_insert(value_key);
	if (value_id)
	{
		value_ids_updated.emplace(*value_id);
	}
	return value_id;
}

void dregress_t::value_remove(const dregress::value_key_t& value_key)
{
	values.remove_value(value_key);
}

void dregress_t::value_compile(common::idp::updateGlobalBase::request& globalbase,
                               const dregress::generation_t& generation,
                               const uint32_t& value_id,
                               const dregress::value_key_t& value_key)
{
	common::idp::updateGlobalBase::dregress_value_update::request request_update;

	const auto& [vrf_priority, attribute_destinations] = value_key;

	bool is_best = true;
	for (const auto& [attribute, destinations] : attribute_destinations)
	{
		(void)attribute;

		for (const auto& [nexthop, label, communities, peer_as, origin_as] : destinations)
		{
			(void)vrf_priority; ///< @todo
			auto community = generation.get_peer_link_community(communities);
			if (community)
			{
				request_update[value_id].emplace(nexthop,
				                                 label,
				                                 *community,
				                                 peer_as,
				                                 origin_as,
				                                 is_best);
			}
			else
			{
				request_update[value_id].emplace(nexthop,
				                                 label,
				                                 community_t(),
				                                 peer_as,
				                                 origin_as,
				                                 is_best);
			}
		}

		is_best = false;
	}

	if (request_update.size())
	{
		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::dregress_value_update,
		                        request_update);
	}
}
