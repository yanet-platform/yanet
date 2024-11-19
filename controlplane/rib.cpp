#include "rib.h"
#include "controlplane.h"

using namespace controlplane::module;

rib_t::rib_t()
{
}

rib_t::~rib_t()
{
}

eResult rib_t::init()
{
	controlPlane->register_command(common::icp::requestType::rib_update, [this](const common::icp::request& request) {
		rib_update(std::get<common::icp::rib_update::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::rib_flush, [this]() {
		rib_flush(true);
	});

	controlPlane->register_command(common::icp::requestType::rib_summary, [this]() {
		return rib_summary();
	});

	controlPlane->register_command(common::icp::requestType::rib_prefixes, [this]() {
		return rib_prefixes();
	});

	controlPlane->register_command(common::icp::requestType::rib_lookup, [this](const common::icp::request& request) {
		return rib_lookup(std::get<common::icp::rib_lookup::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::rib_get, [this](const common::icp::request& request) {
		return rib_get(std::get<common::icp::rib_get::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::rib_save, [this]() {
		return rib_save();
	});

	controlPlane->register_command(common::icp::requestType::rib_load, [this](const common::icp::request& request) {
		rib_load(std::get<common::icp::rib_load::request>(std::get<1>(request)));
	});

	{ /// @todo: move to config
		common::icp::rib_update::insert request_insert = {"static",
		                                                  "default",
		                                                  YANET_RIB_PRIORITY_DEFAULT,
		                                                  {}};

		auto& prefixes = std::get<3>(request_insert)[{ip_address_t("::"), "", 0, {}, {}, {}, 0}]
		                                            [""]
		                                            [ip_address_t("::")];
		prefixes.emplace_back("fe80::/64", "", std::vector<uint32_t>());

		common::icp::rib_update::eor request_eor = {"static",
		                                            "default",
		                                            YANET_RIB_PRIORITY_DEFAULT,
		                                            ip_address_t("::"),
		                                            ""};

		rib_update({request_insert, request_eor});
	}

	funcThreads.emplace_back([this]() {
		rib_thread();
	});

	return eResult::success;
}

void rib_t::reload(const controlplane::base_t& base_prev,
                   const controlplane::base_t& base_next,
                   common::idp::updateGlobalBase::request& globalbase)
{
	(void)base_prev;
	(void)globalbase;

	common::icp::rib_update::request request;

	{
		common::icp::rib_update::clear clear{"config", std::nullopt};
		request.emplace_back(std::move(clear));
	}

	for (const auto& [vrf_name, rib_items] : base_next.rib)
	{
		common::icp::rib_update::insert request_insert = {"config",
		                                                  vrf_name,
		                                                  YANET_RIB_PRIORITY_DEFAULT,
		                                                  {}};

		for (const auto& rib_item : rib_items)
		{
			if (rib_item.is_tunnel)
			{
				common::large_community_t large_community(YANET_DEFAULT_BGP_AS, 1, 1);
				auto& prefixes = std::get<3>(request_insert)[{ip_address_t("::"), "", 0, {}, {}, {large_community}, 0}]
				                                            [""]
				                                            [rib_item.nexthop];
				prefixes.emplace_back(rib_item.prefix, YANET_STATIC_ROUTE_TUNNEL_PATH_INFORMATION, std::vector<uint32_t>(1, YANET_STATIC_ROUTE_TUNNEL_LABEL));
			}
			else
			{
				auto& prefixes = std::get<3>(request_insert)[{ip_address_t("::"), "", 0, {}, {}, {}, 0}]
				                                            [""]
				                                            [rib_item.nexthop];
				prefixes.emplace_back(rib_item.prefix, "", std::vector<uint32_t>());
			}
		}

		request.emplace_back(std::move(request_insert));
	}

	if (base_next.rib.size())
	{
		common::icp::rib_update::eor request_eor = {"config",
		                                            "default",
		                                            YANET_RIB_PRIORITY_DEFAULT,
		                                            ip_address_t("::"),
		                                            ""};
		request.emplace_back(std::move(request_eor));
	}

	rib_update(request);
}

void rib_t::rib_update(const common::icp::rib_update::request& request)
{
	std::lock_guard<std::mutex> rib_update_guard(rib_update_mutex);

	for (const auto& action : request)
	{
		if (std::holds_alternative<common::icp::rib_update::insert>(action))
		{
			rib_insert(std::get<common::icp::rib_update::insert>(action));
		}
		else if (std::holds_alternative<common::icp::rib_update::remove>(action))
		{
			rib_remove(std::get<common::icp::rib_update::remove>(action));
		}
		else if (std::holds_alternative<common::icp::rib_update::clear>(action))
		{
			rib_clear(std::get<common::icp::rib_update::clear>(action));
		}
		else if (std::holds_alternative<common::icp::rib_update::eor>(action))
		{
			rib_eor(std::get<common::icp::rib_update::eor>(action));
		}
	}

	need_flushing = true;
}

void rib_t::rib_insert(const common::icp::rib_update::insert& request)
{
	const auto& [protocol, vrf, priority, attribute_tables] = request;

	rib::vrf_priority_t vrf_priority = {vrf, priority};

	for (const auto& [attribute, tables] : attribute_tables)
	{
		const auto& [peer, origin, med, aspath, communities, large_communities, local_preference] = attribute;

		for (const auto& [table_name, nexthops] : tables)
		{
			std::lock_guard<std::mutex> prefixes_guard(prefixes_mutex);
			std::lock_guard<std::mutex> prefixes_rebuild_guard(prefixes_rebuild_mutex);
			std::lock_guard<std::mutex> summary_guard(summary_mutex);

			rib::pptn_t current_pptn = {protocol, peer, table_name};

			// is this {protocol, peer, table_name} known at all?
			bool new_pptn = true;
			pptn_index_t current_pptn_index = proto_peer_table_name.size();
			for (uint32_t i = 0; i < proto_peer_table_name.size(); ++i)
			{
				if (current_pptn == proto_peer_table_name[i])
				{
					new_pptn = false;
					current_pptn_index = i;
					break;
				}
			}

			if (new_pptn)
			{
				proto_peer_table_name.push_back(current_pptn);
				new_pptn = false;
			}

			for (const auto& [nexthop, nlris] : nexthops)
			{
				auto& [summary_prefixes, summary_paths, summary_eor] = this->summary[{vrf, priority, protocol, peer, table_name}];
				(void)summary_eor;

				for (const auto& [prefix, path_information, labels] : nlris)
				{
					unsigned int prefixes_diff = 1; // remember, that prefixes are counted for each {vrf, priority, protocol, peer, table_name}
					unsigned int paths_diff = 1;
					unsigned int nxthp_stff_diff = 1;

					rib::nexthop_stuff_t nxthp_stff = {nexthop,
					                                   labels,
					                                   origin,
					                                   med,
					                                   aspath,
					                                   communities,
					                                   large_communities,
					                                   local_preference};

					if (prefixes_to_path_info_to_nh_ptr.count(vrf_priority))
					{
						if (prefixes_to_path_info_to_nh_ptr[vrf_priority].count(prefix))
						{
							if (prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix].count(current_pptn_index))
							{
								// prefix exists for this vptn, does this path_info exist for this prefix + vppptn
								prefixes_diff = 0;

								if (prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix][current_pptn_index].count(path_information))
								{
									// path_info exists for this prefix + vppptn, time to update nexthop_stuff (obviously, if path_info exists, it is an update)
									paths_diff = 0;

									const rib::nexthop_stuff_t* old_nh_ptr = prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix][current_pptn_index][path_information];

									// if nexthop_stuff from the table and from request match, nothing to update
									if (*old_nh_ptr != nxthp_stff)
									{
										--nh_to_ref_count[*old_nh_ptr];

										// nothing references this nexthop_stuff (ref_count dropped to zero) - remove it
										if (nh_to_ref_count[*old_nh_ptr] == 0)
										{
											nh_to_ref_count.erase(*old_nh_ptr);
										}
									}
									else
									{
										nxthp_stff_diff = 0;
									}
								}
							}
						}
					}

					// this nexthop stuff may have existed for some other path_info
					auto [nh_to_ref_count_it, insert_result] = nh_to_ref_count.insert({nxthp_stff, 1});

					const rib::nexthop_stuff_t* nh_ptr = &(nh_to_ref_count_it->first);

					if (!insert_result) // nh already existed in table
					{
						auto& ref_count = nh_to_ref_count_it->second;
						++ref_count;
					}

					prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix][current_pptn_index][path_information] = nh_ptr;

					if (prefixes_diff || paths_diff || nxthp_stff_diff)
					{
						prefixes_reb[vrf_priority].insert(prefix);
					}

					summary_prefixes.value += prefixes_diff;
					summary_paths.value += paths_diff;
				}
			}
		}
	}
}

void rib_t::rib_remove(const common::icp::rib_update::remove& request)
{
	const auto& [protocol, vrf, priority, attribute_tables] = request;
	const auto vrf_priority = std::make_tuple(vrf, priority);

	for (const auto& [peer, tables] : attribute_tables)
	{
		for (const auto& [table_name, nlris] : tables)
		{
			std::lock_guard<std::mutex> prefixes_guard(prefixes_mutex);
			std::lock_guard<std::mutex> prefixes_rebuild_guard(prefixes_rebuild_mutex);
			std::lock_guard<std::mutex> summary_guard(summary_mutex);

			if (this->summary.count({vrf, priority, protocol, peer, table_name}) == 0)
			{
				// nothing to remove
				// TODO: counter?
				continue;
			}

			auto& [summary_prefixes, summary_paths, summary_eor] = this->summary[{vrf, priority, protocol, peer, table_name}];
			(void)summary_eor;

			rib::pptn_t current_pptn = {protocol, peer, table_name};

			for (const auto& [prefix, path_information, labels] : nlris)
			{
				(void)labels;

				unsigned int prefixes_diff = 0;
				unsigned int paths_diff = 0;

				if (prefixes_to_path_info_to_nh_ptr.count(vrf_priority))
				{
					if (prefixes_to_path_info_to_nh_ptr[vrf_priority].count(prefix))
					{
						pptn_index_t current_pptn_index = proto_peer_table_name.size();
						for (uint32_t i = 0; i < proto_peer_table_name.size(); ++i)
						{
							if (current_pptn == proto_peer_table_name[i])
							{
								current_pptn_index = i;
								break;
							}
						}

						// no such combination of proto-peer-table_name
						if (current_pptn_index == proto_peer_table_name.size())
						{
							break;
						}

						if (prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix].count(current_pptn_index))
						{
							if (prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix][current_pptn_index].count(path_information))
							{
								const rib::nexthop_stuff_t* nh_ptr = prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix][current_pptn_index][path_information];

								--nh_to_ref_count[*nh_ptr];

								// nexthop stuff is not referenced by any prefix anymore - remove it entirely
								if (nh_to_ref_count[*nh_ptr] == 0)
								{
									nh_to_ref_count.erase(*nh_ptr);
								}

								prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix][current_pptn_index].erase(path_information);
								paths_diff = 1;

								// even if prefix still exists for some other proto-peer-table_name, it is still updated and must be flushed to route_t tables
								prefixes_reb[vrf_priority].insert(prefix);

								if (prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix][current_pptn_index].empty())
								{
									prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix].erase(current_pptn_index);

									prefixes_diff = 1;

									if (prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix].empty())
									{
										prefixes_to_path_info_to_nh_ptr[vrf_priority].erase(prefix);

										if (prefixes_to_path_info_to_nh_ptr[vrf_priority].empty())
										{
											prefixes_to_path_info_to_nh_ptr.erase(vrf_priority);
										}
									}
								}
							}
						}
					}
				}

				summary_prefixes.value -= prefixes_diff;
				summary_paths.value -= paths_diff;

				if (summary_prefixes.value == 0) // is it possible to have zero paths and not zero prefixes?
				{
					this->summary.erase({vrf, priority, protocol, peer, table_name});
				}
			}
		}
	}
}

void rib_t::rib_clear(const common::icp::rib_update::clear& request)
{
	const auto& [request_protocol, request_attribute] = request;

	{
		std::lock_guard<std::mutex> summary_guard(summary_mutex);

		for (auto& [summary_key, summary_value] : this->summary)
		{
			const auto& [vrf, priority, protocol, peer, table_name] = summary_key;
			auto& [summary_prefixes, summary_paths, summary_eor] = summary_value;
			(void)table_name;
			(void)summary_prefixes;
			(void)summary_paths;

			if (protocol != request_protocol)
			{
				continue;
			}

			if (request_attribute)
			{
				const auto& [request_peer, request_vrf_priority] = *request_attribute;

				if (peer != request_peer)
				{
					continue;
				}

				if (std::make_tuple(vrf, priority) != request_vrf_priority)
				{
					continue;
				}
			}

			summary_eor = false;
		}
	}

	{
		std::lock_guard<std::mutex> prefixes_guard(prefixes_mutex);

		std::vector<rib::vrf_priority_t> vrf_priorities_to_remove;
		for (auto& [vrf_priority, prefixes_to_pptn_to_path_info_to_nh_ptr] : prefixes_to_path_info_to_nh_ptr)
		{
			if (request_attribute)
			{
				const auto& [request_peer, request_vrf_priority] = *request_attribute;
				(void)request_peer;

				if (request_vrf_priority != vrf_priority)
				{
					continue;
				}
			}

			std::vector<ip_prefix_t> prefixes_to_remove;
			for (auto& [prefix, pptn_to_path_info_to_nh_ptr] : prefixes_to_pptn_to_path_info_to_nh_ptr)
			{
				std::vector<pptn_index_t> pptns_to_remove;
				for (auto& [pptn_index, path_info_to_nh_ptr] : pptn_to_path_info_to_nh_ptr)
				{
					const auto& [protocol, peer, table_name] = proto_peer_table_name[pptn_index];
					(void)table_name;

					if (request_protocol != protocol)
					{
						continue;
					}

					if (request_attribute)
					{
						const auto& [request_peer, request_vrf_priority] = request_attribute.value();
						(void)request_vrf_priority;

						if (request_peer != peer)
						{
							continue;
						}
					}

					for (auto& [path_info, nh_ptr] : path_info_to_nh_ptr)
					{
						(void)path_info;
						--nh_to_ref_count[*nh_ptr];

						// nexthop stuff is not referenced by any prefix anymore - remove it entirely
						if (nh_to_ref_count[*nh_ptr] == 0)
						{
							nh_to_ref_count.erase(*nh_ptr);
						}
					}

					path_info_to_nh_ptr.clear();

					{
						std::lock_guard<std::mutex> prefixes_reb_guard(prefixes_rebuild_mutex);
						prefixes_reb[vrf_priority].insert(prefix);
					}

					pptns_to_remove.push_back(pptn_index);
				}

				for (auto pptn_to_remove : pptns_to_remove)
				{
					pptn_to_path_info_to_nh_ptr.erase(pptn_to_remove);
				}

				if (pptn_to_path_info_to_nh_ptr.empty())
				{
					prefixes_to_remove.push_back(prefix);
				}
			}

			for (auto prefix_to_remove : prefixes_to_remove)
			{
				prefixes_to_pptn_to_path_info_to_nh_ptr.erase(prefix_to_remove);
			}

			if (prefixes_to_pptn_to_path_info_to_nh_ptr.empty())
			{
				vrf_priorities_to_remove.push_back(vrf_priority);
			}
		}

		for (const auto& vrf_priority_to_remove : vrf_priorities_to_remove)
		{
			prefixes_to_path_info_to_nh_ptr.erase(vrf_priority_to_remove);
		}
	}

	{
		std::lock_guard<std::mutex> summary_guard(summary_mutex);

		std::vector<std::tuple<std::string,
		                       uint32_t,
		                       std::string,
		                       ip_address_t,
		                       std::string>>
		        summary_keys;
		summary_keys.reserve(this->summary.size());

		for (auto& [summary_key, summary_value] : this->summary)
		{
			const auto& [vrf, priority, protocol, peer, table_name] = summary_key;
			(void)summary_value;
			(void)table_name;

			if (protocol != request_protocol)
			{
				continue;
			}

			if (request_attribute)
			{
				const auto& [request_peer, request_vrf_priority] = *request_attribute;

				if (peer != request_peer)
				{
					continue;
				}

				if (std::make_tuple(vrf, priority) != request_vrf_priority)
				{
					continue;
				}
			}

			summary_keys.emplace_back(summary_key);
		}

		for (const auto& key : summary_keys)
		{
			this->summary.erase(key);
		}
	}
}

void rib_t::rib_eor(const common::icp::rib_update::eor& request)
{
	std::lock_guard<std::mutex> summary_guard(summary_mutex);

	const auto& [protocol, vrf, priority, peer, table_name] = request;

	auto& [summary_prefixes, summary_paths, summary_eor] = this->summary[{vrf, priority, protocol, peer, table_name}];
	(void)summary_prefixes;
	(void)summary_paths;

	summary_eor = true;
}

void rib_t::rib_flush(bool force_flush)
{
	bool flush;
	{
		std::lock_guard<std::mutex> rib_update_guard(rib_update_mutex);
		std::lock_guard<std::mutex> prefixes_guard(prefixes_mutex);
		std::lock_guard<std::mutex> prefixes_rebuild_guard(prefixes_rebuild_mutex);

		for (const auto& [vrf_priority, updated_prefixes] : prefixes_reb)
		{
			for (const auto& updated_prefix : updated_prefixes)
			{
				if (prefixes_to_path_info_to_nh_ptr.count(vrf_priority) &&
				    prefixes_to_path_info_to_nh_ptr[vrf_priority].count(updated_prefix) &&
				    prefixes_to_path_info_to_nh_ptr[vrf_priority][updated_prefix].size())
				{
					const auto& destination = prefixes_to_path_info_to_nh_ptr[vrf_priority][updated_prefix];

					controlPlane->route.prefix_update(vrf_priority, updated_prefix, proto_peer_table_name, destination);
					controlPlane->route.tunnel_prefix_update(vrf_priority, updated_prefix, destination);
					//controlPlane->route.linux_prefix_update(vrf_priority, updated_prefix, destination);
					controlPlane->dregress.prefix_insert(vrf_priority, updated_prefix, destination);
				}
				else
				{
					controlPlane->route.prefix_update(vrf_priority, updated_prefix, {}, std::monostate()); // TODO: get rid of third parameter
					controlPlane->route.tunnel_prefix_update(vrf_priority, updated_prefix, std::monostate());
					//controlPlane->route.linux_prefix_update(vrf_priority, updated_prefix, std::monostate());
					controlPlane->dregress.prefix_remove(vrf_priority, updated_prefix);
				}
			}
		}

		flush = force_flush || prefixes_reb.size();
		prefixes_reb.clear();

		need_flushing = false;
	}

	if (flush)
	{
		controlPlane->route.prefix_flush();
		controlPlane->dregress.prefix_flush();
	}
}

common::icp::rib_summary::response rib_t::rib_summary()
{
	std::lock_guard<std::mutex> summary_guard(summary_mutex);
	return {this->summary.begin(), this->summary.end()};
}

common::icp::rib_prefixes::response rib_t::rib_prefixes()
{
	std::lock_guard<std::mutex> prefixes_guard(prefixes_mutex);

	common::icp::rib_prefixes::response res;

	for (const auto& [vrf_priority, prefixes_to_pptn_to_path_info_to_nh_ptr] : prefixes_to_path_info_to_nh_ptr)
	{
		for (const auto& [prefix, pptn_to_path_info_to_nh_ptr] : prefixes_to_pptn_to_path_info_to_nh_ptr)
		{
			for (const auto& [pptn_index, path_info_to_nh_ptr] : pptn_to_path_info_to_nh_ptr)
			{
				const auto& [protocol, peer, table_name] = proto_peer_table_name[pptn_index];

				for (const auto& [path_info, nh_ptr] : path_info_to_nh_ptr)
				{
					res[vrf_priority][prefix][{protocol, peer, table_name, path_info}] = *nh_ptr;
				}
			}
		}
	}

	return res;
}

common::icp::rib_lookup::response rib_t::rib_lookup(const common::icp::rib_lookup::request& request)
{
	common::icp::rib_lookup::response result;

	const auto& [request_vrf, request_address] = request;

	std::lock_guard<std::mutex> prefixes_guard(prefixes_mutex);

	for (int mask = 0;
	     mask <= 128;
	     mask++)
	{
		if (request_address.is_ipv4() &&
		    mask > 32)
		{
			break;
		}

		ip_prefix_t prefix(request_address.applyMask(mask), mask);

		for (const auto& [vrf_priority, prefixes_to_pptn_to_path_info_to_nh_ptr] : prefixes_to_path_info_to_nh_ptr)
		{
			const auto& [vrf, priority] = vrf_priority;
			(void)priority;

			if (request_vrf != vrf)
			{
				continue;
			}

			if (prefixes_to_pptn_to_path_info_to_nh_ptr.count(prefix))
			{
				for (const auto& [pptn_index, path_info_to_nh_ptr] : prefixes_to_pptn_to_path_info_to_nh_ptr.at(prefix))
				{
					if (pptn_index > proto_peer_table_name.size())
					{
						// it is impossible to get here, however...
						// TODO: counter?
						continue;
					}

					const auto& [proto, peer, table_name] = proto_peer_table_name[pptn_index];

					for (const auto& [path_info, nh_ptr] : path_info_to_nh_ptr)
					{
						result[vrf_priority][prefix][{proto, peer, table_name, path_info}] = *nh_ptr;
					}
				}
			}
		}
	}

	return result;
}

common::icp::rib_get::response rib_t::rib_get(const common::icp::rib_get::request& request)
{
	common::icp::rib_get::response result;

	const auto& [request_vrf, request_prefix] = request;

	std::lock_guard<std::mutex> prefixes_guard(prefixes_mutex);

	for (const auto& [vrf_priority, prefixes_to_pptn_to_path_info_to_nh_ptr] : prefixes_to_path_info_to_nh_ptr)
	{
		const auto& [vrf, priority] = vrf_priority;
		(void)priority;

		if (request_vrf != vrf)
		{
			continue;
		}

		if (prefixes_to_pptn_to_path_info_to_nh_ptr.count(request_prefix))
		{
			for (const auto& [pptn_index, path_info_to_nh_ptr] : prefixes_to_pptn_to_path_info_to_nh_ptr.at(request_prefix))
			{
				if (pptn_index > proto_peer_table_name.size())
				{
					// it is impossible to get here, however...
					// TODO: counter?
					continue;
				}

				const auto& [proto, peer, table_name] = proto_peer_table_name[pptn_index];

				for (const auto& [path_info, nh_ptr] : path_info_to_nh_ptr)
				{
					result[vrf_priority][request_prefix][{proto, peer, table_name, path_info}] = *nh_ptr;
				}
			}
		}
	}

	return result;
}

common::icp::rib_save::response rib_t::rib_save()
{
	common::stream_out_t stream;

	{
		std::lock_guard<std::mutex> rib_update_guard(rib_update_mutex);
		std::lock_guard<std::mutex> prefixes_guard(prefixes_mutex);
		std::lock_guard<std::mutex> summary_guard(summary_mutex);

		stream.push(proto_peer_table_name);

		std::unordered_map<rib::nexthop_stuff_t, std::pair<uint32_t, uint32_t>> nh_to_index_ref_count_pair;
		uint32_t i = 0;
		for (const auto& [nh, ref_count] : nh_to_ref_count)
		{
			nh_to_index_ref_count_pair[nh] = {i, ref_count};
			++i;
		}

		stream.push(nh_to_index_ref_count_pair);

		std::unordered_map<rib::vrf_priority_t,
		                   std::unordered_map<ip_prefix_t,
		                                      std::unordered_map<uint32_t, // index from proto_peer_table_name
		                                                         std::unordered_map<std::string,
		                                                                            uint32_t // index from nh_ptr_to_index
		                                                                            >>>>
		        prefixes_to_save;

		for (const auto& [vrf_priority, prefixes_to_pptn_to_path_info_to_nh_ptr] : prefixes_to_path_info_to_nh_ptr)
		{
			for (const auto& [prefix, pptn_to_path_info_to_nh_ptr] : prefixes_to_pptn_to_path_info_to_nh_ptr)
			{
				for (const auto& [pptn_index, path_info_to_nh_ptr] : pptn_to_path_info_to_nh_ptr)
				{
					for (const auto& [path_info, nh_ptr] : path_info_to_nh_ptr)
					{
						uint32_t nh_index = nh_to_index_ref_count_pair[*nh_ptr].first;
						prefixes_to_save[vrf_priority][prefix][pptn_index][path_info] = nh_index;
					}
				}
			}
		}

		stream.push(prefixes_to_save);

		stream.push(summary);
	}

	return stream.getBuffer();
}

void rib_t::rib_load(const common::icp::rib_load::request& request)
{
	common::stream_in_t stream(request);

	decltype(this->proto_peer_table_name) proto_peer_table_name_loaded;
	std::unordered_map<rib::nexthop_stuff_t, std::pair<uint32_t, uint32_t>> nh_to_index_ref_count_pair_loaded;
	std::unordered_map<rib::vrf_priority_t,
	                   std::unordered_map<ip_prefix_t,
	                                      std::unordered_map<uint32_t, // index from proto_peer_table_name
	                                                         std::unordered_map<std::string,
	                                                                            uint32_t // index from nh_ptr_to_index
	                                                                            >>>>
	        prefixes_loaded;

	stream.pop(proto_peer_table_name_loaded);
	stream.pop(nh_to_index_ref_count_pair_loaded);
	stream.pop(prefixes_loaded);

	decltype(this->summary) summary;
	stream.pop(summary);

	{
		std::lock_guard<std::mutex> rib_update_guard(rib_update_mutex);
		std::lock_guard<std::mutex> prefixes_guard(prefixes_mutex);
		std::lock_guard<std::mutex> prefixes_rebuild_guard(prefixes_rebuild_mutex);
		std::lock_guard<std::mutex> summary_guard(summary_mutex);

		this->summary.swap(summary);

		// first get rid of all prefixes stored prior to rib_load(), they should be marked as rebuilt for rib_flush()
		for (const auto& [vrf_priority, prefixes_to_pptn_to_path_info_to_nh_ptr] : this->prefixes_to_path_info_to_nh_ptr)
		{
			for (const auto& [prefix, pptn_to_path_info_to_nh_ptr] : prefixes_to_pptn_to_path_info_to_nh_ptr)
			{
				(void)pptn_to_path_info_to_nh_ptr;
				this->prefixes_reb[vrf_priority].insert(prefix);
			}
		}

		proto_peer_table_name.swap(proto_peer_table_name_loaded);
		prefixes_to_path_info_to_nh_ptr.clear();
		nh_to_ref_count.clear();

		// getting relation between loaded nexthop_stuff_t objects and its indexes (to insert correct pointers to prefixes_to_path_info_to_nh_ptr)
		std::vector<const rib::nexthop_stuff_t*> nh_to_index(nh_to_index_ref_count_pair_loaded.size());
		for (const auto& [nh, index_ref_count_pair] : nh_to_index_ref_count_pair_loaded)
		{
			const auto& [index, ref_count] = index_ref_count_pair;
			auto [nh_to_ref_count_it, insert_result] = this->nh_to_ref_count.insert({nh, ref_count});
			(void)insert_result;

			const rib::nexthop_stuff_t* nh_ptr = &(nh_to_ref_count_it->first);

			nh_to_index[index] = nh_ptr;
		}

		// replace indexes with pointers from nh_to_ref_count, obtained on previous step
		for (const auto& [vrf_priority, prefixes_to_pptn_to_path_info_to_nh_index] : prefixes_loaded)
		{
			for (const auto& [prefix, pptn_to_path_info_to_nh_index] : prefixes_to_pptn_to_path_info_to_nh_index)
			{
				for (const auto& [pptn_index, path_info_to_nh_index] : pptn_to_path_info_to_nh_index)
				{
					for (const auto& [path_info, nh_index] : path_info_to_nh_index)
					{
						const rib::nexthop_stuff_t* nh_ptr = nh_to_index[nh_index];
						this->prefixes_to_path_info_to_nh_ptr[vrf_priority][prefix][pptn_index][path_info] = nh_ptr;

						// all loaded prefixes should be marked as rebuilt as well (as they or their routes might differ from stored)
						this->prefixes_reb[vrf_priority].insert(prefix);
					}
				}
			}
		}
	}
}

void rib_t::rib_thread()
{
	while (!flagStop)
	{
		if (need_flushing)
		{
			rib_flush();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds{200});
	}
}
