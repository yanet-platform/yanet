#pragma once

#include <iostream>

#include "common/icontrolplane.h"

#include "helper.h"

namespace rib
{

void summary()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.rib_summary();

	table_t table;
	table.insert("vrf",
	             "priority",
	             "protocol",
	             "peer",
	             "table_name",
	             "prefixes",
	             "paths",
	             "eor");

	for (const auto& [key, value] : response)
	{
		const auto& [vrf, priority, protocol, peer, table_name] = key;
		const auto& [prefixes, paths, eor] = value;

		table.insert(vrf,
		             priority,
		             protocol,
		             peer,
		             table_name,
		             prefixes,
		             paths,
		             (bool)eor);
	}

	table.print();
}

void prefixes()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.rib_prefixes();

	table_t table;
	table.insert("vrf",
	             "priority",
	             "prefix",
	             "protocol",
	             "peer",
	             "table_name",
	             "path_information",
	             "nexthop",
	             "labels",
	             "local_preference",
	             "aspath",
	             "origin",
	             "med",
	             "communities",
	             "large_communities");

	for (const auto& [vrf_priority, prefix_nexthops] : response)
	{
		const auto& [vrf, priority] = vrf_priority;

		for (const auto& [prefix, nexthops] : prefix_nexthops)
		{
			for (const auto& [nexthop_key, nexthop_value] : nexthops)
			{
				const auto& [protocol, peer, table_name, path_information] = nexthop_key;
				const auto& [nexthop, labels, origin, med, aspath, communities, large_communities, local_preference] = nexthop_value;

				table.insert(vrf,
				             priority,
				             prefix,
				             protocol,
				             peer,
				             table_name,
				             path_information,
				             nexthop,
				             labels,
				             local_preference,
				             aspath,
				             origin,
				             med,
				             communities,
				             large_communities);
			}
		}
	}

	table.print();
}

void lookup(const std::string& vrf,
            const common::ip_address_t& address)
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.rib_lookup({vrf, address});

	table_t table;
	table.insert("vrf",
	             "priority",
	             "prefix",
	             "protocol",
	             "peer",
	             "table_name",
	             "path_information",
	             "nexthop",
	             "labels",
	             "local_preference",
	             "aspath",
	             "origin",
	             "med",
	             "communities",
	             "large_communities");

	for (const auto& [vrf_priority, prefix_nexthops] : response)
	{
		const auto& [vrf, priority] = vrf_priority;

		for (const auto& [prefix, nexthops] : prefix_nexthops)
		{
			for (const auto& [nexthop_key, nexthop_value] : nexthops)
			{
				const auto& [protocol, peer, table_name, path_information] = nexthop_key;
				const auto& [nexthop, labels, origin, med, aspath, communities, large_communities, local_preference] = nexthop_value;

				table.insert(vrf,
				             priority,
				             prefix,
				             protocol,
				             peer,
				             table_name,
				             path_information,
				             nexthop,
				             labels,
				             local_preference,
				             aspath,
				             origin,
				             med,
				             communities,
				             large_communities);
			}
		}
	}

	table.print();
}

void get(const std::string& vrf,
         const common::ip_prefix_t& prefix)
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.rib_get({vrf, prefix});

	table_t table;
	table.insert("vrf",
	             "priority",
	             "protocol",
	             "peer",
	             "table_name",
	             "path_information",
	             "nexthop",
	             "labels",
	             "local_preference",
	             "aspath",
	             "origin",
	             "med",
	             "communities",
	             "large_communities");

	for (const auto& [vrf_priority, prefix_nexthops] : response)
	{
		const auto& [vrf, priority] = vrf_priority;

		for (const auto& [prefix, nexthops] : prefix_nexthops)
		{
			for (const auto& [nexthop_key, nexthop_value] : nexthops)
			{
				const auto& [protocol, peer, table_name, path_information] = nexthop_key;
				const auto& [nexthop, labels, origin, med, aspath, communities, large_communities, local_preference] = nexthop_value;
				YANET_GCC_BUG_UNUSED(prefix);

				table.insert(vrf,
				             priority,
				             protocol,
				             peer,
				             table_name,
				             path_information,
				             nexthop,
				             labels,
				             local_preference,
				             aspath,
				             origin,
				             med,
				             communities,
				             large_communities);
			}
		}
	}

	table.print();
}

std::vector<std::string> split(const std::string& string,
                               char delimiter = ' ')
{
	std::vector<std::string> result;

	std::stringstream stream(string);
	std::string item;
	while (std::getline(stream, item, delimiter))
	{
		result.emplace_back(item);
	}

	return result;
}

void convert(const std::string& string,
             std::tuple<std::string, common::ip_address_t, std::vector<uint32_t>>& result)
{
	auto nexthop_label_string = split(string, '+');

	if (nexthop_label_string.size() == 1)
	{
		result = {string,
		          nexthop_label_string[0],
		          std::vector<uint32_t>()};
	}
	else
	{
		std::vector<uint32_t> labels;
		labels.emplace_back(std::stoll(nexthop_label_string[1], nullptr, 0));

		result = {string,
		          nexthop_label_string[0],
		          labels};
	}
}

void insert(const std::string& vrf,
            const common::ip_prefix_t& prefix,
            const common::ip_address_t& nexthop,
            std::optional<common::uint> label,
            std::optional<common::uint> peer_id,
            std::optional<common::uint> origin_as,
            std::optional<common::uint> weight)
{
	interface::controlPlane controlplane;

	std::string path_information = nexthop.toString();

	std::vector<uint32_t> labels;
	if (label)
	{
		path_information += "+" + label->toString();
		labels.emplace_back(*label);
	}

	if (peer_id)
	{
		path_information += ":" + peer_id->toString();
	}

	std::vector<uint32_t> aspath;
	if (origin_as)
	{
		aspath.emplace_back(*origin_as);
	}

	std::set<common::large_community_t> large_communities;
	if (weight)
	{
		large_communities.emplace(13238, 1, *weight); ///< @todo: DEFINE
	}

	common::icp::rib_update::insert insert = {"static",
	                                          vrf,
	                                          YANET_RIB_PRIORITY_DEFAULT,
	                                          {}};
	auto& nexthop_prefixes = std::get<3>(insert)[{common::ip_address_t("::"), "", 0, aspath, {}, large_communities, 0}][""];

	nexthop_prefixes[nexthop].emplace_back(prefix, path_information, labels);

	common::icp::rib_update::eor eor = {"static",
	                                    vrf,
	                                    YANET_RIB_PRIORITY_DEFAULT,
	                                    common::ip_address_t("::"),
	                                    ""};

	controlplane.rib_update({insert, eor});
	controlplane.rib_flush();
}

void remove(const std::string& vrf,
            const common::ip_prefix_t& prefix,
            const common::ip_address_t& nexthop,
            std::optional<common::uint> label,
            std::optional<common::uint> peer_id)
{
	interface::controlPlane controlplane;

	std::string path_information = nexthop.toString();

	std::vector<uint32_t> labels;
	if (label)
	{
		path_information += "+" + label->toString();
		labels.emplace_back(*label);
	}

	if (peer_id)
	{
		path_information += ":" + peer_id->toString();
	}

	common::icp::rib_update::remove remove = {"static",
	                                          vrf,
	                                          YANET_RIB_PRIORITY_DEFAULT,
	                                          {}};
	auto& prefixes = std::get<3>(remove)[common::ip_address_t("::")][""];

	prefixes.emplace_back(prefix, path_information, std::vector<uint32_t>());

	common::icp::rib_update::eor eor = {"static",
	                                    vrf,
	                                    YANET_RIB_PRIORITY_DEFAULT,
	                                    common::ip_address_t("::"),
	                                    ""};

	controlplane.rib_update({remove, eor});
	controlplane.rib_flush();
}

void save()
{
	interface::controlPlane controlplane;
	auto response = controlplane.rib_save();

	size_t size = response.size();
	std::cout.write((const char*)&size, sizeof(size));
	std::cout.write((const char*)response.data(), size);
}

void load()
{
	interface::controlPlane controlplane;

	size_t size = 0;
	common::icp::rib_load::request request;
	std::cin.read((char*)&size, sizeof(size));

	request.resize(size);

	std::cin.read((char*)request.data(), size);

	controlplane.rib_load(request);
	controlplane.rib_flush();
}

void clear(const std::string& protocol,
           const std::optional<common::ip_address_t>& peer,
           const std::optional<std::string>& vrf,
           const std::optional<uint32_t>& priority)
{
	if (!(peer.has_value() == vrf.has_value() &&
	      vrf.has_value() == priority.has_value()))
	{
		throw std::string("invalid arguments");
	}

	interface::controlPlane controlplane;

	common::icp::rib_update::clear rib_update_clear = {protocol, std::nullopt};
	if (peer)
	{
		std::get<1>(rib_update_clear) = {*peer, std::make_tuple(*vrf, *priority)};
	}

	common::icp::rib_update::request request;
	request.emplace_back(rib_update_clear);
	controlplane.rib_update(request);
	controlplane.rib_flush();
}

}
