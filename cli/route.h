#pragma once

#include "common/icontrolplane.h"

#include "helper.h"
#include "influxdb_format.h"

namespace route
{

void summary()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.route_summary();

	table_t table;
	table.insert("module",
	             "vrf");

	for (const auto& [route_name, vrf] : response)
	{
		table.insert(route_name,
		             vrf);
	}

	table.print();
}

void interface()
{
	interface::controlPlane controlplane;
	const auto response = controlplane.route_interface();

	table_t table;
	table.insert("module",
	             "interface",
	             "address",
	             "neighbor_v4",
	             "neighbor_v6",
	             "neighbor_mac_address_v4",
	             "neighbor_mac_address_v6",
	             "next_module");

	for (const auto& [key, value] : response)
	{
		const auto& [route_name, interface_name] = key;
		const auto& [address, neighbor_v4, neighbor_v6, neighbor_mac_address_v4, neighbor_mac_address_v6, next_module] = value;

		table.insert(route_name,
		             interface_name,
		             address,
		             neighbor_v4,
		             neighbor_v6,
		             neighbor_mac_address_v4,
		             neighbor_mac_address_v6,
		             next_module == "controlPlane" ? std::string("linux") : next_module);
	}

	table.print();
}

void lookup(const std::string& route_name,
            const common::ip_address_t& address)
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_lookup({route_name, address});

	table_t table;
	table.insert("ingress_physical_ports",
	             "prefix",
	             "nexthop",
	             "egress_interface",
	             "labels");

	for (const auto& item : response)
	{
		const auto& [ingress_physical_ports, prefix, nexthop, egress_interface, labels] = item;

		table.insert(ingress_physical_ports,
		             prefix,
		             nexthop.is_default() ? std::string("") : nexthop.toString(),
		             egress_interface,
		             labels);
	}

	table.print();
}

void get(const std::string& route_name,
         const common::ip_prefix_t& prefix)
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_get({route_name, prefix});

	table_t table;
	table.insert("ingress_physical_ports",
	             "nexthop",
	             "egress_interface",
	             "labels");

	for (const auto& item : response)
	{
		const auto& [ingress_physical_ports, prefix, nexthop, egress_interface, labels] = item;
		(void)prefix;

		table.insert(ingress_physical_ports,
		             nexthop.is_default() ? std::string("") : nexthop.toString(),
		             egress_interface,
		             labels);
	}

	table.print();
}

void counters(const std::optional<std::string>& format)
{
	bool use_table = true;
	if (format != std::nullopt)
	{
		if (*format == "influxdb")
		{
			use_table = false;
		}
		else if (*format != "table")
		{
			fprintf(stderr, "unknown output format: %s\n", format->c_str());
			return;
		}
	}
	interface::controlPlane controlplane;
	auto response = controlplane.route_counters();

	if (use_table)
	{
		table_t table;
		table.insert("peer",
		             "nexthop",
		             "prefix",
		             "counts",
		             "size");

		for (const auto& item : response)
		{
			const auto& [peer, nexthop, prefix, counts, size] = item;
			table.insert(peer, nexthop, prefix, counts, size);
		}

		table.print();
	}
	else
	{
		for (const auto& item : response)
		{
			const auto& [peer, nexthop, prefix, counts, size] = item;
			influxdb_format::print("route_counters", {{"peer", peer}, {"nexthop", nexthop}, {"prefix", prefix}}, {{"counts", counts}, {"size", size}});
		}
	}
}

namespace tunnel
{

void lookup(const std::string& route_name,
            const common::ip_address_t& address)
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_tunnel_lookup({route_name, address});

	table_t table;
	table.insert("ingress_physical_ports",
	             "prefix",
	             "nexthop",
	             "label",
	             "egress_interface",
	             "peer",
	             "weight (%)");

	for (const auto& item : response)
	{
		const auto& [ingress_physical_ports, prefix, nexthop, label, egress_interface, peer, weight_percent] = item;

		double percent = (double)100.0 * weight_percent;

		std::stringstream stream;
		stream << std::fixed << std::setprecision(2) << percent;
		std::string percent_string = stream.str();

		table.insert(ingress_physical_ports,
		             prefix,
		             nexthop.is_default() ? std::string("") : nexthop.toString(),
		             label,
		             egress_interface,
		             peer,
		             percent_string);
	}

	table.print();
}

void get(const std::string& route_name,
         const common::ip_prefix_t& prefix)
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_tunnel_get({route_name, prefix});

	table_t table;
	table.insert("ingress_physical_ports",
	             "nexthop",
	             "label",
	             "egress_interface",
	             "peer",
	             "weight (%)");

	for (const auto& item : response)
	{
		const auto& [ingress_physical_ports, prefix, nexthop, label, egress_interface, peer, weight_percent] = item;
		(void)prefix;

		double percent = (double)100.0 * weight_percent;

		std::stringstream stream;
		stream << std::fixed << std::setprecision(2) << percent;
		std::string percent_string = stream.str();

		table.insert(ingress_physical_ports,
		             nexthop.is_default() ? std::string("") : nexthop.toString(),
		             label,
		             egress_interface,
		             peer,
		             percent_string);
	}

	table.print();
}

}

}
