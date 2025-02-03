#pragma once

#include "cli/helper.h"
#include "common/icontrolplane.h"

#include "common/utils.h"
#include "table_printer.h"

namespace route
{

void summary()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.route_summary();

	FillAndPrintTable({"module", "vrf"}, response);
}

void interface()
{
	interface::controlPlane controlplane;
	const auto response = controlplane.route_interface();

	TablePrinter table;
	table.insert_row("module",
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

		table.insert_row(route_name,
		                 interface_name,
		                 address,
		                 neighbor_v4,
		                 neighbor_v6,
		                 neighbor_mac_address_v4,
		                 neighbor_mac_address_v6,
		                 next_module == "controlPlane" ? std::string("linux") : next_module);
	}

	table.Print();
}

void lookup(const std::string& route_name,
            const common::ip_address_t& address)
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_lookup({route_name, address});

	TablePrinter table;
	table.insert_row("ingress_physical_ports",
	                 "prefix",
	                 "nexthop",
	                 "egress_interface",
	                 "labels");

	for (const auto& item : response)
	{
		const auto& [ingress_physical_ports, prefix, nexthop, egress_interface, labels] = item;

		table.insert_row(ingress_physical_ports,
		                 prefix,
		                 nexthop.is_default() ? std::string("") : nexthop.toString(),
		                 egress_interface,
		                 labels);
	}

	table.Print();
}

void get(const std::string& route_name,
         const common::ip_prefix_t& prefix)
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_get({route_name, prefix});

	TablePrinter table;
	table.insert_row("ingress_physical_ports",
	                 "nexthop",
	                 "egress_interface",
	                 "labels");

	for (const auto& item : response)
	{
		const auto& [ingress_physical_ports, prefix, nexthop, egress_interface, labels] = item;
		GCC_BUG_UNUSED(prefix);

		table.insert_row(ingress_physical_ports,
		                 nexthop.is_default() ? std::string("") : nexthop.toString(),
		                 egress_interface,
		                 labels);
	}

	table.Print();
}

void counters()
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_counters();

	FillAndPrintTable({"link", "nexthop", "prefix", "counts", "size"}, response);
}

namespace tunnel
{

void lookup(const std::string& route_name,
            const common::ip_address_t& address)
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_tunnel_lookup({route_name, address});

	TablePrinter table;
	table.insert_row("ingress_physical_ports",
	                 "prefix",
	                 "nexthop",
	                 "label",
	                 "egress_interface",
	                 "peer",
	                 "weight (%)");

	for (const auto& item : response)
	{
		const auto& [ingress_physical_ports, prefix, nexthop, label, egress_interface, peer, weight_percent] = item;

		table.insert_row(ingress_physical_ports,
		                 prefix,
		                 nexthop.is_default() ? std::string("") : nexthop.toString(),
		                 label,
		                 egress_interface,
		                 peer,
		                 utils::to_percent(weight_percent));
	}

	table.Print();
}

void get(const std::string& route_name,
         const common::ip_prefix_t& prefix)
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_tunnel_get({route_name, prefix});

	TablePrinter table;
	table.insert_row("ingress_physical_ports",
	                 "nexthop",
	                 "label",
	                 "egress_interface",
	                 "peer",
	                 "weight (%)");

	for (const auto& item : response)
	{
		const auto& [ingress_physical_ports, prefix, nexthop, label, egress_interface, peer, weight_percent] = item;
		GCC_BUG_UNUSED(prefix);

		table.insert_row(ingress_physical_ports,
		                 nexthop.is_default() ? std::string("") : nexthop.toString(),
		                 label,
		                 egress_interface,
		                 peer,
		                 utils::to_percent(weight_percent));
	}

	table.Print();
}

void counters()
{
	interface::controlPlane controlplane;
	auto response = controlplane.route_tunnel_counters();

	FillAndPrintTable({"link", "nexthop", "counts", "size"}, response);
}
}

}
