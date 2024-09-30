#pragma once

#include "common/icontrolplane.h"

#include "table_printer.h"

namespace dregress
{

void summary()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.dregress_config();

	TablePrinter table;
	table.insert_row("module",
	                 "ipv6_sources",
	                 "ipv6_destination",
	                 "ipv4_address",
	                 "ipv6_address",
	                 "udp_destination_port",
	                 "only_longest",
	                 "next_module");

	for (const auto& [module_name, dregress] : response)
	{
		table.insert_row(module_name,
		                 dregress.ipv6SourcePrefixes,
		                 dregress.ipv6DestinationPrefix,
		                 dregress.ipv4SourceAddress,
		                 dregress.ipv6SourceAddress,
		                 dregress.udpDestinationPort,
		                 dregress.onlyLongest,
		                 dregress.nextModule);
	}

	table.Print();
}

void announce()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.dregress_config();

	TablePrinter table;
	table.insert("module",
	             "announces");

	for (const auto& [module_name, dregress] : response)
	{
		table.insert_row(module_name,
		                 dregress.announces);
	}

	table.Print();
}

/** @todo
void lookup(const std::string& module,
            const common::ip_address_t& address)
{
}
*/

}
