#pragma once

#include "cli/helper.h"
#include "common/icontrolplane.h"

#include "table_printer.h"

namespace nat46clat
{

void summary()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.nat46clat_config();

	TablePrinter table;
	table.insert_row("module",
	                 "ipv6_source",
	                 "ipv6_destination",
	                 "next_module");

	for (const auto& [module_name, nat46clat] : response)
	{
		table.insert_row(module_name,
		                 nat46clat.ipv6_source,
		                 nat46clat.ipv6_destination,
		                 nat46clat.next_module);
	}

	table.Print();
}

void announce()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.nat46clat_announce();

	FillAndPrintTable({"module", "announces"}, response);
}

}
