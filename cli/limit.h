#pragma once

#include "common/icontrolplane.h"

#include "common/utils.h"
#include "table_printer.h"

namespace limit
{

void summary()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.limit_summary();

	TablePrinter table;
	table.insert_row("name",
	                 "socket_id",
	                 "current",
	                 "maximum",
	                 "percent");

	for (const auto& [name, socket_id, current, maximum] : response)
	{
		table.insert_row(name, socket_id, current, maximum, utils::to_percent(current, maximum));
	}

	table.Print();
}

}
