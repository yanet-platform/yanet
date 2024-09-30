#pragma once

#include "common/icontrolplane.h"
#include "table_printer.h"

namespace convert
{

inline void logical_module()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.convert("logical_module");

	TablePrinter table;
	table.insert("id",
	             "name");

	for (const auto& [id, name] : response)
	{
		table.insert(id, name);
	}

	table.print();
}

} /* namespace convert */
