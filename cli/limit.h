#pragma once

#include "common/icontrolplane.h"

#include "common/utils.h"
#include "helper.h"

namespace limit
{

void summary()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.limit_summary();

	table_t table;
	table.insert("name",
	             "socket_id",
	             "current",
	             "maximum",
	             "percent");

	for (const auto& [name, socket_id, current, maximum] : response)
	{
		table.insert(name,
		             socket_id,
		             current,
		             maximum,
		             utils::to_percent(current, maximum));
	}

	table.print();
}

}
