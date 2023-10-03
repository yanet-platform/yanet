#pragma once

#include "common/icontrolplane.h"

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
		double percent = 0.0;
		if (maximum)
		{
			percent = (double)current / (double)maximum;
			percent *= (double)100;
		}

		std::stringstream stream;
		stream << std::fixed << std::setprecision(2) << percent;
		std::string percent_string = stream.str();

		table.insert(name,
		             socket_id,
		             current,
		             maximum,
		             percent_string);
	}

	table.print();
}

}
