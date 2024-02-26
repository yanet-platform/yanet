#pragma once

#include "common/idataplane.h"
#include "helper.h"

namespace memory_manager
{

void show()
{
	interface::dataPlane dataplane;

	const auto response = dataplane.memory_manager_stats();
	const auto& [response_memory_group, response_objects] = response;
	(void)response_memory_group;

	table_t table;
	table.insert("name",
	             "socket_id",
	             "current");

	uint64_t total = 0;
	for (const auto& [name, socket_id, current] : response_objects)
	{
		total += current;

		table.insert(name,
		             socket_id,
		             current);
	}

	table.insert("total",
	             "n/s",
	             total);

	table.print();
}

void group()
{
	interface::dataPlane dataplane;

	const auto response = dataplane.memory_manager_stats();
	const auto& [response_memory_group, response_objects] = response;

	table_t table;
	table.insert("group",
	             "current",
	             "maximum",
	             "percent");

	std::map<std::string, ///< object_name
	         common::uint64> ///< current
	        currents;

	for (const auto& [name, socket_id, current] : response_objects)
	{
		(void)socket_id;

		currents[name] = std::max(currents[name].value,
		                          current);
	}

	response_memory_group.for_each([&](const auto& memory_group,
	                                   const std::set<std::string>& object_names) {
		if (memory_group.name.empty())
		{
			return;
		}

		uint64_t group_total = 0;
		for (const auto& object_name : object_names)
		{
			group_total += currents[object_name];
		}

		std::optional<uint64_t> maximum;
		std::optional<std::string> percent;
		if (memory_group.limit)
		{
			maximum = memory_group.limit;
			percent = to_percent(group_total, memory_group.limit);
		}

		table.insert(memory_group.name,
		             group_total,
		             maximum,
		             percent);
	});

	table.print();
}

}
