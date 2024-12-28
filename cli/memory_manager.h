#pragma once

#include "common/idataplane.h"
#include "table_printer.h"

namespace memory_manager
{

void show()
{
	interface::dataPlane dataplane;

	const auto response = dataplane.memory_manager_stats();
	const auto& [response_memory_group, response_objects] = response;
	YANET_GCC_BUG_UNUSED(response_memory_group);

	TablePrinter table;
	table.insert_row("name", "socket_id", "current");

	uint64_t total = 0;
	for (const auto& [name, socket_id, current] : response_objects)
	{
		total += current;

		table.insert_row(name, socket_id, current);
	}

	table.insert_row("total", "n/s", total);

	table.Print();
}

void group()
{
	interface::dataPlane dataplane;

	const auto response = dataplane.memory_manager_stats();
	const auto& [response_memory_group, response_objects] = response;

	TablePrinter table;
	table.insert_row("group", "current", "maximum", "percent");

	std::map<std::string, ///< object_name
	         common::uint64> ///< current
	        currents;

	for (const auto& [name, socket_id, current] : response_objects)
	{
		YANET_GCC_BUG_UNUSED(socket_id);

		currents[name] = std::max(currents[name].value, current);
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
			percent = utils::to_percent(group_total, memory_group.limit);
		}

		table.insert_row(memory_group.name, group_total, maximum, percent);
	});

	table.Print();
}
}
