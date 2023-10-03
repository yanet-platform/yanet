#pragma once

#include "common/idataplane.h"
#include "common/icontrolplane.h"

#include "helper.h"

namespace develop
{

namespace dataplane
{

static inline void printValue(const common::idp::value& value)
{
	const auto& type = std::get<0>(value);
	if (type == common::globalBase::eNexthopType::drop)
	{
		printf("  drop\n");
	}
	else if (type == common::globalBase::eNexthopType::interface)
	{
		for (const auto& iter : std::get<1>(value))
		{
			if (std::get<0>(std::get<1>(iter)) != common::unlabelled)
			{
				if (std::get<0>(std::get<2>(iter)) != common::unlabelled)
				{
					printf("  interfaceId: %u,\ttransport: [label: %u, exp: %u],\tservice: [label: %u, exp: %u]\n",
					       std::get<0>(iter),
					       std::get<0>(std::get<1>(iter)), std::get<1>(std::get<1>(iter)),
					       std::get<0>(std::get<2>(iter)), std::get<1>(std::get<2>(iter)));
				}
				else
				{
					printf("  interfaceId: %u,\ttransport: [label: %u, exp: %u]\n",
					       std::get<0>(iter),
					       std::get<0>(std::get<1>(iter)), std::get<1>(std::get<1>(iter)));
				}
			}
			else
			{
				printf("  interfaceId: %u\n",
				       std::get<0>(iter));
			}
		}
	}
	else if (type == common::globalBase::eNexthopType::controlPlane)
	{
		printf("  controlPlane\n");
	}
	else
	{
		printf("  error\n");
	}
}

void lpm4LookupAddress(const common::ipv4_address_t& address)
{
	interface::dataPlane dataPlane;
	const auto response = dataPlane.lpm4LookupAddress(address);
	for (const auto& iter : response)
	{
		const auto& socketId = iter.first;
		const auto& found = std::get<0>(iter.second);
		const auto& valueId = std::get<1>(iter.second);
		const auto& value = std::get<2>(iter.second);

		printf("[socketId: %u] %s -> ", socketId, common::ipv4_address_t(address).toString().data());
		if (found)
		{
			printf("valueId: %u\n", valueId);
			printValue(value);
		}
		else
		{
			printf("not found\n");
		}
	}
}

void lpm6LookupAddress(const common::ipv6_address_t& ipv6Address)
{
	interface::dataPlane dataPlane;
	const auto response = dataPlane.lpm6LookupAddress(ipv6Address);
	for (const auto& iter : response)
	{
		const auto& socketId = iter.first;
		const auto& found = std::get<0>(iter.second);
		const auto& valueId = std::get<1>(iter.second);
		const auto& value = std::get<2>(iter.second);

		printf("[socketId: %u] %s -> ", socketId, common::ipv6_address_t(ipv6Address).toString().data());
		if (found)
		{
			printf("valueId: %u\n", valueId);
			printValue(value);
		}
		else
		{
			printf("not found\n");
		}
	}
}

void getErrors()
{
	interface::dataPlane dataPlane;
	const auto response = dataPlane.getErrors();

	printf("errors:\n");
	for (const auto& iter: response)
	{
		printf("  (%lu) %s\n",
		       iter.second.value,
		       iter.first.data());
	}
}

void getReport()
{
	interface::dataPlane dataPlane;
	const auto response = dataPlane.getReport();
	printf("%s\n", response.data());
}

void counter(const uint32_t& counter_id,
             const std::optional<uint32_t>& range_size)
{
	interface::dataPlane dataplane;

	std::vector<tCounterId> counter_ids = {counter_id};
	if (range_size && (*range_size) > 0)
	{
		for (uint32_t offset = 0;
		     offset < (*range_size) - 1;
		     offset++)
		{
			counter_ids.emplace_back(counter_id + offset + 1);
		}
	}

	const auto response = dataplane.getCounters(counter_ids);

	table_t table;
	table.insert("counter_id",
	             "value");

	for (uint32_t i = 0;
	     i < counter_ids.size();
	     i++)
	{
		table.insert(counter_ids[i],
		             response[i]);
	}

	table.print();
}

}

}
