#pragma once

#include "common/idataplane.h"

#include "helper.h"

namespace neighbor
{

void show()
{
	interface::dataPlane dataplane;
	const auto response = dataplane.neighbor_show();

	table_t table({.optional_null = "static"});
	table.insert("route_name",
	             "interface_name",
	             "ip_address",
	             "mac_address",
	             "last_update");

	for (const auto& [route_name,
	                  interface_name,
	                  ip_address,
	                  mac_address,
	                  last_update] : response)
	{
		table.insert(route_name,
		             interface_name,
		             ip_address,
		             mac_address,
		             last_update);
	}

	table.print();
}

void insert(const std::string& route_name,
            const std::string& interface_name,
            const common::ip_address_t& ip_address,
            const common::mac_address_t& mac_address)
{
	interface::dataPlane dataplane;
	dataplane.neighbor_insert({route_name,
	                           interface_name,
	                           ip_address,
	                           mac_address});
}

void remove(const std::string& route_name,
            const std::string& interface_name,
            const common::ip_address_t& ip_address)
{
	interface::dataPlane dataplane;
	dataplane.neighbor_remove({route_name,
	                           interface_name,
	                           ip_address});
}

}
