#pragma once

#include "cli/helper.h"
#include "common/idataplane.h"

namespace neighbor
{

void show()
{
	interface::dataPlane dataplane;
	const auto response = dataplane.neighbor_show();

	FillAndPrintTable({"route_name",
	                   "interface_name",
	                   "ip_address",
	                   "mac_address"},
	                  response,
	                  {.optional_null = "static"});
}

void show_cache()
{
	interface::dataPlane dataplane;
	const auto response = dataplane.neighbor_show_cache();

	FillAndPrintTable({"interface_name",
	                   "ip_address",
	                   "mac_address",
	                   "last_update",
	                   "last_remove"},
	                  response,
	                  {.optional_null = "static"});
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

void flush()
{
	interface::dataPlane dataplane;
	dataplane.neighbor_flush();
}

}
