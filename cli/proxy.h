#pragma once

#include "common/icontrolplane.h"
#include "common/type.h"
#include <rte_mbuf.h>

namespace proxy
{

void counters()
{
    interface::controlPlane controlplane;
	const auto response = controlplane.proxy_counters();
	
    TablePrinter table;
	constexpr std::tuple row = std::tuple_cat(std::tie("service_id", "service_name"),
                        			  		  proxy::names);
	table.insert_row(row);

	for (const auto& record : response)
	{
		const std::tuple row = std::tuple_cat(std::tie(std::get<0>(record), std::get<1>(record)),
								   			  std::get<2>(record));
        table.insert_row(row);
    }

    table.Print();
}

void connections(proxy_service_id_t service_id)
{
	interface::dataPlane dataplane;
	const auto response = dataplane.proxy_connections(service_id);

	TablePrinter table;
	table.insert_row("src_addr",
	                 "src_port",
	                 "local_addr",
	                 "local_port");

	for (const auto& [src_addr, src_port, local_addr, local_port] : response)
	{
		table.insert_row(common::ipv4_address_t(rte_cpu_to_be_32(src_addr)).toString(), rte_cpu_to_be_16(src_port), common::ipv4_address_t(rte_cpu_to_be_32(local_addr)).toString(), rte_cpu_to_be_16(local_port));
	}

	table.Print();
}

void syn(proxy_service_id_t service_id)
{
	interface::dataPlane dataplane;
	const auto response = dataplane.proxy_syn(service_id);
	YANET_LOG_WARNING("\tsyn service_id=%d, response.size()=%ld\n", service_id, response.size());

	TablePrinter table;
	table.insert_row("src_addr",
	                 "src_port",
	                 "local_addr",
	                 "local_port");

	for (const auto& [src_addr, src_port, local_addr, local_port] : response)
	{
		table.insert_row(common::ipv4_address_t(rte_cpu_to_be_32(src_addr)).toString(), rte_cpu_to_be_16(src_port), common::ipv4_address_t(rte_cpu_to_be_32(local_addr)).toString(), rte_cpu_to_be_16(local_port));
	}

	table.Print();
}

void tables(std::optional<proxy_service_id_t> service_id)
{
	interface::dataPlane dataplane;
	const auto response = dataplane.proxy_tables(service_id);

	TablePrinter table;
	table.insert_row("service_id",
					 "connections",
					 "max_connections",
					 "syn_connections",
					 "max_syn_connections",
					 "prefix",
					 "total_addresses",
					 "free_addresses",
					 "used_addresses");
	for (const auto& [service_id, connections, max_connections, syn_connections, max_syn_connections, prefix, total_addresses, free_addresses, used_addresses] : response)
	{
		table.insert_row(service_id, connections, max_connections, syn_connections, max_syn_connections, prefix, total_addresses, free_addresses, used_addresses);
	}

	table.Print();
}

}
