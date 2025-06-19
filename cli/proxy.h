#pragma once

#include "common/icontrolplane.h"
#include "common/type.h"
#include <rte_mbuf.h>

namespace proxy
{

void services()
{
    interface::controlPlane controlplane;
	const auto response = controlplane.proxy_services();

    TablePrinter table;
	table.insert_row("service_id",
	                 "service_name",
                     "packets_in",
	                 "bytes_in",
	                 "packets_out",
	                 "bytes_out",
	                 "syn_count",
	                 "ping_count",
	                 "connections_count",
					 "service_bucket_overflow",
					 "failed_local_pool_allocation",
					 "failed_local_pool_search",
					 "failed_answer_service_syn_ack",
					 "ignored_size_update_detections",
					 "failed_check_syn_cookie",
					 "failed_search_client_service_ack",
					 "new_connections",
					 "new_syn_connections");

	for (const auto& record : response)
	{
        table.insert_row(record);
    }

    table.Print();
}

void connections(std::optional<proxy_service_id_t> service_id)
{
	interface::dataPlane dataplane;
	const auto response = dataplane.proxy_connections(service_id);

	TablePrinter table;
	table.insert_row("service_id",
	                 "src_addr",
	                 "src_port",
	                 "local_addr",
	                 "local_port");

	for (const auto& [service_id, src_addr, src_port, local_addr, local_port] : response)
	{
		table.insert_row(service_id, common::ipv4_address_t(rte_cpu_to_be_32(src_addr)).toString(), rte_cpu_to_be_16(src_port), common::ipv4_address_t(rte_cpu_to_be_32(local_addr)).toString(), rte_cpu_to_be_16(local_port));
	}

	table.Print();
}

void syn(std::optional<proxy_service_id_t> service_id)
{
	interface::dataPlane dataplane;
	const auto response = dataplane.proxy_syn(service_id);

	(void)response;

	TablePrinter table;
	table.insert_row("service_id",
	                 "src_addr",
	                 "src_port");

	for (const auto& [service_id, src_addr, src_port] : response)
	{
		table.insert_row(service_id, common::ipv4_address_t(rte_cpu_to_be_32(src_addr)).toString(), rte_cpu_to_be_16(src_port));
	}

	table.Print();
}

void local_pool(std::optional<proxy_service_id_t> service_id)
{
	interface::dataPlane dataplane;
	const auto response = dataplane.proxy_local_pool(service_id);

	TablePrinter table;
	table.insert_row("service_id",
					 "prefix",
					 "total_addresses",
					 "free_addresses",
					 "used_addresses");

	for (const auto& [service_id, prefix, total_addresses, free_addresses, used_addresses] : response)
	{
		table.insert_row(service_id, prefix, total_addresses, free_addresses, used_addresses);
	}

	table.Print();
}

}
