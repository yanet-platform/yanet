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
	                 "connections_count");

	for (const auto& [service_id, service_name, packets_in, bytes_in, packets_out, bytes_out, syn_count, ping_count, connections_count] : response)
	{
        table.insert_row(service_id, service_name, packets_in, bytes_in, packets_out, bytes_out, syn_count, ping_count, connections_count);
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
	                 "local_port",
	                 "state");

	for (const auto& [service_id, src_addr, src_port, local_addr, local_port, state] : response)
	{
		table.insert_row(service_id, common::ipv4_address_t(rte_cpu_to_be_32(src_addr)).toString(), rte_cpu_to_be_16(src_port), common::ipv4_address_t(rte_cpu_to_be_32(local_addr)).toString(), rte_cpu_to_be_16(local_port), state);
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
}
