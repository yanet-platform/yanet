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
	std::vector<std::string> row = {"id", "service", "ip", "proto", "port"};
	for (tCounterId counter = 0; counter < static_cast<tCounterId>(proxy::service_counter::size); counter++)
	{
		row.push_back(proxy::service_counter_toString(static_cast<proxy::service_counter>(counter)));
	}
	table.insert_row(row.begin(), row.end());

	for (const auto& record : response)
	{
		const auto& [service_id, service_name, service_ip, service_proto, service_port, counters] = record;
		const std::tuple row = std::tuple_cat(std::tie(service_id, service_name, service_ip, service_proto, service_port), counters);
        table.insert_row(row);
    }

	table.RemoveZeroColumns();
    table.Print();
}

void connections(std::string service_name)
{
	interface::controlPlane controlplane;
	const auto response = controlplane.proxy_connections(service_name);

	TablePrinter table;
	table.insert_row("service_name",
					 "src_addr",
	                 "src_port",
	                 "local_addr",
	                 "local_port",
					 "socket_id");

	for (const auto& [service_name, src_addr, src_port, local_addr, local_port, socket_id] : response)
	{
		table.insert_row(service_name, common::ipv4_address_t(rte_cpu_to_be_32(src_addr)).toString(), rte_cpu_to_be_16(src_port), common::ipv4_address_t(rte_cpu_to_be_32(local_addr)).toString(), rte_cpu_to_be_16(local_port), socket_id);
	}

	table.Print();
}

void syn(std::string service_name)
{
	interface::controlPlane controlplane;
	const auto response = controlplane.proxy_syn(service_name);
	// YANET_LOG_WARNING("\tsyn service_name=%s, response.size()=%ld\n", service_name.c_str(), response.size());

	TablePrinter table;
	table.insert_row("service_name",
					 "src_addr",
	                 "src_port",
	                 "local_addr",
	                 "local_port",
					 "socket_id");

	for (const auto& [service_name, src_addr, src_port, local_addr, local_port, socket_id] : response)
	{
		table.insert_row(service_name, common::ipv4_address_t(rte_cpu_to_be_32(src_addr)).toString(), rte_cpu_to_be_16(src_port), common::ipv4_address_t(rte_cpu_to_be_32(local_addr)).toString(), rte_cpu_to_be_16(local_port), socket_id);
	}

	table.Print();
}

void tables(std::optional<std::string> service_name)
{
	interface::controlPlane controlplane;
	const auto response = controlplane.proxy_tables(service_name);

	TablePrinter table;
	table.insert_row("service_id",
					 "service_name",
					 "socket_id",
					 "connections",
					 "max_connections",
					 "syn_connections",
					 "max_syn_connections",
					 "prefix",
					 "total_addresses",
					 "free_addresses",
					 "used_addresses");
	for (const auto& record : response)
	{
		table.insert_row(record);
	}

	table.Print();
}

void blacklist(std::string service_name)
{
	if (service_name.empty())
	{
		throw std::invalid_argument("service_name is empty");
	}

	interface::controlPlane controlplane;
	const auto response = controlplane.proxy_blacklist(service_name);

	uint64_t current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

	TablePrinter table{};
	table.insert_row("service_name",
					 "ip",
					 "time_until_ms",
					 "time_left_ms");
	for (const auto& [service_name, ip, time_until] : response)
	{
		uint64_t time_left = time_until > current_time_ms ? time_until - current_time_ms : 0;
		table.insert_row(service_name, ip, time_until, time_left);
	}
	table.Print();
}

void blacklist_add(std::string service_name, std::string ip, uint32_t timeout)
{
	if (service_name.empty())
	{
		throw std::invalid_argument("service_name is empty");
	}
	if (ip.empty())
	{
		throw std::invalid_argument("ip is empty");
	}
	if (timeout == 0)
	{
		throw std::invalid_argument("timeout is empty");
	}

	interface::controlPlane controlplane;
	controlplane.proxy_blacklist_add({service_name, ip, timeout});
}

void debug_counter_id(proxy_service_id_t service_id)
{
	interface::controlPlane controlplane;
	const auto [counter_id, counter_names] = controlplane.proxy_debug_counters_id(service_id);
	std::cout << counter_id;
	for (const auto& name : counter_names)
	{
		std::cout << " " << name;
	}
	std::cout << "\n";
}

}
