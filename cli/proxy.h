#pragma once

#include "common/icontrolplane.h"
#include "common/type.h"
#include <rte_mbuf.h>

namespace proxy
{

std::tuple<std::string, common::ip_address_t, std::string, uint16_t> ServiceTie(const common::proxy::ServiceHeader& service)
{
	std::string proto(controlplane::balancer::from_proto(service.proto));
	return std::tie(service.service, service.proxy_addr, proto, service.proxy_port);
}

void counters(std::optional<common::ip_address_t> proxy_ip,
              std::optional<std::string> proto_string,
              std::optional<uint16_t> proxy_port)
{
	std::optional<uint8_t> proto;
	if (proto_string)
	{
		proto = controlplane::balancer::to_proto(*proto_string);
	}

    interface::controlPlane controlplane;
	const auto response = controlplane.proxy_counters({proxy_ip, proto, proxy_port});
	
    TablePrinter table;
	std::vector<std::string> row = {"id", "service", "ip", "proto", "port"};
	for (tCounterId counter = 0; counter < static_cast<tCounterId>(proxy::service_counter::size); counter++)
	{
		row.push_back(proxy::service_counter_toString(static_cast<proxy::service_counter>(counter)));
	}
	table.insert_row(row.begin(), row.end());

	for (const auto& record : response)
	{
		const auto& [service_info, counters] = record;
		const std::tuple row = std::tuple_cat(std::tie(service_info.service_id), ServiceTie(service_info), counters);
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

void tables(std::optional<common::ip_address_t> proxy_ip,
            std::optional<std::string> proto_string,
            std::optional<uint16_t> proxy_port)
{
	std::optional<uint8_t> proto;
	if (proto_string)
	{
		proto = controlplane::balancer::to_proto(*proto_string);
	}

	interface::controlPlane controlplane;
	const auto response = controlplane.proxy_tables({proxy_ip, proto, proxy_port});

	TablePrinter table;
	table.insert_row("id", "service", "ip", "proto", "port", "socket_id",
					 "con_size", "con_count", "con_bucket",
					 "syn_size", "syn_count", "syn_bucket",
					 "lp_size", "lp_count",
					 "rl_size", "rl_count", "rl_bucket",
					 "cl_size", "cl_count", "cl_bucket");
	for (const auto& record : response)
	{
		const auto& header = record.header;
		const std::tuple row = std::tuple_cat(std::tie(header.service_id),
		                                      ServiceTie(header),
		                                      std::tie(header.socket_id),
		                                      record.connections.info(),
		                                      record.syn_connections.info(),
		                                      record.local_pool.info_short(),
		                                      record.rate_limiter.info(),
		                                      record.connection_limiter.info());
		table.insert_row(row);
	}

	table.Print();
}

void buckets(std::optional<common::ip_address_t> proxy_ip,
             std::optional<std::string> proto_string,
             std::optional<uint16_t> proxy_port)
{
	std::optional<uint8_t> proto;
	if (proto_string)
	{
		proto = controlplane::balancer::to_proto(*proto_string);
	}

    interface::controlPlane controlplane;
	const auto response = controlplane.proxy_buckets({proxy_ip, proto, proxy_port});

	size_t max_count = 0;
	for (const auto& [service_info, table_name, counts] : response)
	{
		GCC_BUG_UNUSED(service_info);
		GCC_BUG_UNUSED(table_name);
		max_count = std::max(max_count, counts.size());
	}
	
    TablePrinter table;
	std::vector<std::string> row = {"id", "service", "ip", "proto", "port", "socket_id", "table"};
	for (size_t count = 0; count < max_count; count++)
	{
		row.push_back(std::to_string(count));
	}
	table.insert_row(row.begin(), row.end());

	for (const auto& [service_info, table_name, counts] : response)
	{
		const auto& [name, addr, proto, port] = ServiceTie(service_info);
		std::vector<std::string> row = {std::to_string(service_info.service_id), name, addr.toString(), proto, std::to_string(port), std::to_string(service_info.socket_id), table_name};
		for (size_t count: counts)
		{
			if (count == 0)
			{
				row.push_back("-");
			}
			else
			{
				row.push_back(std::to_string(count));
			}
		}
        table.insert_row(row.begin(), row.end());
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
