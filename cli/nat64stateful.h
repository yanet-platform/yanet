#pragma once

#include "cli/helper.h"
#include "common/icontrolplane.h"
#include "common/idataplane.h"

#include "table_printer.h"

namespace nat64stateful
{

void summary()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.nat64stateful_config();

	TablePrinter table;
	table.insert_row("module",
	                 "ipv4_pool_size",
	                 "next_module");

	for (const auto& [name, nat64stateful] : response)
	{
		unsigned int ipv4_pool_size = 0;
		for (const auto& ipv4_prefix : nat64stateful.ipv4_prefixes)
		{
			ipv4_pool_size += (1u << (32 - ipv4_prefix.mask()));
		}

		table.insert_row(name,
		                 ipv4_pool_size,
		                 nat64stateful.next_module);
	}

	table.Print();
}

void announce()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.nat64stateful_announce();

	FillAndPrintTable({"module", "announces"}, response);
}

/// @todo: move
const std::string& proto_to_string(const uint8_t proto)
{
	/// @todo: std::array<256>
	static std::map<uint8_t, std::string> protocols = {{IPPROTO_TCP, "tcp"},
	                                                   {IPPROTO_UDP, "udp"},
	                                                   {IPPROTO_ICMP, "icmpv4"},
	                                                   {IPPROTO_ICMPV6, "icmpv6"},
	                                                   {IPPROTO_RAW, "unknown"}};

	auto it = protocols.find(proto);
	if (it == protocols.end())
	{
		return protocols.rend()->second;
	}

	return it->second;
}

/// @todo: move
std::optional<uint8_t> string_to_proto(const std::string& string)
{
	static std::map<std::string, uint8_t> protocols = {{"tcp", IPPROTO_TCP},
	                                                   {"udp", IPPROTO_UDP},
	                                                   {"icmpv4", IPPROTO_ICMP},
	                                                   {"icmpv6", IPPROTO_ICMPV6}};

	auto it = protocols.find(string);
	if (it == protocols.end())
	{
		return std::nullopt;
	}

	return it->second;
}

/// @todo: move
const std::string& tcp_flags_to_string(const uint8_t flags)
{
	static std::vector<std::string> results(1u << (8 * sizeof(uint8_t)));

	auto& result = results[flags];

	if (flags)
	{
		if (result.empty())
		{
			auto check_and_insert = [&](const uint8_t flag,
			                            const char* name) {
				if (flags & flag)
				{
					result += name;
					result.push_back(',');
				}
			};

			check_and_insert(TCP_SYN_FLAG, "syn");
			check_and_insert(TCP_ACK_FLAG, "ack");
			check_and_insert(TCP_PSH_FLAG, "psh");
			check_and_insert(TCP_FIN_FLAG, "fin");
			check_and_insert(TCP_RST_FLAG, "rst");
			check_and_insert(TCP_URG_FLAG, "urg");
			check_and_insert(TCP_ECN_FLAG, "ecn");
			check_and_insert(TCP_CWR_FLAG, "cwr");

			result.pop_back(); ///< remove last ','
		}
	}

	return result;
}

void state(std::optional<std::string> module)
{
	interface::controlPlane controlplane;
	auto config = controlplane.nat64stateful_config();

	std::optional<nat64stateful_id_t> module_id;
	if (module &&
	    *module != "any")
	{
		if (exist(config, *module))
		{
			module_id = config[*module].nat64stateful_id;
		}
		else
		{
			throw std::string("unknown module: '" + *module + "'");
		}
	}

	std::map<nat64stateful_id_t, std::string> modules;
	for (const auto& [module, nat64stateful] : config)
	{
		modules[nat64stateful.nat64stateful_id] = module;
	}

	interface::dataPlane dataplane;
	const auto response = dataplane.nat64stateful_state({module_id});

	TablePrinter table;
	table.insert_row("module",
	                 "ipv6_source",
	                 "ipv4_source",
	                 "ipv4_destination",
	                 "proto",
	                 "origin_port_source",
	                 "port_source",
	                 "port_destination",
	                 "lan_flags",
	                 "wan_flags",
	                 "lan_last_seen",
	                 "wan_last_seen");

	for (const auto& [nat64stateful_id,
	                  proto,
	                  ipv6_source,
	                  ipv6_destination,
	                  port_source,
	                  port_destination,
	                  ipv4_source,
	                  wan_port_source,
	                  lan_flags,
	                  wan_flags,
	                  lan_last_seen,
	                  wan_last_seen] : response)
	{
		auto it = modules.find(nat64stateful_id);
		if (it == modules.end())
		{
			it = modules.emplace_hint(it, nat64stateful_id, "unknown");
		}

		table.insert_row(it->second,
		                 ipv6_source,
		                 ipv4_source,
		                 ipv6_destination.get_mapped_ipv4_address().toString().data(),
		                 proto_to_string(proto).data(),
		                 port_source,
		                 wan_port_source,
		                 port_destination,
		                 tcp_flags_to_string(lan_flags),
		                 tcp_flags_to_string(wan_flags),
		                 lan_last_seen,
		                 wan_last_seen);
	}

	table.Print();
}

}
