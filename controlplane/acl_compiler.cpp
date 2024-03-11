#include "acl_compiler.h"
#include "acl_filter.h"

using namespace acl;

compiler_t::compiler_t() :
        transport_layers_size_max(1),
        transport_layers_shift(0),
        network_ipv4_source(this),
        network_ipv4_destination(this),
        network_ipv6_source(this),
        network_ipv6_destination(this),
        network_table(this),
        transport(this),
        transport_table(this),
        total_table(this)
{
}

void compiler_t::compile(const std::vector<rule_t>& unwind_rules,
                         result_t& result,
                         const unsigned int transport_layers_size_max)
{
	this->transport_layers_size_max = transport_layers_size_max;
	this->transport_layers_shift = __builtin_popcount(transport_layers_size_max - 1);

	YANET_LOG_INFO("acl::compile: rules: %lu\n", unwind_rules.size());

	YANET_LOG_INFO("acl::compile: clear\n");
	clear();

	YANET_LOG_INFO("acl::compile: collect\n");
	collect(unwind_rules);

	YANET_LOG_INFO("acl::compile: network_compile\n");
	network_compile();

	YANET_LOG_INFO("acl::compile: network_table_compile\n");
	network_table_compile();

	YANET_LOG_INFO("acl::compile: network_flags_compile\n");
	network_flags_compile();

	YANET_LOG_INFO("acl::compile: transport_compile\n");
	transport_compile();

	YANET_LOG_INFO("acl::compile: transport_table_compile\n");
	transport_table_compile();

	YANET_LOG_INFO("acl::compile: total_table_compile\n");
	total_table_compile();

	YANET_LOG_INFO("acl::compile: value_compile\n");
	value_compile();

	YANET_LOG_INFO("acl::compile: result\n");

	{
		result.acl_network_ipv6_destination_ht.reserve(network_ipv6_destination_hosts.size());
		for (const auto& address : network_ipv6_destination_hosts)
		{
			auto group_id = network_ipv6_destination.tree.lookup(address);
			result.acl_network_ipv6_destination_ht.emplace_back(address, group_id);
		}
	}

	result.acl_network_ipv4_source.swap(network_ipv4_source.tree.chunks);
	result.acl_network_ipv4_destination.swap(network_ipv4_destination.tree.chunks);
	result.acl_network_ipv6_source.swap(network_ipv6_source.tree.chunks);
	result.acl_network_ipv6_destination.swap(network_ipv6_destination.tree.chunks);

	{
		auto& [width, values] = result.acl_network_table;
		width = network_table.width;
		values.swap(network_table.values);
	}

	result.acl_network_flags.swap(network_flags.filters);

	for (auto& layer : transport.layers)
	{
		result.acl_transport_layers.emplace_back(std::move(layer.protocol.filters),
		                                         std::move(layer.tcp_source.filters),
		                                         std::move(layer.tcp_destination.filters),
		                                         std::move(layer.tcp_flags.filters),
		                                         std::move(layer.udp_source.filters),
		                                         std::move(layer.udp_destination.filters),
		                                         std::move(layer.icmp_type_code.filters),
		                                         std::move(layer.icmp_identifier.filters));
	}

	result.acl_transport_tables.clear();
	for (const auto& thread : transport_table.threads)
	{
		result.acl_transport_tables.emplace_back(std::move(thread.acl_transport_table));
	}

	result.acl_total_table.reserve(total_table.table.size());
	for (const auto& [key, value] : total_table.table)
	{
		result.acl_total_table.emplace_back(key, value);
	}

	result.acl_values.swap(value.vector);

	YANET_LOG_INFO("acl::compile: done\n");
}

void compiler_t::clear()
{
	rules.clear();

	network_ipv4_source.clear();
	network_ipv4_destination.clear();
	network_ipv6_source.clear();
	network_ipv6_destination.clear();
	network_table.clear();
	network_flags.clear();
	transport.clear();
	transport_table.clear();
	total_table.clear();
	value.clear();

	network_ipv6_destination_hosts.clear();

	source_group_id = 0; ///< @todo: 1
	destination_group_id = 0; ///< @todo: 1

	used_rules.clear();
}

void compiler_t::collect(const std::vector<rule_t>& unwind_rules)
{
	for (unsigned int rule_id = 0;
	     rule_id < unwind_rules.size();
	     rule_id++)
	{
		const auto& unwind_rule = unwind_rules[rule_id];
		auto& rule = rules.emplace_back(rule_id);

		/// network
		{
			std::set<network_t> network_ipv4_source_filter;
			std::set<network_t> network_ipv4_destination_filter;
			std::set<network_t> network_ipv6_source_filter;
			std::set<network_t> network_ipv6_destination_filter;
			bool src_family[7];
			bool dst_family[7];

			src_family[4] = false;
			src_family[6] = false;
			dst_family[4] = false;
			dst_family[6] = false;

			if (unwind_rule.filter->src &&
			    unwind_rule.filter->src->networks.size())
			{
				for (const auto& network : unwind_rule.filter->src->networks)
				{
					if (network.family == 4)
					{
						network_ipv4_source_filter.emplace(network.normalize());
					}
					else
					{
						network_ipv6_source_filter.emplace(network.normalize());
					}

					src_family[network.family] = true;
				}
			}
			else
			{
				network_ipv4_source_filter.emplace(network_t(4, 0, 0));
				network_ipv6_source_filter.emplace(network_t(6, 0, 0));

				src_family[4] = true;
				src_family[6] = true;
			}

			if (unwind_rule.filter->dst &&
			    unwind_rule.filter->dst->networks.size())
			{
				for (const auto& network : unwind_rule.filter->dst->networks)
				{
					if (network.family == 4)
					{
						network_ipv4_destination_filter.emplace(network.normalize());
					}
					else
					{
						network_ipv6_destination_filter.emplace(network.normalize());
					}

					dst_family[network.family] = true;
				}
			}
			else
			{
				network_ipv4_destination_filter.emplace(network_t(4, 0, 0));
				network_ipv6_destination_filter.emplace(network_t(6, 0, 0));

				dst_family[4] = true;
				dst_family[6] = true;
			}

			if (!(src_family[4] && dst_family[4]))
			{
				network_ipv4_source_filter.clear();
				network_ipv4_destination_filter.clear();
			}

			if (!(src_family[6] && dst_family[6]))
			{
				network_ipv6_source_filter.clear();
				network_ipv6_destination_filter.clear();
			}

			rule.network_ipv4_source_filter_id = network_ipv4_source.collect(network_ipv4_source_filter);
			rule.network_ipv4_destination_filter_id = network_ipv4_destination.collect(network_ipv4_destination_filter);
			rule.network_ipv6_source_filter_id = network_ipv6_source.collect(network_ipv6_source_filter);
			rule.network_ipv6_destination_filter_id = network_ipv6_destination.collect(network_ipv6_destination_filter);

			for (const auto& network : network_ipv6_destination_filter)
			{
				if (!(network.mask + 1)) ///< */128
				{
					/// @todo: store */128, */127 ... */120
					network_ipv6_destination_hosts.emplace(network.addr);
				}
			}
		}

		/// network_table
		{
			rule.network_table_filter_id = network_table.collect(rule_id,
			                                                     std::tie(rule.network_ipv4_source_filter_id,
			                                                              rule.network_ipv4_destination_filter_id,
			                                                              rule.network_ipv6_source_filter_id,
			                                                              rule.network_ipv6_destination_filter_id));
		}

		/// network_flags
		{
			compiler::filter_network_flag filter(unwind_rule);
			rule.network_flags_filter_id = network_flags.collect(filter.fragment);
		}

		/// transport
		{
			compiler::filter_transport filter(unwind_rule);
			rule.transport_filter_id = transport.collect(rule_id, filter);
		}

		/// transport_table
		{
			rule.transport_table_filter_id = transport_table.collect(rule_id,
			                                                         std::tie(rule.network_table_filter_id,
			                                                                  rule.network_flags_filter_id,
			                                                                  rule.transport_filter_id));
		}

		/// via
		{
			rule.via_filter_id = unwind_rule.filter->acl_id->val; ///< @todo
		}

		/// total_table
		{
			rule.total_table_filter_id = total_table.collect(rule_id,
			                                                 std::tie(rule.via_filter_id,
			                                                          rule.transport_table_filter_id));
		}

		/// value
		{
			if (auto flow = std::get_if<common::globalBase::tFlow>(&unwind_rule.action))
			{
				rule.value_filter_id = value.collect({*flow});
			}
			else if (auto action = std::get_if<common::acl::action_t>(&unwind_rule.action))
			{
				rule.value_filter_id = value.collect({*action});
			}
		}

		/// terminating
		{
			rule.terminating = std::holds_alternative<common::globalBase::tFlow>(unwind_rule.action);
		}

		YANET_LOG_DEBUG("acl::compile: rule: %s\n", unwind_rule.to_string().data());
		YANET_LOG_DEBUG("acl::compile: terminating: %s\n", rule.terminating ? "true" : "false");
		YANET_LOG_DEBUG("acl::compile: rule_id: %u\n", rule.rule_id);
		YANET_LOG_DEBUG("acl::compile: network_ipv4_source_filter_id: %u\n", rule.network_ipv4_source_filter_id);
		YANET_LOG_DEBUG("acl::compile: network_ipv4_destination_filter_id: %u\n", rule.network_ipv4_destination_filter_id);
		YANET_LOG_DEBUG("acl::compile: network_ipv6_source_filter_id: %u\n", rule.network_ipv6_source_filter_id);
		YANET_LOG_DEBUG("acl::compile: network_ipv6_destination_filter_id: %u\n", rule.network_ipv6_destination_filter_id);
		YANET_LOG_DEBUG("acl::compile: network_table_filter_id: %u\n", rule.network_table_filter_id);
		YANET_LOG_DEBUG("acl::compile: network_flags_filter_id: %u\n", rule.network_flags_filter_id);
		YANET_LOG_DEBUG("acl::compile: transport_filter_id: %u\n", rule.transport_filter_id);
		YANET_LOG_DEBUG("acl::compile: transport_table_filter_id: %u\n", rule.transport_table_filter_id);
		YANET_LOG_DEBUG("acl::compile: via_filter_id: %u\n", rule.via_filter_id);
		YANET_LOG_DEBUG("acl::compile: total_table_filter_id: %u\n", rule.total_table_filter_id);
		YANET_LOG_DEBUG("acl::compile: value_filter_id: %u\n", rule.value_filter_id);
	}

	YANET_LOG_INFO("acl::compile: network.filters: %lu, %lu, %lu, %lu\n",
	               network_ipv4_source.filters.size(),
	               network_ipv4_destination.filters.size(),
	               network_ipv6_source.filters.size(),
	               network_ipv6_destination.filters.size());

	YANET_LOG_INFO("acl::compile: network_table.filters: %lu\n",
	               network_table.filters.size());

	YANET_LOG_INFO("acl::compile: network_flags.filters: %lu\n",
	               network_flags.filters.size());

	YANET_LOG_INFO("acl::compile: transport.filters: %lu\n",
	               transport.filters.size());

	YANET_LOG_INFO("acl::compile: transport_table.filters: %lu\n",
	               transport_table.filters.size());

	YANET_LOG_INFO("acl::compile: total_table.filters: %lu\n",
	               total_table.filters.size());

	YANET_LOG_INFO("acl::compile: value.filters: %lu\n",
	               value.filters.size());
}

void compiler_t::network_compile()
{
	network_ipv4_source.prepare();
	network_ipv4_destination.prepare();
	network_ipv6_source.prepare();
	network_ipv6_destination.prepare();

	network_ipv4_source.compile();
	network_ipv4_destination.compile();
	network_ipv6_source.compile();
	network_ipv6_destination.compile();

	YANET_LOG_INFO("acl::compile: extended_chunks: %lu, %lu, %lu, %lu\n",
	               network_ipv4_source.tree.chunks.size(),
	               network_ipv4_destination.tree.chunks.size(),
	               network_ipv6_source.tree.chunks.size(),
	               network_ipv6_destination.tree.chunks.size());

	network_ipv4_source.populate();
	network_ipv4_destination.populate();
	network_ipv6_source.populate();
	network_ipv6_destination.populate();

	YANET_LOG_INFO("acl::compile: group_ids: %lu, %lu, %lu, %lu\n",
	               network_ipv4_source.reverse_map.size(),
	               network_ipv4_destination.reverse_map.size(),
	               network_ipv6_source.reverse_map.size(),
	               network_ipv6_destination.reverse_map.size());

	network_ipv4_source.remap(source_group_id);
	network_ipv4_destination.remap(destination_group_id);
	network_ipv6_source.remap(source_group_id);
	network_ipv6_destination.remap(destination_group_id);

	YANET_LOG_INFO("acl::compile: collisions: %u, %u, %u, %u\n",
	               network_ipv4_source.collisions,
	               network_ipv4_destination.collisions,
	               network_ipv6_source.collisions,
	               network_ipv6_destination.collisions);
}

void compiler_t::network_table_compile()
{
	network_table.prepare(source_group_id, destination_group_id);

	YANET_LOG_INFO("acl::compile: size: %lu\n",
	               network_table.values.size());

	network_table.compile();
	network_table.populate();

	YANET_LOG_INFO("acl::compile: group_ids: %lu\n",
	               network_table.group_id_filter_ids.size());
}

void compiler_t::network_flags_compile()
{
	network_flags.prepare();
	network_flags.compile();
	network_flags.populate();

	YANET_LOG_INFO("acl::compile: group_ids: %lu\n",
	               network_flags.used_group_ids_set.size());
}

void compiler_t::transport_compile()
{
	transport.prepare();

	std::set<unsigned int> transport_filters;
	for (const auto& [network_table_group_id, network_table_filter_ids] : network_table.group_id_filter_ids)
	{
		transport_filters.clear();

		for (const auto network_table_filter_id : network_table_filter_ids)
		{
			for (const auto rule_id : network_table.filter_id_rule_ids[network_table_filter_id])
			{
				transport_filters.emplace(rules[rule_id].transport_filter_id);
			}
		}

		transport.emplace_variation(network_table_group_id, transport_filters);
	}

	YANET_LOG_INFO("acl::compile: variations: %lu\n",
	               transport.variation.size());

	transport.distribute();

	YANET_LOG_INFO("acl::compile: layers: %lu\n",
	               transport.layers.size());

	transport.compile();
	transport.populate();

	/// remap group ids after distribute
	network_table.remap();
}

void compiler_t::transport_table_compile()
{
	transport_table.prepare();
	transport_table.compile();
	transport_table.populate();

	size_t size = 0;
	size_t group_ids = 0;
	for (const auto& thread : transport_table.threads)
	{
		size += thread.acl_transport_table.size();
		group_ids += thread.group_id_filter_ids.size();
	}
	YANET_LOG_INFO("acl::compile: size: %lu\n",
	               size);
	YANET_LOG_INFO("acl::compile: group_ids: %lu\n",
	               group_ids);
}

void compiler_t::total_table_compile()
{
	total_table.prepare();
	total_table.compile();

	YANET_LOG_INFO("acl::compile: size: %lu\n",
	               total_table.table.size());
}

void compiler_t::value_compile()
{
	value.compile();
	YANET_LOG_INFO("acl::compile: size: %lu\n",
	               value.vector.size());
}
