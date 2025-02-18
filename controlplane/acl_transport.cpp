#include "acl_compiler.h"
#include "acl_network_table.h"

using namespace acl::compiler;

transport_t::transport_t(compiler_t* compiler) :
        compiler(compiler)
{
	clear();
}

void transport_t::clear()
{
	layers.clear();
	remap_group_ids.clear();
	group_id = 1;
	filters.clear();
	filter_ids.clear();
	filter_rule_ids.clear();
	filter_group_ids.clear();
	bitmask.clear();
	map.clear();
	reverse_map.clear();
	reverse_map_next.clear();
	variation.clear();
}

unsigned int transport_t::collect(const unsigned int rule_id,
                                  const filter& filter)
{
	auto it = filter_ids.find(filter);
	if (it == filter_ids.end())
	{
		filters.emplace_back(filter);
		filter_rule_ids.emplace_back();
		it = filter_ids.emplace_hint(it, filter, filter_ids.size());
	}

	filter_rule_ids[it->second].emplace_back(rule_id);
	return it->second;
}

void transport_t::prepare()
{
	/// prepare first layer
	get_layer(0);
}

void transport_t::create_variations()
{
	std::unordered_map<unsigned int, std::set<unsigned int>> group_id_transport_filters;

	for (unsigned int filter_id = 0; filter_id < compiler->network_table.filters.size(); ++filter_id)
	{
		for (tAclGroupId group_id : compiler->network_table.filter_id_group_ids[filter_id])
		{
			for (unsigned int rule_id : compiler->network_table.filter_id_rule_ids[filter_id])
			{
				group_id_transport_filters[group_id].emplace(compiler->rules[rule_id].transport_filter_id);
			}
		}
	}

	for (auto& [group_id, transport_filters] : group_id_transport_filters)
	{
		variation[std::move(transport_filters)].push_back(group_id);
	}
}

void transport_t::distribute()
{
	for (const auto& [filter_ids, network_table_group_ids] : variation)
	{
		unsigned int best_layer_id = 0;
		size_t best_filter_ids_count = std::numeric_limits<size_t>::max();

		for (unsigned int layer_id = 0;
		     layer_id < compiler->transport_layers_size_max;
		     layer_id++)
		{
			const auto& layer_filter_ids = get_layer(layer_id).filter_ids_set;
			auto contains_filter = [&layer_filter_ids](unsigned int id) {
				return layer_filter_ids.find(id) != layer_filter_ids.end();
			};

			if (layer_filter_ids.empty())
			{
				best_layer_id = layer_id;
				break;
			}

			// Check if all filters are already in the set
			if (std::all_of(filter_ids.begin(), filter_ids.end(), contains_filter))
			{
				best_layer_id = layer_id;
				break;
			}

			size_t new_size = layer_filter_ids.size() +
			                  // Count how many new filters would be added
			                  std::count_if(filter_ids.begin(), filter_ids.end(), std::not_fn(contains_filter));

			if (new_size < best_filter_ids_count)
			{
				best_layer_id = layer_id;
				best_filter_ids_count = new_size;
			}
		}

		layers[best_layer_id].filter_ids_set.insert(filter_ids.begin(), filter_ids.end());
		layers[best_layer_id].network_table_group_ids_set.insert(network_table_group_ids.begin(), network_table_group_ids.end());
	}
}

void transport_t::compile()
{
	for (unsigned int layer_id = 0;
	     layer_id < layers.size();
	     layer_id++)
	{
		auto& layer = layers[layer_id];

		for (const auto filter_id : layer.filter_ids_set)
		{
			const auto& filter = filters[filter_id];

			layer.protocol_id[filter_id] = layer.protocol.collect(filter.protocol);
			layer.tcp_source_id[filter_id] = layer.tcp_source.collect(filter.tcp_source);
			layer.tcp_destination_id[filter_id] = layer.tcp_destination.collect(filter.tcp_destination);
			layer.tcp_flags_id[filter_id] = layer.tcp_flags.collect(filter.tcp_flags);
			layer.udp_source_id[filter_id] = layer.udp_source.collect(filter.udp_source);
			layer.udp_destination_id[filter_id] = layer.udp_destination.collect(filter.udp_destination);
			layer.icmpv4_type_code_id[filter_id] = layer.icmp_type_code.collect(filter.icmpv4_type_code);
			layer.icmpv4_identifier_id[filter_id] = layer.icmp_identifier.collect(filter.icmpv4_identifier);
			layer.icmpv6_type_code_id[filter_id] = layer.icmp_type_code.collect(filter.icmpv6_type_code);
			layer.icmpv6_identifier_id[filter_id] = layer.icmp_identifier.collect(filter.icmpv6_identifier);

			layer.filter_ids_vec.emplace_back(filter_id);
		}

		for (const auto network_table_group_id : layer.network_table_group_ids_set)
		{
			layer.network_table_group_ids_vec.emplace_back(network_table_group_id);
		}

		layer.protocol.prepare();
		layer.tcp_source.prepare();
		layer.tcp_destination.prepare();
		layer.tcp_flags.prepare();
		layer.udp_source.prepare();
		layer.udp_destination.prepare();
		layer.icmp_type_code.prepare();
		layer.icmp_identifier.prepare();
	}

	for (unsigned int layer_id = 0;
	     layer_id < layers.size();
	     layer_id++)
	{
		auto& layer = layers[layer_id];

		layer.protocol.compile();
		layer.tcp_source.compile();
		layer.tcp_destination.compile();
		layer.tcp_flags.compile();
		layer.udp_source.compile();
		layer.udp_destination.compile();
		layer.icmp_type_code.compile();
		layer.icmp_identifier.compile();
	}
}

void transport_t::populate()
{
	for (unsigned int layer_id = 0;
	     layer_id < layers.size();
	     layer_id++)
	{
		auto& layer = layers[layer_id];

		layer.protocol.populate();
		layer.tcp_source.populate();
		layer.tcp_destination.populate();
		layer.tcp_flags.populate();
		layer.udp_source.populate();
		layer.udp_destination.populate();
		layer.icmp_type_code.populate();
		layer.icmp_identifier.populate();
	}
}

void transport_t::remap()
{
}

transport_t::layer& transport_t::get_layer(unsigned int layer_id)
{
	if (layer_id >= layers.size())
	{
		/// prepare new layer

		layers.resize(layer_id + 1);

		{
			auto& layer = layers[layer_id];
			layer.protocol_id.resize(filter_ids.size());
			layer.tcp_source_id.resize(filter_ids.size());
			layer.tcp_destination_id.resize(filter_ids.size());
			layer.tcp_flags_id.resize(filter_ids.size());
			layer.udp_source_id.resize(filter_ids.size());
			layer.udp_destination_id.resize(filter_ids.size());
			layer.icmpv4_type_code_id.resize(filter_ids.size());
			layer.icmpv4_identifier_id.resize(filter_ids.size());
			layer.icmpv6_type_code_id.resize(filter_ids.size());
			layer.icmpv6_identifier_id.resize(filter_ids.size());
		}
	}

	return layers[layer_id];
}
