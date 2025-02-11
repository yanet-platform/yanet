#include "acl_network_table.h"
#include "acl_compiler.h"

using namespace acl::compiler;

network_table_t::network_table_t(acl::compiler_t* compiler) :
        compiler(compiler)
{
	clear();
}

void network_table_t::clear()
{
	width = 0;
	table.clear();
	remap_group_ids.clear();
	group_id = 1;
	filters.clear();
	filter_ids.clear();
	filter_id_rule_ids.clear();
	filter_id_group_ids.clear();
	filter_id_group_ids_next.clear();
}

unsigned int network_table_t::collect(const unsigned int rule_id,
                                      const filter& filter)
{
	auto it = filter_ids.find(filter);
	if (it == filter_ids.end())
	{
		filters.emplace_back(filter);
		filter_id_rule_ids.emplace_back();
		it = filter_ids.emplace_hint(it, filter, filter_ids.size());
	}

	filter_id_rule_ids[it->second].emplace_back(rule_id);
	return it->second;
}

void network_table_t::prepare(const uint32_t height, const uint32_t width)
{
	if (!(height && width))
	{
		return;
	}

	this->width = 1;
	while (this->width < width)
	{
		this->width <<= 1;
	}

	table.prepare(height, this->width);

	filter_id_group_ids.resize(filter_ids.size());
	filter_id_group_ids_next.resize(filter_ids.size());
}

void network_table_t::compile()
{
	DimensionArray table_indexes;
	table_indexes.fill(0);

	for (unsigned int filter_id = 0;
	     filter_id < filters.size();
	     filter_id++)
	{
		remap_group_ids.clear();
		initial_group_id = group_id;

		const auto& [network_ipv4_source_filter_id,
		             network_ipv4_destination_filter_id,
		             network_ipv6_source_filter_id,
		             network_ipv6_destination_filter_id] = filters[filter_id];

		const auto& network_ipv4_source_group_ids = compiler->network_ipv4_source.filter_group_ids[network_ipv4_source_filter_id];
		const auto& network_ipv4_destination_group_ids = compiler->network_ipv4_destination.filter_group_ids[network_ipv4_destination_filter_id];
		const auto& network_ipv6_source_group_ids = compiler->network_ipv6_source.filter_group_ids[network_ipv6_source_filter_id];
		const auto& network_ipv6_destination_group_ids = compiler->network_ipv6_destination.filter_group_ids[network_ipv6_destination_filter_id];

		for (unsigned int k1 : network_ipv4_source_group_ids)
		{
			table_indexes[0] = k1;
			for (unsigned int k2 : network_ipv4_destination_group_ids)
			{
				table_indexes[1] = k2;
				table_insert(table_indexes);
			}
		}

		for (unsigned int k1 : network_ipv6_source_group_ids)
		{
			table_indexes[0] = k1;
			for (unsigned int k2 : network_ipv6_destination_group_ids)
			{
				table_indexes[1] = k2;
				table_insert(table_indexes);
			}
		}
	}
}

void network_table_t::populate()
{
	DimensionArray table_indexes;
	table_indexes.fill(0);

	for (unsigned int filter_id = 0;
	     filter_id < filters.size();
	     filter_id++)
	{
		const auto& [network_ipv4_source_filter_id,
		             network_ipv4_destination_filter_id,
		             network_ipv6_source_filter_id,
		             network_ipv6_destination_filter_id] = filters[filter_id];

		const auto& network_ipv4_source_group_ids = compiler->network_ipv4_source.filter_group_ids[network_ipv4_source_filter_id];
		const auto& network_ipv4_destination_group_ids = compiler->network_ipv4_destination.filter_group_ids[network_ipv4_destination_filter_id];
		const auto& network_ipv6_source_group_ids = compiler->network_ipv6_source.filter_group_ids[network_ipv6_source_filter_id];
		const auto& network_ipv6_destination_group_ids = compiler->network_ipv6_destination.filter_group_ids[network_ipv6_destination_filter_id];

		for (unsigned int k1 : network_ipv4_source_group_ids)
		{
			table_indexes[0] = k1;
			for (unsigned int k2 : network_ipv4_destination_group_ids)
			{
				table_indexes[1] = k2;
				table_get(table_indexes, filter_id);
			}
		}

		for (unsigned int k1 : network_ipv6_source_group_ids)
		{
			table_indexes[0] = k1;
			for (unsigned int k2 : network_ipv6_destination_group_ids)
			{
				table_indexes[1] = k2;
				table_get(table_indexes, filter_id);
			}
		}
	}
}

void network_table_t::table_insert(const DimensionArray& keys)
{
	auto& value = table(keys);

	if (value >= initial_group_id)
		return;

	auto it = remap_group_ids.find(value);
	if (it == remap_group_ids.end()) ///< check: don't override self rule
	{
		remap_group_ids.insert_unique(value, group_id);
		value = group_id;
		group_id++;
	}
	else
	{
		value = it->second;
	}
}

void network_table_t::table_get(const DimensionArray& keys, unsigned int filter_id)
{
	auto value = table(keys);

	filter_id_group_ids[filter_id].emplace(value);
}

void network_table_t::remap()
{
	remap_group_ids.clear();

	for (unsigned int layer_id = 0;
	     layer_id < compiler->transport.layers.size();
	     layer_id++)
	{
		const auto& layer = compiler->transport.layers[layer_id];

		for (const auto network_table_group_id : layer.network_table_group_ids_vec)
		{
			auto it = remap_group_ids.find(network_table_group_id);
			if (it == remap_group_ids.end())
			{
				tAclGroupId new_id = (network_table_group_id << compiler->transport_layers_shift) | layer_id;
				remap_group_ids.insert_unique(network_table_group_id, new_id);
			}
			else
			{
				throw std::runtime_error("transport.layers broken");
			}
		}
	}

	for (auto& group_id : table.values())
	{
		group_id = remap_group_ids[group_id];
	}

	for (unsigned int filter_id = 0;
	     filter_id < filters.size();
	     filter_id++)
	{
		for (const auto group_id : filter_id_group_ids[filter_id])
		{
			filter_id_group_ids_next[filter_id].emplace(remap_group_ids[group_id]);
		}
	}
	filter_id_group_ids_next.swap(filter_id_group_ids);

	for (auto& layer : compiler->transport.layers)
	{
		for (const auto group_id : layer.network_table_group_ids_vec)
		{
			layer.network_table_group_ids_vec_next.emplace_back(remap_group_ids[group_id]);
		}
		layer.network_table_group_ids_vec_next.swap(layer.network_table_group_ids_vec);

		layer.network_table_group_ids_set.clear();
		for (const auto group_id : layer.network_table_group_ids_vec)
		{
			layer.network_table_group_ids_set.emplace(group_id);
		}
	}
}
