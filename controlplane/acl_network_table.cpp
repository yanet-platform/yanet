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
	values.resize(0);
	remap_group_ids.clear();
	group_id = 1;
	filters.clear();
	filter_ids.clear();
	filter_id_rule_ids.clear();
	filter_id_group_ids.clear();
	group_id_filter_ids.clear();
	filter_id_group_ids_next.clear();
	group_id_filter_ids_next.clear();
	bitmask.clear();
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

	values.resize(height * this->width);

	filter_id_group_ids.resize(filter_ids.size());
	filter_id_group_ids_next.resize(filter_ids.size());
}

void network_table_t::compile()
{
	for (auto [network_ipv4_source_filter_id, network_ipv4_destination_filter_id, network_ipv6_source_filter_id, network_ipv6_destination_filter_id] : filters)
	{
		remap_group_ids.clear();
		remap_group_ids.resize(group_id, 0);

		const auto& network_ipv4_source_group_ids = compiler->network_ipv4_source.filter_group_ids[network_ipv4_source_filter_id];
		const auto& network_ipv4_destination_group_ids = compiler->network_ipv4_destination.filter_group_ids[network_ipv4_destination_filter_id];
		const auto& network_ipv6_source_group_ids = compiler->network_ipv6_source.filter_group_ids[network_ipv6_source_filter_id];
		const auto& network_ipv6_destination_group_ids = compiler->network_ipv6_destination.filter_group_ids[network_ipv6_destination_filter_id];

		for (const auto& k1 : network_ipv4_source_group_ids)
		{
			uint32_t index = k1 * width;

			for (const auto& k2 : network_ipv4_destination_group_ids)
			{
				uint32_t i = index + k2;

				if (values[i] < remap_group_ids.size()) ///< check: don't override self rule
				{
					auto& remap_group_ip = remap_group_ids[values[i]];
					if (!remap_group_ip)
					{
						remap_group_ip = group_id;
						group_id++;
					}

					values[i] = remap_group_ip;
				}
				else
				{
					/// dont panic. this is fine
				}
			}
		}

		for (const auto& k1 : network_ipv6_source_group_ids)
		{
			uint32_t index = k1 * width;

			for (const auto& k2 : network_ipv6_destination_group_ids)
			{
				uint32_t i = index + k2;

				if (values[i] < remap_group_ids.size()) ///< check: don't override self rule
				{
					auto& remap_group_ip = remap_group_ids[values[i]];
					if (!remap_group_ip)
					{
						remap_group_ip = group_id;
						group_id++;
					}

					values[i] = remap_group_ip;
				}
				else
				{
					/// dont panic. this is fine
				}
			}
		}
	}
}

void network_table_t::populate()
{
	for (unsigned int filter_id = 0;
	     filter_id < filters.size();
	     filter_id++)
	{
		bitmask.resize(0);
		bitmask.resize(group_id, 0);

		const auto& [network_ipv4_source_filter_id,
		             network_ipv4_destination_filter_id,
		             network_ipv6_source_filter_id,
		             network_ipv6_destination_filter_id] = filters[filter_id];

		const auto& network_ipv4_source_group_ids = compiler->network_ipv4_source.filter_group_ids[network_ipv4_source_filter_id];
		const auto& network_ipv4_destination_group_ids = compiler->network_ipv4_destination.filter_group_ids[network_ipv4_destination_filter_id];
		const auto& network_ipv6_source_group_ids = compiler->network_ipv6_source.filter_group_ids[network_ipv6_source_filter_id];
		const auto& network_ipv6_destination_group_ids = compiler->network_ipv6_destination.filter_group_ids[network_ipv6_destination_filter_id];

		for (const auto& k1 : network_ipv4_source_group_ids)
		{
			uint32_t index = k1 * width;

			for (const auto& k2 : network_ipv4_destination_group_ids)
			{
				uint32_t i = index + k2;

				bitmask[values[i]] = 1;
			}
		}

		for (const auto& k1 : network_ipv6_source_group_ids)
		{
			uint32_t index = k1 * width;

			for (const auto& k2 : network_ipv6_destination_group_ids)
			{
				uint32_t i = index + k2;

				bitmask[values[i]] = 1;
			}
		}

		for (unsigned int i = 0;
		     i < bitmask.size();
		     i++)
		{
			if (bitmask[i])
			{
				filter_id_group_ids[filter_id].emplace_back(i);
				group_id_filter_ids[i].emplace(filter_id);
			}
		}
	}
}

void network_table_t::remap()
{
	remap_group_ids.clear();
	remap_group_ids.resize(group_id, 0);

	for (unsigned int layer_id = 0;
	     layer_id < compiler->transport.layers.size();
	     layer_id++)
	{
		const auto& layer = compiler->transport.layers[layer_id];

		for (const auto network_table_group_id : layer.network_table_group_ids_vec)
		{
			auto& remap_group_id = remap_group_ids[network_table_group_id];
			if (!remap_group_id)
			{
				remap_group_id = (network_table_group_id << compiler->transport_layers_shift) | layer_id;
			}
			else
			{
				throw std::runtime_error("transport.layers broken");
			}
		}
	}

	for (auto& group_id : values)
	{
		group_id = remap_group_ids[group_id];
	}

	for (unsigned int filter_id = 0;
	     filter_id < filters.size();
	     filter_id++)
	{
		for (const auto group_id : filter_id_group_ids[filter_id])
		{
			filter_id_group_ids_next[filter_id].emplace_back(remap_group_ids[group_id]);
		}
	}
	filter_id_group_ids_next.swap(filter_id_group_ids);

	for (auto& [group_id, filter_ids] : group_id_filter_ids)
	{
		group_id_filter_ids_next[remap_group_ids[group_id]].swap(filter_ids);
	}
	group_id_filter_ids_next.swap(group_id_filter_ids);

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
