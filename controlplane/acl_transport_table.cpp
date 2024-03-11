#include "acl_transport_table.h"
#include "acl_compiler.h"

using namespace acl::compiler;

transport_table_t::transport_table_t(acl::compiler_t* compiler,
                                     const unsigned int threads_count) :
        compiler(compiler),
        threads_count(threads_count)
{
	clear();
}

void transport_table_t::clear()
{
	threads.clear();
	filters.clear();
	filter_ids.clear();
	filter_id_rule_ids.clear();
}

unsigned int transport_table_t::collect(const unsigned int rule_id, const filter& filter)
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

void transport_table_t::prepare()
{
	threads_count = std::min((unsigned int)compiler->transport.layers.size(), threads_count);

	for (unsigned int thread_id = 0;
	     thread_id < threads_count;
	     thread_id++)
	{
		threads.emplace_back(this,
		                     thread_id,
		                     threads_count);
	}
}

void transport_table_t::compile()
{
	for (auto& thread : threads)
	{
		thread.start();
	}
}

void transport_table_t::populate()
{
	for (auto& thread : threads)
	{
		thread.join();
	}
}

void transport_table_t::remap()
{
}

transport_table::thread_t::thread_t(transport_table_t* transport_table,
                                    const unsigned int thread_id,
                                    const unsigned int threads_count) :
        transport_table(transport_table),
        thread_id(thread_id),
        threads_count(threads_count)
{
	group_id = 1 + thread_id;
}

void transport_table::thread_t::start()
{
	thread = std::thread([this]() {
		try
		{
			prepare();
			compile();
			populate();
			result();
		}
		catch (...)
		{
			YANET_LOG_ERROR("exception in thread\n");
			exception = std::current_exception();
		}
	});
}

void transport_table::thread_t::join()
{
	if (thread.joinable())
	{
		thread.join();
	}

	if (exception)
	{
		std::rethrow_exception(*exception);
	}
}

void transport_table::thread_t::prepare()
{
	filter_id_group_ids.resize(transport_table->filter_ids.size());
	transport_table_filter_id_group_ids.resize(transport_table->filter_ids.size());

	for (unsigned int layer_id = thread_id;
	     layer_id < transport_table->compiler->transport.layers.size();
	     layer_id += threads_count)
	{
		const auto& transport_layer = transport_table->compiler->transport.layers[layer_id];
		auto& layer = layers[layer_id];

		unsigned int group1_size = transport_layer.tcp_source.group_id;
		group1_size = std::max(group1_size, transport_layer.udp_source.group_id);
		group1_size = std::max(group1_size, transport_layer.icmp_type_code.group_id);

		unsigned int group2_size = transport_layer.tcp_destination.group_id;
		group2_size = std::max(group2_size, transport_layer.udp_destination.group_id);
		group2_size = std::max(group2_size, transport_layer.icmp_identifier.group_id);

		unsigned int group3_size = transport_layer.tcp_flags.group_id;

		layer.table.prepare(transport_table->compiler->network_flags.group_id - 1, /// id always start with 1
		                    transport_layer.protocol.group_id - 1, /// id always start with 1
		                    group1_size,
		                    group2_size,
		                    group3_size,
		                    transport_layer.network_table_group_ids_vec.size());

		/// prepare remap vector for compress network_table_group_ids
		for (unsigned int i = 0;
		     i < transport_layer.network_table_group_ids_vec.size();
		     i++)
		{
			const unsigned int network_table_group_id = transport_layer.network_table_group_ids_vec[i] >> transport_table->compiler->transport_layers_shift;

			if (network_table_group_id >= layer.remap_network_table_group_ids.size())
			{
				layer.remap_network_table_group_ids.resize(network_table_group_id + 1, 0);
			}

			layer.remap_network_table_group_ids[network_table_group_id] = i;
		}
	}
}

void transport_table::thread_t::compile()
{
	std::array<size_t, dimension> table_indexes;
	table_indexes.fill(0);

	for (unsigned int filter_id = 0;
	     filter_id < transport_table->filters.size();
	     filter_id++)
	{
		remap_group_ids.clear();
		remap_group_ids.resize(group_id, 0);

		const auto& [network_table_filter_id, network_flags_filter_id, transport_filter_id] = transport_table->filters[filter_id];
		const auto& network_table_group_ids_orig = transport_table->compiler->network_table.filter_id_group_ids[network_table_filter_id];
		const auto& network_flags_group_ids = transport_table->compiler->network_flags.filter_id_group_ids[network_flags_filter_id];

		std::vector<tAclGroupId> network_table_group_ids;
		std::vector<tAclGroupId> network_table_group_ids_curr;
		std::vector<tAclGroupId> network_table_group_ids_next = network_table_group_ids_orig;

		for (unsigned int layer_id = thread_id;
		     layer_id < transport_table->compiler->transport.layers.size();
		     layer_id += threads_count)
		{
			const auto& transport_layer = transport_table->compiler->transport.layers[layer_id];
			auto& layer = layers[layer_id];

			if (!transport_layer.filter_ids_set.count(transport_filter_id))
			{
				continue;
			}

			if (network_table_group_ids_next.empty())
			{
				break;
			}

			network_table_group_ids.swap(network_table_group_ids_next);
			network_table_group_ids_curr.clear();
			network_table_group_ids_next.clear();

			for (const auto network_table_group_id : network_table_group_ids)
			{
				if (transport_layer.network_table_group_ids_set.count(network_table_group_id))
				{
					network_table_group_ids_curr.emplace_back(network_table_group_id);
				}
				else
				{
					network_table_group_ids_next.emplace_back(network_table_group_id);
				}
			}

			const auto& protocol_group_ids = transport_layer.protocol.filter_id_group_ids[transport_layer.protocol_id[transport_filter_id]];
			const auto& tcp_source_group_ids = transport_layer.tcp_source.filter_id_group_ids[transport_layer.tcp_source_id[transport_filter_id]];
			const auto& tcp_destination_group_ids = transport_layer.tcp_destination.filter_id_group_ids[transport_layer.tcp_destination_id[transport_filter_id]];
			const auto& tcp_flags_group_ids = transport_layer.tcp_flags.filter_id_group_ids[transport_layer.tcp_flags_id[transport_filter_id]];
			const auto& udp_source_group_ids = transport_layer.udp_source.filter_id_group_ids[transport_layer.udp_source_id[transport_filter_id]];
			const auto& udp_destination_group_ids = transport_layer.udp_destination.filter_id_group_ids[transport_layer.udp_destination_id[transport_filter_id]];
			const auto& icmpv4_type_code_group_ids = transport_layer.icmp_type_code.filter_id_group_ids[transport_layer.icmpv4_type_code_id[transport_filter_id]];
			const auto& icmpv4_identifier_group_ids = transport_layer.icmp_identifier.filter_id_group_ids[transport_layer.icmpv4_identifier_id[transport_filter_id]];
			const auto& icmpv6_type_code_group_ids = transport_layer.icmp_type_code.filter_id_group_ids[transport_layer.icmpv6_type_code_id[transport_filter_id]];
			const auto& icmpv6_identifier_group_ids = transport_layer.icmp_identifier.filter_id_group_ids[transport_layer.icmpv6_identifier_id[transport_filter_id]];

			for (const auto& protocol_group_id : protocol_group_ids)
			{
				/// @todo: skip tcp,udp,icmp

				table_indexes[1] = layer.table.get_index(1, protocol_group_id - 1); /// id always start with 1
				table_indexes[2] = layer.table.get_index(2, 0);
				table_indexes[3] = layer.table.get_index(3, 0);
				table_indexes[4] = layer.table.get_index(4, 0);

				for (const auto network_flags_group_id : network_flags_group_ids)
				{
					table_indexes[0] = layer.table.get_index(0, network_flags_group_id - 1); /// id always start with 1
					table_insert(layer, table_indexes, network_table_group_ids_curr);
				}
			}

			/// @todo: check if not fragment

			/// tcp
			{
				table_indexes[1] = layer.table.get_index(1, transport_layer.protocol.get(IPPROTO_TCP) - 1); /// id always start with 1

				for (const auto& tcp_source_id : tcp_source_group_ids)
				{
					table_indexes[2] = layer.table.get_index(2, tcp_source_id);
					for (const auto& tcp_destination_id : tcp_destination_group_ids)
					{
						table_indexes[3] = layer.table.get_index(3, tcp_destination_id);
						for (const auto& tcp_flags_id : tcp_flags_group_ids)
						{
							table_indexes[4] = layer.table.get_index(4, tcp_flags_id);
							for (const auto network_flags_group_id : network_flags_group_ids)
							{
								table_indexes[0] = layer.table.get_index(0, network_flags_group_id - 1); /// id always start with 1
								table_insert(layer, table_indexes, network_table_group_ids_curr);
							}
						}
					}
				}
			}

			/// udp
			{
				table_indexes[1] = layer.table.get_index(1, transport_layer.protocol.get(IPPROTO_UDP) - 1); /// id always start with 1
				table_indexes[4] = layer.table.get_index(4, 0);

				for (const auto& udp_source_id : udp_source_group_ids)
				{
					table_indexes[2] = layer.table.get_index(2, udp_source_id);
					for (const auto& udp_destination_id : udp_destination_group_ids)
					{
						table_indexes[3] = layer.table.get_index(3, udp_destination_id);
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = layer.table.get_index(0, network_flags_group_id - 1); /// id always start with 1
							table_insert(layer, table_indexes, network_table_group_ids_curr);
						}
					}
				}
			}

			/// icmp
			{
				table_indexes[1] = layer.table.get_index(1, transport_layer.protocol.get(IPPROTO_ICMP) - 1); /// id always start with 1
				table_indexes[4] = layer.table.get_index(4, 0);

				for (const auto& icmp_type_code_id : icmpv4_type_code_group_ids)
				{
					table_indexes[2] = layer.table.get_index(2, icmp_type_code_id);
					for (const auto& icmp_identifier_id : icmpv4_identifier_group_ids)
					{
						table_indexes[3] = layer.table.get_index(3, icmp_identifier_id);
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = layer.table.get_index(0, network_flags_group_id - 1); /// id always start with 1
							table_insert(layer, table_indexes, network_table_group_ids_curr);
						}
					}
				}
			}

			/// icmp_v6
			{
				table_indexes[1] = layer.table.get_index(1, transport_layer.protocol.get(IPPROTO_ICMPV6) - 1); /// id always start with 1
				table_indexes[4] = layer.table.get_index(4, 0);

				for (const auto& icmp_type_code_id : icmpv6_type_code_group_ids)
				{
					table_indexes[2] = layer.table.get_index(2, icmp_type_code_id);
					for (const auto& icmp_identifier_id : icmpv6_identifier_group_ids)
					{
						table_indexes[3] = layer.table.get_index(3, icmp_identifier_id);
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = layer.table.get_index(0, network_flags_group_id - 1); /// id always start with 1
							table_insert(layer, table_indexes, network_table_group_ids_curr);
						}
					}
				}
			}
		}
	}
}

void transport_table::thread_t::populate()
{
	std::array<size_t, dimension> table_indexes;
	table_indexes.fill(0);

	for (unsigned int filter_id = 0;
	     filter_id < transport_table->filters.size();
	     filter_id++)
	{
		bitmask.clear();

		const auto& [network_table_filter_id, network_flags_filter_id, transport_filter_id] = transport_table->filters[filter_id];
		const auto& network_table_group_ids_orig = transport_table->compiler->network_table.filter_id_group_ids[network_table_filter_id];
		const auto& network_flags_group_ids = transport_table->compiler->network_flags.filter_id_group_ids[network_flags_filter_id];

		std::vector<tAclGroupId> network_table_group_ids;
		std::vector<tAclGroupId> network_table_group_ids_curr;
		std::vector<tAclGroupId> network_table_group_ids_next = network_table_group_ids_orig;

		for (unsigned int layer_id = thread_id;
		     layer_id < transport_table->compiler->transport.layers.size();
		     layer_id += threads_count)
		{
			const auto& transport_layer = transport_table->compiler->transport.layers[layer_id];
			auto& layer = layers[layer_id];

			if (!transport_layer.filter_ids_set.count(transport_filter_id))
			{
				continue;
			}

			if (network_table_group_ids_next.empty())
			{
				break;
			}

			network_table_group_ids.swap(network_table_group_ids_next);
			network_table_group_ids_curr.clear();
			network_table_group_ids_next.clear();

			for (const auto network_table_group_id : network_table_group_ids)
			{
				if (transport_layer.network_table_group_ids_set.count(network_table_group_id))
				{
					network_table_group_ids_curr.emplace_back(network_table_group_id);
				}
				else
				{
					network_table_group_ids_next.emplace_back(network_table_group_id);
				}
			}

			const auto& protocol_group_ids = transport_layer.protocol.filter_id_group_ids[transport_layer.protocol_id[transport_filter_id]];
			const auto& tcp_source_group_ids = transport_layer.tcp_source.filter_id_group_ids[transport_layer.tcp_source_id[transport_filter_id]];
			const auto& tcp_destination_group_ids = transport_layer.tcp_destination.filter_id_group_ids[transport_layer.tcp_destination_id[transport_filter_id]];
			const auto& tcp_flags_group_ids = transport_layer.tcp_flags.filter_id_group_ids[transport_layer.tcp_flags_id[transport_filter_id]];
			const auto& udp_source_group_ids = transport_layer.udp_source.filter_id_group_ids[transport_layer.udp_source_id[transport_filter_id]];
			const auto& udp_destination_group_ids = transport_layer.udp_destination.filter_id_group_ids[transport_layer.udp_destination_id[transport_filter_id]];
			const auto& icmpv4_type_code_group_ids = transport_layer.icmp_type_code.filter_id_group_ids[transport_layer.icmpv4_type_code_id[transport_filter_id]];
			const auto& icmpv4_identifier_group_ids = transport_layer.icmp_identifier.filter_id_group_ids[transport_layer.icmpv4_identifier_id[transport_filter_id]];
			const auto& icmpv6_type_code_group_ids = transport_layer.icmp_type_code.filter_id_group_ids[transport_layer.icmpv6_type_code_id[transport_filter_id]];
			const auto& icmpv6_identifier_group_ids = transport_layer.icmp_identifier.filter_id_group_ids[transport_layer.icmpv6_identifier_id[transport_filter_id]];

			for (const auto& protocol_group_id : protocol_group_ids)
			{
				/// @todo: skip tcp,udp,icmp

				table_indexes[1] = layer.table.get_index(1, protocol_group_id - 1); /// id always start with 1
				table_indexes[2] = layer.table.get_index(2, 0);
				table_indexes[3] = layer.table.get_index(3, 0);
				table_indexes[4] = layer.table.get_index(4, 0);

				for (const auto network_flags_group_id : network_flags_group_ids)
				{
					table_indexes[0] = layer.table.get_index(0, network_flags_group_id - 1); /// id always start with 1
					table_get(layer, table_indexes, network_table_group_ids_curr);
				}
			}

			/// @todo: check if not fragment

			/// tcp
			{
				table_indexes[1] = layer.table.get_index(1, transport_layer.protocol.get(IPPROTO_TCP) - 1); /// id always start with 1

				for (const auto& tcp_source_id : tcp_source_group_ids)
				{
					table_indexes[2] = layer.table.get_index(2, tcp_source_id);
					for (const auto& tcp_destination_id : tcp_destination_group_ids)
					{
						table_indexes[3] = layer.table.get_index(3, tcp_destination_id);
						for (const auto& tcp_flags_id : tcp_flags_group_ids)
						{
							table_indexes[4] = layer.table.get_index(4, tcp_flags_id);
							for (const auto network_flags_group_id : network_flags_group_ids)
							{
								table_indexes[0] = layer.table.get_index(0, network_flags_group_id - 1); /// id always start with 1
								table_get(layer, table_indexes, network_table_group_ids_curr);
							}
						}
					}
				}
			}

			/// udp
			{
				table_indexes[1] = layer.table.get_index(1, transport_layer.protocol.get(IPPROTO_UDP) - 1); /// id always start with 1
				table_indexes[4] = layer.table.get_index(4, 0);

				for (const auto& udp_source_id : udp_source_group_ids)
				{
					table_indexes[2] = layer.table.get_index(2, udp_source_id);
					for (const auto& udp_destination_id : udp_destination_group_ids)
					{
						table_indexes[3] = layer.table.get_index(3, udp_destination_id);
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = layer.table.get_index(0, network_flags_group_id - 1); /// id always start with 1
							table_get(layer, table_indexes, network_table_group_ids_curr);
						}
					}
				}
			}

			/// icmp
			{
				table_indexes[1] = layer.table.get_index(1, transport_layer.protocol.get(IPPROTO_ICMP) - 1); /// id always start with 1
				table_indexes[4] = layer.table.get_index(4, 0);

				for (const auto& icmp_type_code_id : icmpv4_type_code_group_ids)
				{
					table_indexes[2] = layer.table.get_index(2, icmp_type_code_id);
					for (const auto& icmp_identifier_id : icmpv4_identifier_group_ids)
					{
						table_indexes[3] = layer.table.get_index(3, icmp_identifier_id);
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = layer.table.get_index(0, network_flags_group_id - 1); /// id always start with 1
							table_get(layer, table_indexes, network_table_group_ids_curr);
						}
					}
				}
			}

			/// icmp_v6
			{
				table_indexes[1] = layer.table.get_index(1, transport_layer.protocol.get(IPPROTO_ICMPV6) - 1); /// id always start with 1
				table_indexes[4] = layer.table.get_index(4, 0);

				for (const auto& icmp_type_code_id : icmpv6_type_code_group_ids)
				{
					table_indexes[2] = layer.table.get_index(2, icmp_type_code_id);
					for (const auto& icmp_identifier_id : icmpv6_identifier_group_ids)
					{
						table_indexes[3] = layer.table.get_index(3, icmp_identifier_id);
						for (const auto network_flags_group_id : network_flags_group_ids)
						{
							table_indexes[0] = layer.table.get_index(0, network_flags_group_id - 1); /// id always start with 1
							table_get(layer, table_indexes, network_table_group_ids_curr);
						}
					}
				}
			}
		}

		for (const auto i : bitmask)
		{
			filter_id_group_ids[filter_id].emplace_back(i);
			group_id_filter_ids[i].emplace(filter_id);
			transport_table_filter_id_group_ids[filter_id].emplace_back(i);
		}
	}
}

void transport_table::thread_t::result()
{
	for (unsigned int layer_id = thread_id;
	     layer_id < transport_table->compiler->transport.layers.size();
	     layer_id += threads_count)
	{
		const auto& transport_layer = transport_table->compiler->transport.layers[layer_id];
		auto& layer = layers[layer_id];

		acl_transport_table.reserve(acl_transport_table.size() + layer.table.values.size());

		layer.table.for_each([&](const std::array<unsigned int, dimension>& keys,
		                         const unsigned int value) {
			common::acl::transport_key_t key;
			key.network_flags = keys[0] + 1; /// id always start with 1
			key.protocol = keys[1] + 1; /// id always start with 1
			key.group1 = keys[2];
			key.group2 = keys[3];
			key.group3 = keys[4];
			key.network_id = transport_layer.network_table_group_ids_vec[keys[5]];
			acl_transport_table.emplace_back(key, value);
		});

		layer.table.clear();
	}
}

void transport_table::thread_t::table_insert(transport_table::layer_t& layer,
                                             const std::array<size_t, dimension>& table_indexes,
                                             const std::vector<unsigned int>& network_table_group_ids)
{
	/// calc index for keys[0, 1, 2, 3, 4]
	size_t total_index = 0;
	for (const auto index : table_indexes)
	{
		total_index += index;
	}

	for (const auto network_table_group_id : network_table_group_ids)
	{
		///                                            calc index with key[5]
		auto& value = layer.table.values[total_index + layer.remap_network_table_group_ids[network_table_group_id >> transport_table->compiler->transport_layers_shift]];

		if (value < remap_group_ids.size()) ///< check: don't override self rule
		{
			auto& remap_group_ip = remap_group_ids[value];
			if (!remap_group_ip)
			{
				remap_group_ip = group_id;
				group_id += threads_count;
			}

			value = remap_group_ip;
		}
	}
}

void transport_table::thread_t::table_get(transport_table::layer_t& layer,
                                          const std::array<size_t, dimension>& table_indexes,
                                          const std::vector<unsigned int>& network_table_group_ids)
{
	/// calc index for keys[0, 1, 2, 3, 4]
	size_t total_index = 0;
	for (const auto index : table_indexes)
	{
		total_index += index;
	}

	for (const auto network_table_group_id : network_table_group_ids)
	{
		///                                                 calc index with key[5]
		const auto value = layer.table.values[total_index + layer.remap_network_table_group_ids[network_table_group_id >> transport_table->compiler->transport_layers_shift]];
		bitmask.emplace(value);
	}
}
