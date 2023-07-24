#include "acl_total_table.h"
#include "acl_compiler.h"

using namespace acl::compiler;

total_table_t::total_table_t(compiler_t* compiler) :
        compiler(compiler)
{
	clear();
}

void total_table_t::clear()
{
	table.clear();
	remap_group_ids.clear();
	group_id = 1;
	filters.clear();
	filter_ids.clear();
	filter_id_by_rule_id.clear();
	filter_id_group_ids.clear();
	bitmask.clear();
	map.clear();
	reverse_map.clear();
	reverse_map_next.clear();
}

unsigned int total_table_t::collect(const unsigned int rule_id, const filter& filter)
{
	(void)rule_id;

	auto it = filter_ids.find(filter);
	if (it == filter_ids.end())
	{
		filters.emplace_back(filter);
		it = filter_ids.emplace_hint(it, filter, filter_ids.size());
	}

	filter_id_by_rule_id.emplace_back(it->second);
	return it->second;
}

void total_table_t::prepare()
{
	filter_id_group_ids.resize(filter_ids.size());
}

void total_table_t::compile()
{
	common::acl::total_key_t key;
	memset(&key, 0, sizeof(key));

	for (const auto& rule : compiler->rules)
	{
		const auto filter_id = rule.total_table_filter_id;
		const auto group_id = rule.value_filter_id;

		if (!filter_id_group_ids[filter_id].empty())
		{
			continue;
		}

		const auto& [acl_id, transport_table_filter_id] = filters[filter_id];
		/// @todo: acl_id -> via_filter_id

		key.acl_id = acl_id;

		bool used = true;
		for (const auto& thread : compiler->transport_table.threads)
		{
			for (const auto transport_table_group_id : thread.transport_table_filter_id_group_ids[transport_table_filter_id])
			{
				key.transport_id = transport_table_group_id;

				auto it = table.find(key);
				if (it == table.end())
				{
					table.emplace_hint(it, key, group_id);
					filter_id_group_ids[filter_id].emplace(group_id);

					if (used)
					{
						compiler->used_rules.emplace_back(rule.rule_id);
						used = false;
					}
				}
			}
		}
	}
}
