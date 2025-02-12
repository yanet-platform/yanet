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
	filters.clear();
	filter_ids.clear();
	filled_filter_ids.clear();
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

	return it->second;
}

void total_table_t::prepare()
{
}

void total_table_t::compile()
{
	common::acl::total_key_t key;
	memset(&key, 0, sizeof(key));

	for (const auto& rule : compiler->rules)
	{
		const auto filter_id = rule.total_table_filter_id;
		const auto group_id = rule.value_filter_id;

		if (filled_filter_ids.find(filter_id) != filled_filter_ids.end())
		{
			continue;
		}

		const auto& [acl_id, transport_table_filter_id] = filters[filter_id];
		/// @todo: acl_id -> via_filter_id

		key.acl_id = acl_id;
		bool used = false;
		for (const auto& thread : compiler->transport_table.threads)
		{
			for (const auto transport_table_group_id : thread.transport_table_filter_id_group_ids[transport_table_filter_id])
			{
				key.transport_id = transport_table_group_id;
				auto it = table.find(key);
				if (it == table.end())
				{
					// If there is no such key in table, then we save [key, group_id]
					// without any additional checks.
					table.insert_unique(key, group_id);
					used = true;
				}
				else
				{
					// If table already has such key, then we are trying to collect
					// new combination of the previous group_id and the current group_id.
					// If new_group_id differs from the current group_id, then we replace
					// the previous group_id with the new one. Otherwise we don't do anything.
					const auto new_group_id = compiler->value.collect(it->second, group_id);
					if (new_group_id != it->second)
					{
						it->second = new_group_id;
						used = true;
					}
				}

				if (rule.terminating && used)
				{
					// If the rule is termineting and has been used, then we mark filter_id
					// as filled in to prevent further additional checks.
					filled_filter_ids.emplace(filter_id);
				}
			}
		}

		if (used)
		{
			compiler->used_rules.emplace_back(rule.rule_id);
		}
	}
}
