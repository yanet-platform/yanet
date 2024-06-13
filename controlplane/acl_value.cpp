#include "acl_value.h"
#include "acl_compiler.h"

using namespace acl::compiler;

value_t::value_t()
{
	clear();
}

void value_t::clear()
{
	vector.clear();
	filters.clear();
	filter_ids.clear();

	{
		/// @todo: find default_flow
		common::globalBase::flow_t default_flow;
		default_flow.type = common::globalBase::eFlowType::drop;
		collect({default_flow});
	}
}

unsigned int value_t::collect(const filter& filter)
{
	auto it = filter_ids.find(filter);
	if (it == filter_ids.end())
	{
		filters.emplace_back(filter);
		it = filter_ids.emplace_hint(it, filter, filter_ids.size());
	}

	return it->second;
}

// This collect function is only used in acl_total_table compiler to squash
// non-terminating and terminating rules into one unique group_id.
unsigned int value_t::collect(const tAclGroupId prev_id, const tAclGroupId id)
{
	unsigned int ret;
	auto prev_filter = filters[prev_id];
	if (std::holds_alternative<common::globalBase::flow_t>(prev_filter.back()))
	{
		ret = prev_id;
	}
	else
	{
		const auto& filter = filters[id];
		prev_filter.emplace_back(filter.back());
		ret = collect(prev_filter);
	}

	return ret;
}

void value_t::compile()
{
	for (const auto& filter : filters)
	{
		int dumps_counter = 0;
		common::acl::value_t value;
		for (const auto& it : filter)
		{
			if (auto action = std::get_if<common::acl::action_t>(&it))
			{
				if (dumps_counter >= YANET_CONFIG_DUMP_ID_SIZE)
				{
					continue;
				}
				value.dump_ids[dumps_counter] = action->dump_id;
				dumps_counter++;
			}
			else
			{
				value.flow = std::get<common::globalBase::tFlow>(it);
			}
		}

		vector.emplace_back(std::move(value));
	}
}
