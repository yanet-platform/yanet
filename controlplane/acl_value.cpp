#include "acl_value.h"
#include "acl_compiler.h"

using namespace acl::compiler;

value_t::value_t()
{
	clear();
}

void value_t::clear()
{
	values.clear();
	filters.clear();
	filter_ids.clear();

	for (size_t i = 0; i < actions.size(); i++)
	{
		actions[i].clear();
		action_ids[i].clear();
	}

	{
		/// @todo: find default_flow
		common::globalBase::flow_t default_flow;
		default_flow.type = common::globalBase::eFlowType::drop;
		collect({default_flow});

		for (size_t i = 0; i < actions.size(); i++)
		{
			collect(action_ids_array(action_t(i)));
		}
	}
}

unsigned int value_t::collect(const value_filter& filter)
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

uint32_t value_t::collect(const action_ids_array& ids)
{
	const auto action = uint8_t(ids.action);

	auto it = action_ids[action].find(ids.values);
	if (it == action_ids[action].end())
	{
		actions[action].emplace_back(ids.values);
		it = action_ids[action].emplace_hint(it, ids.values, action_ids[action].size());
	}

	return it->second;
}

void value_t::compile()
{
	for (const auto& filter : filters)
	{
		common::acl::value_t value;
		common::globalBase::tActions<action_ids_array> value_actions;
		for (size_t i = 0; i < value_actions.size(); i++)
		{
			value_actions[i] = action_ids_array(action_t(i));
		}

		for (const auto& it : filter)
		{
			if (auto action = std::get_if<common::acl::action_t>(&it))
			{
				if (action->type < action_t::size)
				{
					value_actions[int(action->type)].add(action->id);
				}
			}
			else
			{
				value.flow = std::get<common::globalBase::tFlow>(it);
				break;
			}
		}

		for (size_t i = 0; i < value.actions.size(); i++)
		{
			value.actions[i] = collect(value_actions[i]);
		}

		values.emplace_back(std::move(value));
	}
}
