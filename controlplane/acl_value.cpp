#include "acl_value.h"

using namespace acl::compiler;

value_t::value_t()
{
	clear();
}

void value_t::clear()
{
	vector.clear();
	rule_actions.clear();

	{
		/// @todo: find default_flow

		common::globalBase::flow_t default_flow;
		default_flow.type = common::globalBase::eFlowType::drop;
		collect_initial_rule(std::move(default_flow));
	}
}

unsigned int value_t::collect(unsigned int rule_action_id)
{
	vector.emplace_back(rule_actions[rule_action_id]);
	return vector.size() - 1;
}

void value_t::append_to_last(unsigned int rule_action_id)
{
	vector.back().add(rule_actions[rule_action_id]);
}

void value_t::compile()
{
	for (auto& actions : vector)
	{
		auto last_action = actions.get_last();

		if (!std::visit([](const auto& act) { return act.terminating(); }, last_action.raw_action))
		{
			// Adding default "drop" rule to the end
			actions.add(rule_actions[0]);
		}
	}
}
