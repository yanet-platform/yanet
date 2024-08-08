#include "acl_value.h"

using namespace acl::compiler;

value_t::value_t()
{
	clear();
}

void value_t::clear()
{
	intermediate_vector.clear();
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
	intermediate_vector.emplace_back(rule_actions[rule_action_id]);
	return intermediate_vector.size() - 1;
}

void value_t::append_to_last(unsigned int rule_action_id)
{
	intermediate_vector.back().add(rule_actions[rule_action_id]);
}

void value_t::compile()
{
	for (auto& intermediate_actions : intermediate_vector)
	{
		auto last_action = intermediate_actions.path.back();

		if (!std::visit([](const auto& act) { return act.terminating(); }, last_action.raw_action))
		{
			// Adding default "drop" rule to the end
			intermediate_actions.add(rule_actions[0]);
		}

		if (intermediate_actions.check_state_index.has_value())
		{
			vector.emplace_back(common::BaseActions<true>(std::move(intermediate_actions)));
		}
		else
		{
			vector.emplace_back(common::BaseActions<false>(std::move(intermediate_actions)));
		}
	}
}
