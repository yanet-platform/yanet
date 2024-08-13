#include "acl_value.h"

#include "common/actions.h"

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

void value_t::ensure_termination(IntermediateActions& actions)
{
	auto& last_action = actions.path.back();

	if (!std::holds_alternative<common::FlowAction>(last_action.raw_action))
	{
		// Adding default "drop" rule to the end
		actions.add(rule_actions[0]);
	}
}

void value_t::move_timeout_from_state_timeout_to_flow(IntermediateActions& actions)
{
	if (const auto* state_timeout_action = actions.get<common::StateTimeoutAction>())
	{
		// Flow action should exist at this point
		auto* flow_action = actions.get<common::FlowAction>();
		flow_action->timeout = state_timeout_action->timeout;

		actions.remove<common::StateTimeoutAction>();
	}
}

void value_t::finalize_actions(IntermediateActions&& actions)
{
	if (actions.indices.get<common::CheckStateAction>().has_value())
	{
		vector.emplace_back(common::BaseActions<true>(std::move(actions)));
	}
	else
	{
		vector.emplace_back(common::BaseActions<false>(std::move(actions)));
	}
}

void value_t::compile()
{
	for (auto& actions : intermediate_vector)
	{
		ensure_termination(actions);
		move_timeout_from_state_timeout_to_flow(actions);
		finalize_actions(std::move(actions));
	}
}
