#pragma once

#include "common/actions.h"

namespace acl::compiler
{

class value_t
{
	using IntermediateActions = common::acl::IntermediateActions;

	/**
	 * Ensures that the last action in each path is terminating. If not, a default "drop" rule is added.
	 */
	void ensure_termination(IntermediateActions& actions);

	/**
	 * Removes the StateTimeoutAction to reduce dataplane load
	 * by moving the timeout value directly into the FlowAction.
	 */
	void move_timeout_from_state_timeout_to_flow(IntermediateActions& actions);

	/**
	 * Finalizes the intermediate actions into a vector of BaseActions objects.
	 */
	void finalize_actions(IntermediateActions&& actions);

public:
	value_t();

public:
	void clear();

	template<typename T>
	unsigned int collect_initial_rule(T&& rule)
	{
		static_assert(!std::is_same_v<std::decay_t<T>, int64_t>,
		              "int64_t should not be a type of action in unwinded rule");

		rule_actions.emplace_back(std::forward<T>(rule));
		return rule_actions.size() - 1;
	}

	unsigned int collect(unsigned int rule_actions_id);

	void compile();

public:
	// FIXME: I don't like this name.. Why was it called like that previously?
	std::vector<common::acl::IntermediateActions> intermediate_vector;

	// FIXME: I don't like this name.. Why was it called like that previously?
	std::vector<common::Actions> vector;

	// FIXME:
	// The initial objects are created using collect_inintial_rule and stored here.
	// Then we create copies in intermediate_vector.
	// I've tried to use shared pointers and/or real pointers, but then a bunch
	// of issues arise when serializing a `vector` with stream.push/pop
	std::vector<common::Action> rule_actions;

	void append_to_last(unsigned int rule_action_id);
};

}
