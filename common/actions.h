#pragma once

#include <utility>
#include <variant>

#include "common/type.h"
#include "config.release.h"
#include "stream.h"

namespace common
{

namespace acl
{
class dump_t
{
public:
	dump_t() :
	        dump_id(0),
	        dump_tag("")
	{}

	dump_t(std::string dump_tag) :
	        dump_id(0),
	        dump_tag(std::move(dump_tag))
	{}

	inline bool operator==(const dump_t& o) const
	{
		return std::tie(dump_id, dump_tag) ==
		       std::tie(o.dump_id, o.dump_tag);
	}

	inline bool operator!=(const dump_t& o) const
	{
		return !operator==(o);
	}

	constexpr bool operator<(const dump_t& o) const
	{
		return std::tie(dump_id, dump_tag) <
		       std::tie(o.dump_id, o.dump_tag);
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(dump_id);
		stream.pop(dump_tag);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(dump_id);
		stream.push(dump_tag);
	}

	uint64_t dump_id;
	std::string dump_tag;
};

struct check_state_t
{
	// Unique identifier for hash calculation
	static constexpr int64_t HASH_IDENTIFIER = 12345;

	bool operator==([[maybe_unused]] const check_state_t& o) const
	{
		return true; // TODO: why do we need this operator?
	}

	constexpr bool operator<([[maybe_unused]] const check_state_t& o) const
	{
		return true; // TODO: why do we need this operator?
	}
};

} // namespace acl

// TODO: When rewriting the current ACL library into LibFilter, we could consider using inheritance.
// All "action" classes should implement some operators and pop/push methods, so it's beneficial to enforce this
// at the language level. However, if the same structures are used in the dataplane, it could impact performance
// due to extra pointer dereferences in vtable, if compiler does not succeed in devirtualization.
// Anyway, this is something to think about.

/**
 * @brief Represents an action that dumps packets to a specified ring.
 *
 * Only one DumpAction is allowed in an Actions object.
 */
struct DumpAction final
{
	// Maximum count of DumpAction objects allowed.
	static constexpr size_t MAX_COUNT = YANET_CONFIG_DUMP_ID_SIZE;
	// The identifier for the dump ring.
	uint64_t dump_id;

	DumpAction(const acl::dump_t& dump_action) :
	        dump_id(dump_action.dump_id){};

	DumpAction() :
	        dump_id(0){};

	[[nodiscard]] bool terminating() const { return false; }

	void pop(stream_in_t& stream)
	{
		stream.pop(dump_id);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(dump_id);
	}

	[[nodiscard]] std::string to_string() const
	{
		std::ostringstream oss;
		oss << "DumpAction(dump_id=" << dump_id << ")";
		return oss.str();
	}
};

/**
 * @brief Represents an action that processes a packet flow.
 *
 * Only one FlowAction is allowed in an Actions object.
 */
struct FlowAction final
{
	// Maximum count of FlowAction objects allowed.
	static constexpr size_t MAX_COUNT = 1;
	// The flow associated with this action.
	globalBase::tFlow flow;

	FlowAction(const globalBase::tFlow& flow) :
	        flow(flow){};

	FlowAction(globalBase::tFlow&& flow) :
	        flow(std::move(flow)) {}

	FlowAction() :
	        flow(globalBase::tFlow()) {}

	[[nodiscard]] bool terminating() const { return true; }

	void pop(stream_in_t& stream)
	{
		stream.pop(flow);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(flow);
	}

	[[nodiscard]] std::string to_string() const
	{
		std::ostringstream oss;
		oss << "FlowAction(flow=" << flow.to_string() << ")";
		return oss.str();
	}
};

/**
 * @brief Represents an action that checks the dynamic firewall state.
 *
 * This class doesn't have any specific info to store,
 * because check-state rule doesn't need anything.
 *
 * Only one CheckStateAction is allowed in an Actions object.
 */
struct CheckStateAction final
{
	static constexpr size_t MAX_COUNT = 1;

	CheckStateAction(const acl::check_state_t&){};
	CheckStateAction() = default;

	[[nodiscard]] bool terminating() const { return false; }

	void pop(stream_in_t& stream)
	{
		stream.pop(reinterpret_cast<uint8_t(&)[sizeof(*this)]>(*this));
	}

	void push(stream_out_t& stream) const
	{
		stream.push(reinterpret_cast<const uint8_t(&)[sizeof(*this)]>(*this));
	}

	[[nodiscard]] std::string to_string() const
	{
		return "CheckStateAction()";
	}
};

/**
 * @brief Represents a generic action.
 */
struct Action
{
	std::variant<FlowAction, DumpAction, CheckStateAction> raw_action;

	Action() :
	        raw_action(FlowAction()) {}

	template<typename T>
	Action(T action) :
	        raw_action(std::move(action)) {}

	void pop(stream_in_t& stream)
	{
		stream.pop(raw_action);
	}
	void push(stream_out_t& stream) const
	{
		stream.push(raw_action);
	}

	[[nodiscard]] std::string to_string() const
	{
		return std::visit([](auto&& action) { return action.to_string(); }, raw_action);
	}
};

namespace acl
{
/**
 * This struct is used for an intermediate representation of an object that
 * describes a list of actions that needs to be performed on a packet that matched some group.
 *
 * Such objects are created in total_table_t::compile.
 *
 * This representation is intermediate cause the Actions objects that are we going to use in dataplane
 * will have slightly different representation of the internal vector based on whether we have
 * a "check-state" action or not. This way we can reduce a number of branching in the dataplane and
 * also reduce the size of the object since we will use std::variant to hold either a "check-state"-object,
 * or a regular one (see common::Actions definition below)
 */
struct Actions
{
	std::vector<Action> path{};
	std::array<size_t, std::variant_size_v<decltype(Action::raw_action)>> action_counts = {0};
	std::optional<size_t> check_state_index{};

	Actions() = default;
	Actions(const Action& action) { add(action); };

	void add(const Action& action)
	{
		size_t index = action.raw_action.index();

		if (std::holds_alternative<FlowAction>(action.raw_action))
		{
			assert(action_counts[index] == 0 && "Incorrectly requested to add more than one FlowAction");
		}
		else
		{
			size_t max_count = std::visit([](auto&& arg) { return std::decay_t<decltype(arg)>::MAX_COUNT; },
			                              action.raw_action);
			if (action_counts[index] >= max_count)
			{
				return;
			}
		}

		if (std::holds_alternative<CheckStateAction>(action.raw_action))
		{
			check_state_index = path.size();
		}

		action_counts[index]++;
		path.push_back(action);
	}
};

} // namespace acl

template<bool HasCheckState>
class BaseActions;

template<>
class BaseActions<false>
{
private:
	std::vector<Action> path_{};

public:
	BaseActions() = default;

	BaseActions(acl::Actions&& actions) :
	        path_(std::move(actions.path)) {}

	[[nodiscard]] const Action& get_last() const
	{
		assert(!path_.empty());
		return path_.back();
	}

	Action& get_last()
	{
		assert(!path_.empty());
		return path_.back();
	}

	[[nodiscard]] const std::vector<Action>& get_actions() const
	{
		return path_;
	}

	[[nodiscard]] const common::globalBase::tFlow& get_flow() const
	{
		assert(std::holds_alternative<FlowAction>(get_last().raw_action));
		return std::get<FlowAction>(get_last().raw_action).flow;
	}

	[[nodiscard]] common::globalBase::tFlow& get_flow()
	{
		assert(std::holds_alternative<FlowAction>(get_last().raw_action));
		return std::get<FlowAction>(get_last().raw_action).flow;
	}

	bool operator<(const BaseActions& second) const
	{
		return get_flow() < second.get_flow();
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(path_);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(path_);
	}
};

template<>
class BaseActions<true>
{
private:
	std::vector<Action> path_{};
	// TODO: This is a prefix of a path_, in C++-20 I would use std::span to avoid extra copying
	std::vector<Action> check_state_path_{};

public:
	BaseActions() = default;
	BaseActions(acl::Actions&& actions)
	{
		assert(actions.check_state_index.has_value());
		auto check_state_index = static_cast<std::ptrdiff_t>(actions.check_state_index.value());

		path_ = std::move(actions.path);

		// check_state_path_ is the prefix up to the check-state action inclusively
		check_state_path_.assign(path_.begin(), path_.begin() + check_state_index + 1);

		// Remove the check-state action from the main path_
		path_.erase(path_.begin() + check_state_index);
	}

	[[nodiscard]] const std::vector<Action>& get_actions() const
	{
		return path_;
	}

	[[nodiscard]] const std::vector<Action>& get_check_state_actions() const
	{
		return check_state_path_;
	}

	[[nodiscard]] const Action& get_last() const
	{
		assert(!path_.empty());
		return path_.back();
	}

	Action& get_last()
	{
		assert(!path_.empty());
		return path_.back();
	}

	[[nodiscard]] const common::globalBase::tFlow& get_flow() const
	{
		assert(std::holds_alternative<FlowAction>(get_last().raw_action));
		return std::get<FlowAction>(get_last().raw_action).flow;
	}

	[[nodiscard]] common::globalBase::tFlow& get_flow()
	{
		assert(std::holds_alternative<FlowAction>(get_last().raw_action));
		return std::get<FlowAction>(get_last().raw_action).flow;
	}

	bool operator<(const BaseActions& second) const
	{
		return get_flow() < second.get_flow();
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(path_);
		stream.pop(check_state_path_);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(path_);
		stream.push(check_state_path_);
	}
};

/**
 * The Actions type is defined as a std::variant to efficiently handle two possible states of action sequences:
 * - BaseActions<true>: This specialization is used when the action sequence contains a check-state action.
 * - BaseActions<false>: This specialization is used when the action sequence does not contain a check-state action.
 *
 * This approach allows us to avoid runtime branching to check for the presence of a check-state action, thereby
 * enhancing performance. Instead, the decision is made once when constructing the Actions object.
 *
 * During packet processing in the dataplane, this enables a more efficient execution path, as the
 * type of Actions being processed (with or without check-state) can be resolved at compile time using std::visit.
 * We will still have one extra branch on packet cause we need to know whether it will require a check-state, but
 * that will be only once. Once the result of a check-state is determined, we will choose correct path and execute it
 * without any additional checks.
 */
using Actions = std::variant<BaseActions<true>, BaseActions<false>>;

} // namespace common
