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
};

/**
 * @brief Represents a collection of actions to be performed on a packet.
 *
 * The last rule in the path_ is always a terminating rule.
 */
class Actions
{
private:
	// The sequence of actions to be executed.
	std::vector<Action> path_{};
	// Count of each type of action.
	std::array<size_t, std::variant_size_v<decltype(Action::raw_action)>> action_counts_ = {0};

public:
	Actions() = default;
	Actions(const Action& action) { add(action); };

	void add(const Action& action)
	{
		size_t index = action.raw_action.index();

		if (std::holds_alternative<FlowAction>(action.raw_action))
		{
			assert(action_counts_[index] == 0 && "Incorrectly requested to add more than one FlowAction");
		}
		else
		{
			size_t max_count = std::visit([](auto&& arg) { return std::decay_t<decltype(arg)>::MAX_COUNT; },
			                              action.raw_action);
			if (action_counts_[index] >= max_count)
			{
				return;
			}
		}

		action_counts_[index]++;
		path_.push_back(action);
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

	// TODO: Why do we need it?..
	bool operator<(const Actions& second) const
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

	[[nodiscard]] const std::vector<Action>& get_actions() const
	{
		return path_;
	}
};

} // namespace common
