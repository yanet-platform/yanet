#pragma once

#include <utility>

#include "common/type.h"
#include "common/variant.h"
#include "config.release.h"
#include "stream.h"

namespace common
{

namespace acl
{
// class action_t is used to store all non-terminating rule data that
// shouldn't be stored in common::globalBase::tFlow
// TODO: I don't think that storing all non-terminating rule data in one struct is a good thing.
// This will pollute the abstraction and the class size will grow when we will introduce new nonterminating
// kind of rules. I think that defining a new struct/class for each rule kind and then using it in an std::variant
// is a preffered approach. If so, then this class should not be called "action_t" and rather "dump_t".
class action_t
{
public:
	action_t() :
	        dump_id(0),
	        dump_tag("")
	{}

	action_t(std::string dump_tag) :
	        dump_id(0),
	        dump_tag(std::move(dump_tag))
	{}

	inline bool operator==(const action_t& o) const
	{
		return std::tie(dump_id, dump_tag) ==
		       std::tie(o.dump_id, o.dump_tag);
	}

	inline bool operator!=(const action_t& o) const
	{
		return !operator==(o);
	}

	constexpr bool operator<(const action_t& o) const
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
struct DumpAction final
{
	// Only one DumpAction is allowed in one Actions object.
	// See @class Actions.
	static constexpr size_t MAX_COUNT = YANET_CONFIG_DUMP_ID_SIZE;

	uint64_t dump_id;

	DumpAction(const acl::action_t& dump_action) :
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

struct FlowAction final
{
	// Only one FlowAction is allowed in one Actions object.
	// See @class Actions.
	static constexpr size_t MAX_COUNT = 1;

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

struct CheckStateAction final
{
	// Only one CheckStateAction is allowed in one Actions object.
	// See @class Actions.
	static constexpr size_t MAX_COUNT = 1;

	CheckStateAction(const acl::check_state_t&){};
	CheckStateAction() = default;

	[[nodiscard]] bool terminating() const { return false; }

	void pop(stream_in_t& stream)
	{
		stream.pop((char*)this, sizeof(*this));
	}

	void push(stream_out_t& stream) const
	{
		stream.push((char*)this, sizeof(*this));
	}
};

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

class Actions
{
private:
	std::vector<Action> path_{};
	std::array<size_t, std::variant_size_v<decltype(Action::raw_action)>> action_counts_ = {0};

public:
	Actions() = default;
	Actions(const Action& action) { add(action); };

	void add(const Action& action)
	{
		size_t index = action.raw_action.index();
		static constexpr size_t flow_action_index =
		        common::variant::get_index<FlowAction, decltype(Action::raw_action)>::value;

		if (index == flow_action_index)
		{
			assert(action_counts_[index] == 0 && "Cannot add more than one FlowAction");
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
