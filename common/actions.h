#pragma once

#include "stream.h"
#include <utility>

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
} // namespace common
