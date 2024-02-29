#pragma once

#include <memory>
#include <vector>

#include "stream.h"

namespace common::memory_manager
{

inline uint64_t convert_string_to_bytes(std::string string)
{
	static std::map<char, uint64_t> multipliers =
	        {{'k', 1024ull},
	         {'K', 1024ull},
	         {'m', 1024ull * 1024ull},
	         {'M', 1024ull * 1024ull},
	         {'g', 1024ull * 1024ull * 1024ull},
	         {'G', 1024ull * 1024ull * 1024ull}};

	if (string.empty())
	{
		return 0;
	}

	uint64_t multiplier = 1;

	auto iter = multipliers.find(string.back());
	if (iter != multipliers.end())
	{
		multiplier = iter->second;
		string.pop_back();
	}

	return std::stoll(string) * multiplier;
}

class memory_group
{
public:
	memory_group() :
	        limit(0)
	{
	}

	template<typename callback_t>
	std::set<std::string> for_each(const callback_t& callback) const
	{
		std::set<std::string> object_names;

		if (memory_groups.empty())
		{
			object_names.emplace(name);
		}
		else
		{
			for (const auto& memory_group_next : memory_groups)
			{
				auto object_names_next = memory_group_next->for_each(callback);
				for (const auto& object_name : object_names_next)
				{
					object_names.emplace(object_name);
				}
			}
		}

		callback(*this, object_names);
		return object_names;
	}

	void pop(common::stream_in_t& stream)
	{
		stream.pop(name);
		stream.pop(limit);
		stream.pop(memory_groups);
	}

	void push(common::stream_out_t& stream) const
	{
		stream.push(name);
		stream.push(limit);
		stream.push(memory_groups);
	}

public:
	std::string name;
	uint64_t limit;
	std::vector<std::shared_ptr<memory_group>> memory_groups;
};

}
