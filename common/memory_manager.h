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
