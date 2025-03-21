#pragma once

#include <set>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include "common/traits.h"

namespace converter
{

struct config_t
{
	std::string optional_null = "n/s";
	std::string string_empty = "";
	std::string vector_empty = "";
	std::string set_empty = "n/s";
};

template<typename T>
std::string to_string(const T& value, const config_t& config = {})
{
	if constexpr (std::is_same_v<T, std::string>)
	{
		return value.empty() ? config.string_empty : value;
	}
	else if constexpr (std::is_same_v<T, std::string_view>)
	{
		return value.empty() ? config.string_empty : std::string(value);
	}
	else if constexpr (std::is_constructible_v<std::string, T>)
	{
		return value;
	}
	else if constexpr (std::is_same_v<T, bool>)
	{
		return value ? "true" : "false";
	}
	else if constexpr (std::is_arithmetic_v<T>)
	{
		return std::to_string(value);
	}
	else if constexpr (traits::is_variant_v<T>)
	{
		return std::visit([&config](const auto& val) { return to_string(val, config); }, value);
	}
	else if constexpr (traits::is_optional_v<T>)
	{
		return value ? to_string(*value, config) : config.optional_null;
	}
	else if constexpr (traits::is_container_v<T>)
	{
		if (value.empty())
		{
			if constexpr (traits::is_vector_v<T>)
			{
				return config.vector_empty;
			}
			else if constexpr (traits::is_set_v<T>)
			{
				return config.set_empty;
			}
			else
			{
				static_assert(traits::always_false_v<T>,
				              "Container does not have default empty representation in struct config_t");
			}
		}

		std::ostringstream oss;
		auto it = std::begin(value);
		oss << to_string(*it, config);
		++it;

		for (; it != std::end(value); ++it)
		{
			oss << ',' << to_string(*it, config);
		}

		return oss.str();
	}
	else if constexpr (traits::has_ToString_v<T>)
	{
		return value.ToString();
	}
	else
	{
		static_assert(std::is_constructible_v<std::string, T>,
		              "Type is not convertible to std::string and no overload of to_string is provided");
	}
}

} // namespace converter
