#pragma once

#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

namespace converter
{

struct config_t
{
	std::string optional_null = "n/s";
	std::string string_empty = "";
	std::string vector_empty = "";
	std::string set_empty = "n/s";
};

template<typename arg_T>
std::string to_string(const std::optional<arg_T>& value, const config_t config = {});
template<typename... args_T>
std::string to_string(const std::variant<args_T...>& value, const config_t config = {});
template<typename arg_T>
std::string to_string(const std::vector<arg_T>& vector, const config_t config = {});
template<typename arg_T>
std::string to_string(const std::set<arg_T>& set, const config_t config = {});
std::string to_string(const bool& value, const config_t config = {});
std::string to_string(const std::string& string, const config_t config = {});
template<typename arg_T>
std::string to_string(const arg_T& value, const config_t config = {});

template<typename arg_T>
std::string to_string(const std::optional<arg_T>& value,
                      const config_t config)
{
	if (value)
	{
		return to_string(*value, config);
	}
	else
	{
		return config.optional_null;
	}
};

template<typename... args_T>
std::string to_string(const std::variant<args_T...>& value,
                      const config_t config)
{
	return std::visit([&config](const auto& value) -> std::string { return to_string(value, config); }, value);
};

template<typename arg_T>
std::string to_string(const std::vector<arg_T>& vector,
                      const config_t config)
{
	if (vector.empty())
	{
		return config.vector_empty;
	}

	bool first = true;
	std::ostringstream result;
	for (const auto& item : vector)
	{
		if (!first)
		{
			result << ","; ///< @todo: config
		}

		result << to_string(item, config);
		first = false;
	}
	return result.str();
}

template<typename arg_T>
std::string to_string(const std::set<arg_T>& set,
                      const config_t config)
{
	if (set.empty())
	{
		return config.set_empty;
	}

	bool first = true;
	std::ostringstream result;
	for (const auto& item : set)
	{
		if (!first)
		{
			result << ","; ///< @todo: config
		}

		result << to_string(item, config);
		first = false;
	}
	return result.str();
}

std::string to_string(const bool& value,
                      [[maybe_unused]] const config_t config)
{
	if (value)
	{
		return "true";
	}
	else
	{
		return "false";
	}
};

std::string to_string(const std::string& string,
                      const config_t config)
{
	if (string.empty())
	{
		return config.string_empty;
	}
	else
	{
		return string;
	}
};

template<typename arg_T>
std::string to_string(const arg_T& value,
                      [[maybe_unused]] const config_t config)
{
	if constexpr (std::is_constructible_v<std::string, decltype(value)>)
	{
		return value;
	}
	else
	{
		return std::to_string(value);
	}
};

}
