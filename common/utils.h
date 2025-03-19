#pragma once

#include <iomanip>
#include <vector>

namespace utils
{

// Utility to calculate percentage
// TODO C++20: use std::type_identity_t to establish non-deduced context
// Will allow to do `to_percent(4.2, 1)`
template<typename T>
inline std::string to_percent(T current, T maximum = 1)
{
	double percent = 0.0;
	if (maximum != 0)
	{
		percent = static_cast<double>(current) / static_cast<double>(maximum) * 100.0;
	}

	std::ostringstream stream;
	stream << std::fixed << std::setprecision(2) << percent;
	return stream.str();
}

// Split a string_view into a vector of strings based on a delimiter
inline std::vector<std::string> split(const std::string_view str, char delimiter)
{
	std::vector<std::string> result;
	size_t start = 0;
	size_t end = 0;

	while ((end = str.find(delimiter, start)) != std::string_view::npos)
	{
		result.emplace_back(str.substr(start, end - start));
		start = end + 1;
	}
	result.emplace_back(str.substr(start));
	return result;
}

// Split for std::string but disabled for const char* to avoid ambiguity
template<typename T, typename = std::enable_if_t<!std::is_same_v<T, const char*>>>
inline std::vector<std::string> split(const std::string& str, char delimiter)
{
	return split(std::string_view(str), delimiter);
}

// helper type for the variant visitor
template<class... Ts>
struct Visitor : Ts...
{
	using Ts::operator()...;
};
// explicit deduction guide (not needed as of C++20)
template<class... Ts>
Visitor(Ts...) -> Visitor<Ts...>;

}
// namespace utils
