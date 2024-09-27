
#pragma once

#include <iomanip>
#include <iterator>
#include <optional>
#include <set>
#include <iomanip>
#include <type_traits>
#include <variant>
#include <vector>

namespace utils
{

template<typename>
struct always_false : std::false_type
{};

template<typename T>
struct is_optional : std::false_type
{};

template<typename T>
struct is_optional<std::optional<T>> : std::true_type
{};

template<typename T>
inline constexpr bool is_optional_v = is_optional<T>::value;

template<typename T>
struct is_variant : std::false_type
{};

template<typename... Types>
struct is_variant<std::variant<Types...>> : std::true_type
{};

template<typename T>
inline constexpr bool is_variant_v = is_variant<T>::value;

template<typename T, typename = void>
struct is_container : std::false_type
{};

/*
 * Checks:
 * Whether std::begin(T&), std::end(T&) and std::empty(T&) are valid expressions.
 * Whether the result of std::begin(T&) can be dereferenced (i.e., *std::begin(T&) is valid)
 */
template<typename T>
struct is_container<T,
                    std::void_t<
                            decltype(std::begin(std::declval<T&>())),
                            decltype(std::end(std::declval<T&>())),
                            decltype(std::empty(std::declval<T&>())),
                            decltype(*std::begin(std::declval<T&>()))>> : std::true_type
{};

template<typename T>
inline constexpr bool is_container_v = is_container<T>::value;

template<typename T>
struct is_vector : std::false_type
{};

template<typename T, typename Alloc>
struct is_vector<std::vector<T, Alloc>> : std::true_type
{};

template<typename T>
inline constexpr bool is_vector_v = is_vector<T>::value;

template<typename T>
struct is_set : std::false_type
{};

template<typename Key, typename Compare, typename Allocator>
struct is_set<std::set<Key, Compare, Allocator>> : std::true_type
{};

template<typename T>
inline constexpr bool is_set_v = is_set<T>::value;

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

}
// namespace utils
