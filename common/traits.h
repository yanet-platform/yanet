#pragma once

#include <functional>
#include <iterator>
#include <optional>
#include <set>
#include <type_traits>
#include <variant>
#include <vector>

namespace traits
{

template<typename>
struct always_false : std::false_type
{};

template<typename T>
inline constexpr bool always_false_v = always_false<T>::value;

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

template<typename T>
struct function
{
	template<typename R, typename... Args>
	static std::tuple<Args...> pro_args(std::function<R(Args...)>);

	using args = decltype(pro_args(std::function{std::declval<T>()}));
};

template<typename T, typename = std::void_t<>>
struct has_ToString : std::false_type
{};

template<typename T>
struct has_ToString<T, std::void_t<decltype(std::declval<T>().ToString())>> : std::true_type
{};

template<typename T>
inline constexpr bool has_ToString_v = has_ToString<T>::value;

}
// namespace utils
