#pragma once

#include <array>
#include <tuple>
#include <type_traits>
#include <variant>

namespace utils
{

/**
 * @brief Helper structure to extract types from a std::variant.
 *
 * This template specialization will convert a std::variant<Types...> into a std::tuple<Types...>.
 *
 * Example:
 * using Variant = std::variant<int, double, std::string>;
 * using TupleTypes = VariantTypes<Variant>::type; // std::tuple<int, double, std::string>
 *
 * @tparam Variant The std::variant type from which to extract types.
 */
template<typename Variant>
struct VariantTypes;

template<typename... Types>
struct VariantTypes<std::variant<Types...>>
{
	using type = std::tuple<Types...>;
};

/**
 * @brief Helper structure to filter types in a parameter pack according to a trait.
 *
 * Filters the types in a parameter pack based on whether they satisfy a given trait.
 * The result is a std::tuple containing only the types that satisfy the trait.
 *
 * Example:
 * using Filtered = FilteredTuple<std::is_integral, int, double, char>::type; // std::tuple<int, char>
 *
 * @tparam Trait The trait to filter types by.
 * @tparam Ts The types to filter.
 */
template<template<typename> class Trait, typename... Ts>
struct FilteredTuple
{
	using type = decltype(std::tuple_cat(
	        std::conditional_t<Trait<Ts>::value, std::tuple<Ts>, std::tuple<>>{}...));
};

/**
 * @brief Helper structure to filter types in a std::tuple according to a trait.
 *
 * This specialization allows you to pass a std::tuple of types to FilteredTuple.
 *
 * Example:
 * using MyTuple = std::tuple<int, double, char>;
 * using Filtered = FilteredTupleFromTuple<std::is_integral, MyTuple>::type; // std::tuple<int, char>
 *
 * @tparam Trait The trait to filter types by.
 * @tparam Tuple The std::tuple containing types to filter.
 */
template<template<typename> class Trait, typename... Ts>
struct FilteredTuple<Trait, std::tuple<Ts...>>
{
	using type = typename FilteredTuple<Trait, Ts...>::type;
};

/**
 * @brief Helper structure to check if a type is present in a std::tuple.
 *
 * Example:
 * using MyTuple = std::tuple<int, double, char>;
 * constexpr bool isInTuple = IsInTuple<int, MyTuple>::value; // true
 *
 * @tparam T The type to check for.
 * @tparam Tuple The std::tuple type to check within.
 */
template<typename T, typename Tuple>
struct IsInTuple;

template<typename T, typename... Ts>
struct IsInTuple<T, std::tuple<Ts...>> : std::disjunction<std::is_same<T, Ts>...>
{};

/**
 * @brief Helper structure to get the index of a first occurence of a type in a std::tuple.
 *
 * This structure calculates the zero-based index of type T within a std::tuple<Types...>.
 * If the type is not found, a compile-time error is raised.
 *
 * Example:
 * using MyTuple = std::tuple<int, double, char>;
 * constexpr std::size_t index = IndexOf<double, MyTuple>::value; // index will be 1
 *
 * @tparam T The type to find the index of.
 * @tparam Tuple The std::tuple type containing the types.
 */
template<typename T, typename Tuple>
struct IndexOf;

template<typename T, typename... Types>
struct IndexOf<T, std::tuple<Types...>>
{
private:
	template<std::size_t Index>
	struct Helper
	{
		static constexpr std::size_t value()
		{
			if constexpr (Index >= sizeof...(Types))
			{
				static_assert(Index < sizeof...(Types), "Type T not found in tuple");
				return 0; // This line will never be reached
			}
			else if constexpr (std::is_same_v<T, std::tuple_element_t<Index, std::tuple<Types...>>>)
			{
				return Index;
			}
			else
			{
				return Helper<Index + 1>::value();
			}
		}
	};

public:
	static constexpr std::size_t value = Helper<0>::value();
};

/**
 * @brief Helper to get the size of the first tuple in a parameter pack.
 *
 * This function extracts the size of the first tuple in the parameter pack `Tuples`.
 *
 * @tparam Tuples The types of the tuples.
 * @return The size of the first tuple.
 */
template<typename... Tuples>
constexpr std::size_t get_first_tuple_size()
{
	static_assert(sizeof...(Tuples) > 0, "At least one tuple is required.");
	return std::tuple_size_v<std::decay_t<std::tuple_element_t<0, std::tuple<Tuples...>>>>;
}

template<std::size_t I, std::size_t N, typename Func, typename... Tuples>
static void zip_apply_helper(Func&& f, Tuples&&... tuples)
{
	if constexpr (I < N)
	{
		f(std::get<I>(std::forward<Tuples>(tuples))...);
		zip_apply_helper<I + 1, N>(std::forward<Func>(f), std::forward<Tuples>(tuples)...);
	}
}

/**
 * @brief Applies a function to corresponding elements of multiple tuples.
 *
 * The function `f` should be callable with the elements of the tuples at each index.
 * This function works with any number of tuples, as long as they are all the same size.
 *
 * Example:
 * ```
 * auto t1 = std::make_tuple(1, 2, 3);
 * auto t2 = std::make_tuple(4, 5, 6);
 * zip_apply([](auto a, auto b) {  do something with a and b }, t1, t2);
 * ```
 *
 * @tparam Func The type of the function to apply.
 * @tparam Tuples The types of the tuples.
 * @param f The function to apply.
 * @param tuples The tuples to iterate over.
 */
template<typename Func, typename... Tuples>
inline void zip_apply(Func&& f, Tuples&&... tuples)
{
	constexpr std::size_t tuple_size = get_first_tuple_size<Tuples...>();
	static_assert((... && (std::tuple_size_v<std::decay_t<Tuples>> == tuple_size)), "All tuples must have the same size.");

	zip_apply_helper<0, tuple_size>(std::forward<Func>(f), std::forward<Tuples>(tuples)...);
}

} // namespace utils
