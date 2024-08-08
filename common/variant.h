#pragma once

#include <variant>

namespace common::variant
{
/**
 * @brief Template structure to get the index of a type T within a std::variant.
 *
 * This template uses std::variant's in-place type construction to determine
 * the zero-based index of the type T within the variant type V.
 *
 * Example Usage:
 * using MyVariant = std::variant<int, std::string, double>;
 * constexpr size_t index = get_index<std::string, MyVariant>::value; // index will be 1
 *
 * @tparam T The type to find the index of within the variant.
 * @tparam V The variant type which contains the types.
 */
template<typename T, typename V>
struct get_index;

template<typename T, typename... Ts>
struct get_index<T, std::variant<Ts...>>
        : std::integral_constant<std::size_t,
                                 std::variant<std::in_place_type_t<Ts>...>(std::in_place_type_t<std::in_place_type_t<T>>()).index()>
{};
}
