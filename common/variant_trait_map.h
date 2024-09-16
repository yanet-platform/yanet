#pragma once

#include "tuple.h"

namespace utils
{

/**
 * @brief A class that maps types in a variant to a value V, based on a trait.
 *
 * This class uses a std::tuple to hold values of type V for each type in the
 * variant that satisfies the trait.
 *
 * Example Usage:
 * struct A {};
 * struct B {};
 * struct C {};
 *
 * template<typename T>
 * struct IsSpecial : std::false_type {};
 *
 * template<>
 * struct IsSpecial<A> : std::true_type {};
 *
 * template<>
 * struct IsSpecial<C> : std::true_type {};
 *
 * using Variant = std::variant<A, B, C>;
 * using MyMap = VariantTraitMap<Variant, IsSpecial, std::optional<size_t>>;
 *
 * MyMap map;
 * map.set<A>(42); // Works because A satisfies IsSpecial
 * map.set<C>(99); // Works because C satisfies IsSpecial
 * auto val = map.get<A>(); // Returns 42
 * auto val = map.get<B>(); // Compile-time error because B does not satisfy IsSpecial
 *
 * @tparam Variant The std::variant type containing different types.
 * @tparam Trait   The trait that defines which types are mapped to a value.
 * @tparam V       The value type to map the types to
 */
template<typename Variant, template<typename> class Trait, typename V>
class VariantTraitMap
{
private:
	using AllTypes = typename VariantTypes<Variant>::type;
	static_assert(std::tuple_size<AllTypes>::value > 0, "Variant is empty");

	using FilteredTypes = typename FilteredTuple<Trait, AllTypes>::type;
	static_assert(std::tuple_size<FilteredTypes>::value > 0, "No types satisfy the trait");

	template<typename Tuple>
	struct StorageFromTuple;

	template<typename... Ts>
	struct StorageFromTuple<std::tuple<Ts...>>
	{
		using type = std::tuple<decltype((void)Ts(), V())...>;
	};

	using Storage = typename StorageFromTuple<FilteredTypes>::type;

	// Storage is a tuple of V types repeated for each type in FilteredTypes
	Storage storage_;

public:
	VariantTraitMap() = default;

	/**
	 * @brief Retrieves the value associated with a specific type.
	 *
	 * This function retrieves the value of type V that is associated with a type T in the variant.
	 *
	 * Example:
	 * map.get<A>() = 42;
	 * size_t value = map.get<A>();
	 *
	 * @tparam T The type to retrieve the value for.
	 * @return V& The value of type V associated with type T.
	 */
	template<typename T>
	V& get()
	{
		static_assert(IsInTuple<T, AllTypes>::value, "Type T is not in Variant");
		static_assert(Trait<T>::value, "Type T does not satisfy Trait");
		constexpr std::size_t index = IndexOf<T, FilteredTypes>::value;
		return std::get<index>(storage_);
	}

	/**
	 * @brief Retrieves the value associated with a specific type (const version).
	 *
	 * This function retrieves the const value of type V that is associated with a type T in the variant.
	 *
	 * @tparam T The type to retrieve the value for.
	 * @return const V& The const value of type V associated with type T.
	 */
	template<typename T>
	const V& get() const
	{
		static_assert(IsInTuple<T, AllTypes>::value, "Type T is not in Variant");
		static_assert(Trait<T>::value, "Type T does not satisfy Trait");
		constexpr std::size_t index = IndexOf<T, FilteredTypes>::value;
		return std::get<index>(storage_);
	}

	/**
	 * @brief Sets the value associated with a specific type.
	 *
	 * This function sets the value of type V for a specific type T in the variant.
	 *
	 * Example:
	 * map.set<A>(42);
	 *
	 * @tparam T The type to set the value for.
	 * @param val The value of type V to set.
	 */
	template<typename T>
	void set(const V& val)
	{
		get<T>() = val;
	}
};

} // namespace utils
