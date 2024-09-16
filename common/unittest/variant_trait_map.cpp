#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <optional>

#include "common/variant_trait_map.h"

struct A
{};
struct B
{};
struct C
{};
struct D
{};

// Trait that holds for A and C
template<typename T>
struct SomeTrait : std::false_type
{};

template<>
struct SomeTrait<A> : std::true_type
{};

template<>
struct SomeTrait<C> : std::true_type
{};

// Trait that holds for all types
template<typename T>
struct AllTrait : std::true_type
{};

// Trait that holds for no types
template<typename T>
struct NoTrait : std::false_type
{};

using utils::VariantTraitMap;

TEST(VariantTraitMap, BasicUsage)
{
	using MyVariant = std::variant<A, B, C>;
	VariantTraitMap<MyVariant, SomeTrait, size_t> map;

	map.get<A>() = 42;
	EXPECT_EQ(map.get<A>(), 42);

	map.get<C>() = 100;
	EXPECT_EQ(map.get<C>(), 100);

	++map.get<A>();
	EXPECT_EQ(map.get<A>(), 43);

	map.set<C>(200);
	EXPECT_EQ(map.get<C>(), 200);

	MyVariant runtime_variant(A{});

	std::visit([&map](auto&& actual_variant) {
		using T = std::decay_t<decltype(actual_variant)>;

		if constexpr (SomeTrait<T>::value)
		{
			EXPECT_EQ(map.get<T>(), 43);
		}
	},
	           runtime_variant);

	// The following lines should cause compile-time errors if uncommented
	// map.get<B>(); // B does not satisfy SomeTrait
	// map.get<D>(); // D is not in MyVariant
}

TEST(VariantTraitMap, NoTypesTrait)
{
	using MyVariant [[maybe_unused]] = std::variant<A, B, C>;
	// The following line should cause a compile-time error because no types satisfy the trait
	// VariantTraitMap<MyVariant, NoTrait, int> map;
}

TEST(VariantTraitMap, SingleTypeVariant)
{
	using MyVariant = std::variant<A>;
	VariantTraitMap<MyVariant, SomeTrait, int> map;

	map.get<A>() = 10;
	EXPECT_EQ(map.get<A>(), 10);
}

TEST(VariantTraitMap, AllTypesTrait)
{
	using MyVariant = std::variant<A, B, C>;
	VariantTraitMap<MyVariant, AllTrait, std::optional<int>> map;

	map.get<A>() = 1;
	map.get<B>() = -2;

	EXPECT_EQ(map.get<A>().value(), 1);
	EXPECT_EQ(map.get<B>().value(), -2);
	// will be default constructed
	EXPECT_EQ(map.get<C>(), std::nullopt);
}

TEST(VariantTraitMap, EmptyVariant)
{
	using MyVariant [[maybe_unused]] = std::variant<>;
	// The following line should cause a compile-time error because the variant is empty
	// VariantTraitMap<MyVariant, SomeTrait, int> map;
}
