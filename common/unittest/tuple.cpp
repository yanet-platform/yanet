#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "common/tuple.h"

namespace
{

using utils::VariantTypes;

TEST(VariantTypes, BasicExtraction)
{
	using Variant = std::variant<int, double, std::string>;
	using ExpectedTuple = std::tuple<int, double, std::string>;
	using ExtractedTuple = typename VariantTypes<Variant>::type;

	static_assert(std::is_same_v<ExtractedTuple, ExpectedTuple>, "Extracted tuple doesn't match expected");
}

TEST(VariantTypes, EmptyVariant)
{
	using Variant = std::variant<>;
	using ExpectedTuple = std::tuple<>;
	using ExtractedTuple = typename VariantTypes<Variant>::type;

	static_assert(std::is_same_v<ExtractedTuple, ExpectedTuple>, "Extracted empty tuple doesn't match expected");
}

using utils::FilteredTuple;

TEST(FilteredTuple, FilteredTypes)
{
	using Filtered = typename FilteredTuple<std::is_integral, int, double, char>::type;
	using Expected = std::tuple<int, char>;

	static_assert(std::is_same_v<Filtered, Expected>, "Filtered tuple does not match expected");

	using InputTuple = std::tuple<int, double, char>;
	using Filtered = typename FilteredTuple<std::is_integral, InputTuple>::type;

	static_assert(std::is_same_v<Filtered, Expected>, "Filtered tuple does not match expected");
}

TEST(FilteredTuple, NoMatch)
{
	using Filtered = typename FilteredTuple<std::is_integral, double, float, std::string>::type;
	using Expected = std::tuple<>;

	static_assert(std::is_same_v<Filtered, Expected>, "Expected empty tuple when no types match");

	using InputTuple = std::tuple<double, float, std::string>;
	using Filtered = typename FilteredTuple<std::is_integral, InputTuple>::type;

	static_assert(std::is_same_v<Filtered, Expected>, "Expected empty tuple when no types match");
}

TEST(FilteredTuple, AllMatch)
{
	using Filtered = typename FilteredTuple<std::is_integral, int, char, long>::type;
	using Expected = std::tuple<int, char, long>;

	static_assert(std::is_same_v<Filtered, Expected>, "Filtered tuple should include all types");

	using InputTuple = std::tuple<int, char, long>;
	using Filtered = typename FilteredTuple<std::is_integral, InputTuple>::type;

	static_assert(std::is_same_v<Filtered, Expected>, "Filtered tuple should include all types");
}

using utils::IsInTuple;

TEST(IsInTuple, TypeInTuple)
{
	using MyTuple = std::tuple<int, double, char>;

	constexpr bool is_int = IsInTuple<int, MyTuple>::value;
	EXPECT_TRUE(is_int);

	constexpr bool is_float = IsInTuple<float, MyTuple>::value;
	EXPECT_FALSE(is_float);
}

TEST(IsInTuple, EmptyTuple)
{
	using EmptyTuple = std::tuple<>;

	constexpr bool is_int = IsInTuple<int, EmptyTuple>::value;
	EXPECT_FALSE(is_int);
}

using utils::IndexOf;

TEST(IndexOf, IndexCalculation)
{
	using MyTuple = std::tuple<int, double, char>;

	constexpr std::size_t index1 = IndexOf<int, MyTuple>::value;
	constexpr std::size_t index2 = IndexOf<double, MyTuple>::value;
	constexpr std::size_t index3 = IndexOf<char, MyTuple>::value;

	EXPECT_EQ(index1, 0);
	EXPECT_EQ(index2, 1);
	EXPECT_EQ(index3, 2);
}

TEST(IndexOf, MultipleOccurrences)
{
	using MyTuple = std::tuple<int, double, int, char, int>;

	constexpr std::size_t index1 = IndexOf<int, MyTuple>::value;
	constexpr std::size_t index2 = IndexOf<double, MyTuple>::value;
	constexpr std::size_t index3 = IndexOf<char, MyTuple>::value;

	EXPECT_EQ(index1, 0); // IndexOf should return the first occurrence of 'int'
	EXPECT_EQ(index2, 1); // 'double' appears at index 1
	EXPECT_EQ(index3, 3); // 'char' appears at index 3
}

TEST(IndexOf, TypeNotFound)
{
	using MyTuple [[maybe_unused]] = std::tuple<int, double, char>;

	// Expect compile-time failure for a type not present in the tuple
	// The following line should trigger a compile-time error
	// constexpr std::size_t invalidIndex = IndexOf<float, MyTuple>::value;
}

TEST(IndexOf, EmptyTuple)
{
	using EmptyTuple [[maybe_unused]] = std::tuple<>;

	// Expect a compile-time failure if trying to get index from an empty tuple
	// Uncommenting the following line should trigger a compile-time error:
	// constexpr std::size_t invalidIndex = IndexOf<int, EmptyTuple>::value;
}

} // namespace
