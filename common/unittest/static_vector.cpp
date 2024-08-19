#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define STATIC_VECTOR_USE_EXCEPTIONS
#include "../static_vector.h"

namespace
{
using utils::StaticVector;

static constexpr std::string_view hw = "Hello World!";

TEST(StaticVector, 001_Basic_element_store)
{
	StaticVector<char, hw.length()> v;
	ASSERT_TRUE(v.empty());
	for (auto& c : hw)
	{
		v.push_back(c);
	}
	ASSERT_EQ(hw.length(), v.size());
	ASSERT_EQ(v.size(), v.capacity());
	ASSERT_TRUE(v.Full());
	bool caught = false;
	try
	{
		v.push_back('c');
	}
	catch (std::out_of_range& e)
	{
		caught = true;
	}
	ASSERT_TRUE(caught);
}

TEST(StaticVector, 002_POD_copy_move)
{
	std::vector<std::uint64_t> ref;
	StaticVector<std::uint64_t, 5> v;
	for (auto e : ref)
	{
		v.push_back(e);
	}
	auto copy = v;
	ASSERT_TRUE(std::mismatch(v.begin(), v.end(), copy.begin()).first == v.end());
	auto moved = std::move(copy);
	ASSERT_TRUE(std::mismatch(v.begin(), v.end(), moved.begin()).first == v.end());
}

} // namespace