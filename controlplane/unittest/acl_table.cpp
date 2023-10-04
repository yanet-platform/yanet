#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../acl_table.h"

namespace
{

template<typename... args_T>
void expect_group_ids_helper(std::vector<tAclGroupId>& vector,
                             const unsigned int group_id,
                             const args_T... group_ids)
{
	vector.emplace_back(group_id);

	if constexpr (sizeof...(args_T) != 0)
	{
		expect_group_ids_helper(vector, group_ids...);
	}
}

template<typename... args_T>
std::vector<tAclGroupId> expect_group_ids(const args_T... group_ids)
{
	std::vector<tAclGroupId> result;
	expect_group_ids_helper(result, group_ids...);
	return result;
}

template<typename... args_T>
std::tuple<unsigned int, unsigned int, tAclGroupId> expect_result(const args_T... args)
{
	return {args...};
}

TEST(acl_table, basic)
{
	acl::compiler::table_t<2> table;

	table.prepare(3u, 4u);

	EXPECT_THAT(table.values.size(), 12);
	EXPECT_THAT(table.sizes.size(), 2);
	EXPECT_THAT(table.sizes[0], 3);
	EXPECT_THAT(table.sizes[1], 4);
}

TEST(acl_table, fill_and_get_2d)
{
	acl::compiler::table_t<2> table;
	std::map<std::array<unsigned int, 2>, unsigned int> equivalent_map;

	table.prepare(3u, 4u);

	std::array<size_t, 2> indexes;
	for (unsigned int x = 0;
	     x < 3;
	     x++)
	{
		indexes[0] = table.get_index(0, x);
		for (unsigned int y = 0;
		     y < 4;
		     y++)
		{
			indexes[1] = table.get_index(1, y);
			table.get_value(indexes) = (x << 4) | (y + 1);
			equivalent_map[{x, y}] = (x << 4) | (y + 1);
		}
	}

	EXPECT_THAT(table.values, expect_group_ids(1u, 2u, 3u, 4u, 1u + (1u << 4), 2u + (1u << 4), 3u + (1u << 4), 4u + (1u << 4), 1u + (2u << 4), 2u + (2u << 4), 3u + (2u << 4), 4u + (2u << 4)));

	size_t count = 0;
	table.for_each([&](const std::array<unsigned int, 2>& keys, const tAclGroupId value) {
		EXPECT_THAT(equivalent_map[keys], value);
		count++;
	});
	EXPECT_THAT(count, 12);
}

TEST(acl_table, fill_and_get_3d)
{
	acl::compiler::table_t<3> table;
	std::map<std::array<unsigned int, 3>, unsigned int> equivalent_map;

	table.prepare(2u, 3u, 4u);
	EXPECT_THAT(table.values.size(), 24);

	unsigned int value = 123;
	std::array<size_t, 3> indexes;
	for (unsigned int x = 0;
	     x < 2;
	     x++)
	{
		indexes[0] = table.get_index(0, x);
		for (unsigned int y = 0;
		     y < 3;
		     y++)
		{
			indexes[1] = table.get_index(1, y);
			for (unsigned int z = 0;
			     z < 4;
			     z++)
			{
				indexes[2] = table.get_index(2, z);
				table.get_value(indexes) = value;
				equivalent_map[{x, y, z}] = value;
				value += 9;
			}
		}
	}

	size_t count = 0;
	table.for_each([&](const auto& keys, const tAclGroupId value) {
		EXPECT_THAT(equivalent_map[keys], value);
		count++;
	});
	EXPECT_THAT(count, 24);
}

} // namespace
