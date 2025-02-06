#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "controlplane/ndarray.h"

TEST(ndarray, basic)
{
	acl::compiler::NDArray<int, 2> table;

	table.prepare(3u, 4u);

	EXPECT_EQ(table.size(), 12u);
	EXPECT_EQ(table.sizes().size(), 2u);
	EXPECT_EQ(table.sizes()[0], 3u);
	EXPECT_EQ(table.sizes()[1], 4u);
}

TEST(ndarray, fill_and_get_2d)
{
	using Table = acl::compiler::NDArray<int, 2>;

	std::map<Table::DimensionArray, int> equivalent_map;
	Table table;

	table.prepare(3u, 4u);

	for (unsigned int x = 0; x < 3; x++)
	{
		for (unsigned int y = 0; y < 4; y++)
		{
			auto encoded_value = static_cast<int>((x << 4) | (y + 1));

			table(x, y) = encoded_value;
			equivalent_map[{x, y}] = encoded_value;
		}
	}

	EXPECT_THAT(table.values(), ::testing::ElementsAre(1u, 2u, 3u, 4u, 1u + (1u << 4), 2u + (1u << 4), 3u + (1u << 4), 4u + (1u << 4), 1u + (2u << 4), 2u + (2u << 4), 3u + (2u << 4), 4u + (2u << 4)));

	size_t count = 0;
	table.for_each([&](const Table::DimensionArray& keys, int value) {
		EXPECT_EQ(equivalent_map[keys], value);
		count++;
	});
	EXPECT_EQ(count, 12u);
}

TEST(ndarray, fill_and_get_3d)
{
	using Table = acl::compiler::NDArray<int, 3>;

	std::map<Table::DimensionArray, int> equivalent_map;
	Table table;

	table.prepare(2u, 3u, 4u);
	EXPECT_EQ(table.size(), 24);

	int value = 123;
	for (unsigned int x = 0; x < 2; x++)
	{
		for (unsigned int y = 0; y < 3; y++)
		{
			for (unsigned int z = 0; z < 4; z++)
			{
				table(x, y, z) = value;
				equivalent_map[{x, y, z}] = value;
				value += 9;
			}
		}
	}

	size_t count = 0;
	table.for_each([&](const Table::DimensionArray& keys, int value) {
		EXPECT_EQ(equivalent_map[keys], value);
		count++;
	});
	EXPECT_EQ(count, 24);
}

TEST(ndarray, fill_and_clear_1d)
{
	using Table = acl::compiler::NDArray<int, 1>;
	Table table;

	table.prepare(5u);

	for (unsigned int i = 0; i < 5; i++)
	{
		table(i) = static_cast<int>(i + 10);
	}

	size_t count = 0;
	table.for_each([&](const Table::DimensionArray& key, int value) {
		EXPECT_EQ(value, key[0] + 10u) << "Wrong value at i=" << key[0];
		count++;
	});
	EXPECT_EQ(count, 5u);

	table.clear();
	EXPECT_TRUE(table.empty()) << "Table should be empty after clear()";

	count = 0;
	table.for_each([&](auto, auto) { count++; });
	EXPECT_EQ(count, 0u);
}
