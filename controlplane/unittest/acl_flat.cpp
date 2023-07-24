#include <fstream>

#include "gmock/gmock.h"
#include <gtest/gtest.h>

#include "../src/acl_flat.h"

namespace
{

template<typename ... args_T>
void expect_group_ids_helper(std::vector<tAclGroupId>& vector,
                             const unsigned int group_id,
                             const args_T ... group_ids)
{
	vector.emplace_back(group_id);

	if constexpr (sizeof...(args_T) != 0)
	{
		expect_group_ids_helper(vector, group_ids...);
	}
}

template<typename ... args_T>
std::vector<tAclGroupId> expect_group_ids(const args_T ... group_ids)
{
	std::vector<tAclGroupId> result;
	expect_group_ids_helper(result, group_ids...);
	return result;
}

TEST(acl_flat, basic)
{
	acl::compiler::flat_t<uint8_t> flat;

	common::acl::ranges_t<uint8_t> ranges;
	ranges.vector.emplace_back(3, 8);
	flat.collect(ranges);

	flat.prepare();
	flat.compile();
	flat.populate();

	EXPECT_THAT(flat.get_group_ids_by_filter(ranges), expect_group_ids(2));
}

TEST(acl_flat, any)
{
	acl::compiler::flat_t<uint8_t> flat;

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(3, 8);
		flat.collect(ranges);
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.insert_any();
		flat.collect(ranges);
	}

	flat.prepare();
	flat.compile();
	flat.populate();

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(3, 8);
		EXPECT_THAT(flat.get_group_ids_by_filter(ranges), expect_group_ids(2));
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.insert_any();
		EXPECT_THAT(flat.get_group_ids_by_filter(ranges), expect_group_ids(1, 2));
	}

	EXPECT_THAT(flat.group_id, 3);
}

TEST(acl_flat, intersection)
{
	acl::compiler::flat_t<uint8_t> flat;

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(3, 8);
		flat.collect(ranges);
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(0, 0xFF); ///< any
		flat.collect(ranges);
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(5, 12);
		flat.collect(ranges);
	}

	flat.prepare();
	flat.compile();
	flat.populate();

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(3, 8);
		EXPECT_THAT(flat.get_group_ids_by_filter(ranges), expect_group_ids(2, 3));
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(0, 0xFF); ///< any
		EXPECT_THAT(flat.get_group_ids_by_filter(ranges), expect_group_ids(1, 2, 3, 4));
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(5, 12);
		EXPECT_THAT(flat.get_group_ids_by_filter(ranges), expect_group_ids(3, 4));
	}

	EXPECT_THAT(flat.group_id, 5);
}

TEST(acl_flat, get)
{
	acl::compiler::flat_t<uint8_t> flat;

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(3, 8);
		flat.collect(ranges);
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.insert_any();
		flat.collect(ranges);
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(5, 12);
		flat.collect(ranges);
	}

	flat.prepare();
	flat.compile();
	flat.populate();

	EXPECT_THAT(flat.get(0), 1);
	EXPECT_THAT(flat.get(2), 1);
	EXPECT_THAT(flat.get(3), 2);
	EXPECT_THAT(flat.get(4), 2);
	EXPECT_THAT(flat.get(5), 3);
	EXPECT_THAT(flat.get(6), 3);
	EXPECT_THAT(flat.get(7), 3);
	EXPECT_THAT(flat.get(8), 3);
	EXPECT_THAT(flat.get(9), 4);
	EXPECT_THAT(flat.get(11), 4);
	EXPECT_THAT(flat.get(12), 4);
	EXPECT_THAT(flat.get(13), 1);
	EXPECT_THAT(flat.get(50), 1);
	EXPECT_THAT(flat.get(255), 1);

	EXPECT_THAT(flat.group_id, 5);
}

TEST(acl_flat, two_range)
{
	acl::compiler::flat_t<uint8_t> flat;

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(3, 8);
		ranges.vector.emplace_back(13, 20);
		flat.collect(ranges);
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.insert_any();
		flat.collect(ranges);
	}

	flat.prepare();
	flat.compile();
	flat.populate();

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(3, 8);
		ranges.vector.emplace_back(13, 20);
		EXPECT_THAT(flat.get_group_ids_by_filter(ranges), expect_group_ids(2));
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.insert_any();
		EXPECT_THAT(flat.get_group_ids_by_filter(ranges), expect_group_ids(1, 2));
	}

	EXPECT_THAT(flat.get(0), 1);
	EXPECT_THAT(flat.get(2), 1);
	EXPECT_THAT(flat.get(3), 2);
	EXPECT_THAT(flat.get(4), 2);
	EXPECT_THAT(flat.get(7), 2);
	EXPECT_THAT(flat.get(8), 2);
	EXPECT_THAT(flat.get(9), 1);
	EXPECT_THAT(flat.get(12), 1);
	EXPECT_THAT(flat.get(13), 2);
	EXPECT_THAT(flat.get(14), 2);
	EXPECT_THAT(flat.get(19), 2);
	EXPECT_THAT(flat.get(20), 2);
	EXPECT_THAT(flat.get(21), 1);
	EXPECT_THAT(flat.get(50), 1);
	EXPECT_THAT(flat.get(255), 1);

	EXPECT_THAT(flat.group_id, 3);
}

TEST(acl_flat, two_intersection_range)
{
	acl::compiler::flat_t<uint8_t> flat;

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(3, 8);
		ranges.vector.emplace_back(5, 12);
		flat.collect(ranges);
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.insert_any();
		flat.collect(ranges);
	}

	flat.prepare();
	flat.compile();
	flat.populate();

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.vector.emplace_back(3, 8);
		ranges.vector.emplace_back(5, 12);
		EXPECT_THAT(flat.get_group_ids_by_filter(ranges), expect_group_ids(2));
	}

	{
		common::acl::ranges_t<uint8_t> ranges;
		ranges.insert_any();
		EXPECT_THAT(flat.get_group_ids_by_filter(ranges), expect_group_ids(1, 2));
	}

	EXPECT_THAT(flat.get(0), 1);
	EXPECT_THAT(flat.get(2), 1);
	EXPECT_THAT(flat.get(3), 2);
	EXPECT_THAT(flat.get(4), 2);
	EXPECT_THAT(flat.get(5), 2);
	EXPECT_THAT(flat.get(6), 2);
	EXPECT_THAT(flat.get(7), 2);
	EXPECT_THAT(flat.get(8), 2);
	EXPECT_THAT(flat.get(9), 2);
	EXPECT_THAT(flat.get(11), 2);
	EXPECT_THAT(flat.get(12), 2);
	EXPECT_THAT(flat.get(13), 1);
	EXPECT_THAT(flat.get(50), 1);
	EXPECT_THAT(flat.get(255), 1);

	EXPECT_THAT(flat.group_id, 3);
}

} // namespace
