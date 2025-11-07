#include <gtest/gtest.h>
#include <vector>

#include "common/type.h"
#include "controlplane/segment_allocator.h"

static constexpr uint32_t error_result = 0;
using Allocator = SegmentAllocator<15, 6 * 64, 2 * 64, 64, error_result>;
using Errors = std::pair<uint64_t, uint64_t>;
using BlockStat = std::tuple<uint32_t, uint32_t, uint32_t>;

BlockStat Block(const Allocator& allocator, uint16_t size)
{
	const auto& info = allocator.GetBlocksStat()[size];
	return {info.busy_blocks, info.used_blocks, info.used_segments};
}

TEST(SegmentAllocator, Simple)
{

	Errors no_errors(0, 0);

	Allocator allocator;

	// Interval [15, 384), BlockSize = 128.
	// 3 intervals [15, 143), [143, 271), [271, 384) - length of the last block = 113 < 128.
	// Blocks 0,2 - the blocks will be used for segments of length 23, block 1 - 27.
	// Capacity of blocks: 0 => [128/23] = 5, 1 => [128/27] = 4, 2 => [113/23] = 4.

	// --------------------------------------------------------------------------------------------
	// STEP 1: - Allocate segments, we will get results:
	// len=23: Block 0 (15, 38, 61, 84, 107), Block 2 (271, 294, 317, 340)
	// len=27: Block 1 (143, 170, 197, 224)

	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 3, 0));

	EXPECT_EQ(allocator.Allocate(23), 15);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 2, 0)); // Block 0 for 23
	EXPECT_EQ(Block(allocator, 23), BlockStat(0, 1, 1));

	EXPECT_EQ(allocator.Allocate(27), 143); // Block 1 for 27
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 1, 0));
	EXPECT_EQ(Block(allocator, 27), BlockStat(0, 1, 1));

	EXPECT_EQ(allocator.Allocate(23), 38);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 1, 0));
	EXPECT_EQ(Block(allocator, 23), BlockStat(0, 1, 2));

	EXPECT_EQ(allocator.Allocate(23), 61);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 1, 0));
	EXPECT_EQ(Block(allocator, 23), BlockStat(0, 1, 3));

	EXPECT_EQ(allocator.Allocate(23), 84);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 1, 0));
	EXPECT_EQ(Block(allocator, 23), BlockStat(0, 1, 4));

	EXPECT_EQ(allocator.Allocate(23), 107);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 1, 0));
	EXPECT_EQ(Block(allocator, 23), BlockStat(1, 0, 5)); // Block 0 - busy

	EXPECT_EQ(allocator.Allocate(27), 170);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 1, 0));
	EXPECT_EQ(Block(allocator, 27), BlockStat(0, 1, 2));

	EXPECT_EQ(allocator.Allocate(27), 197);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 1, 0));
	EXPECT_EQ(Block(allocator, 27), BlockStat(0, 1, 3));

	EXPECT_EQ(allocator.Allocate(23), 271); // Block 2 for 23
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 0, 0));
	EXPECT_EQ(Block(allocator, 23), BlockStat(1, 1, 6));

	EXPECT_EQ(allocator.Allocate(23), 294);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 23), BlockStat(1, 1, 7));

	EXPECT_EQ(allocator.Allocate(27), 224);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 27), BlockStat(1, 0, 4)); // Block 1 - busy

	EXPECT_EQ(allocator.Allocate(23), 317);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 23), BlockStat(1, 1, 8));

	EXPECT_EQ(allocator.Allocate(27), 0);
	EXPECT_EQ(allocator.GetErrors(), no_errors);

	EXPECT_EQ(allocator.Allocate(23), 340);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 23), BlockStat(2, 0, 9)); // Block 2 - busy

	EXPECT_EQ(allocator.Allocate(23), 0);
	EXPECT_EQ(allocator.GetErrors(), no_errors);

	// Finish allocate:
	// - no free blocks
	// - len=23 (2 - busy blocks, 9 - segments)
	// - len=27 (1 - busy block, 4 - segments)
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 0, 0));
	EXPECT_EQ(Block(allocator, 23), BlockStat(2, 0, 9));
	EXPECT_EQ(Block(allocator, 27), BlockStat(1, 0, 4));

	// --------------------------------------------------------------------------------------------
	// STEP 2: - Release the length 23 segments (271, 294, 317, 340) from block 2 and then place
	// the length 27 segments in it

	EXPECT_TRUE(allocator.Free(271, 23));
	EXPECT_EQ(Block(allocator, 23), BlockStat(1, 1, 8)); // Block 2 - in list 23
	EXPECT_TRUE(allocator.Free(294, 23));
	EXPECT_TRUE(allocator.Free(317, 23));
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 23), BlockStat(1, 1, 6));

	// release last segment of the length 23
	EXPECT_TRUE(allocator.Free(340, 23));
	EXPECT_EQ(Block(allocator, 23), BlockStat(1, 0, 5));
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 1, 0)); // Block 2 - free

	// start allocate segments len=27
	EXPECT_EQ(allocator.Allocate(27), 271);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 27), BlockStat(1, 1, 5)); // Block 2 for 27
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 0, 0));

	// Allocate other segments
	EXPECT_EQ(allocator.Allocate(27), 298);
	EXPECT_EQ(allocator.Allocate(27), 325);
	EXPECT_EQ(allocator.Allocate(27), 352);
	EXPECT_EQ(allocator.Allocate(27), 0);
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 27), BlockStat(2, 0, 8));

	// --------------------------------------------------------------------------------------------
	// STEP 3: - Release all segments

	// Block 2
	EXPECT_TRUE(allocator.Free(298, 27));
	EXPECT_TRUE(allocator.Free(352, 27));
	EXPECT_TRUE(allocator.Free(325, 27));
	EXPECT_TRUE(allocator.Free(271, 27));
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 27), BlockStat(1, 0, 4));
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 1, 0));

	// Block 0
	EXPECT_TRUE(allocator.Free(15, 23));
	EXPECT_TRUE(allocator.Free(38, 23));
	EXPECT_TRUE(allocator.Free(61, 23));
	EXPECT_TRUE(allocator.Free(84, 23));
	EXPECT_TRUE(allocator.Free(107, 23));
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 23), BlockStat(0, 0, 0));
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 2, 0));

	// Block 1
	EXPECT_TRUE(allocator.Free(143, 27));
	EXPECT_TRUE(allocator.Free(170, 27));
	EXPECT_TRUE(allocator.Free(197, 27));
	EXPECT_TRUE(allocator.Free(224, 27));
	EXPECT_EQ(allocator.GetErrors(), no_errors);
	EXPECT_EQ(Block(allocator, 27), BlockStat(0, 0, 0));
	EXPECT_EQ(Block(allocator, 0), BlockStat(0, 3, 0));
	EXPECT_EQ(allocator.GetErrors(), no_errors);
}

TEST(SegmentAllocator, BigSize)
{
	static constexpr uint32_t index_begin = 128;
	static constexpr uint32_t index_end = 8 * 1024 * 1024;
	using AllocatorBig = SegmentAllocator<index_begin, index_end, 64 * 64, 64, error_result>;

	uint8_t data[sizeof(AllocatorBig)];
	memset((void*)data, -1, sizeof(AllocatorBig));
	auto* allocator = new (data) AllocatorBig();

	uint16_t size = 4;
	uint32_t full_size = index_end - index_begin;
	for (uint32_t index = index_begin; index < index_end; index += size)
	{
		EXPECT_EQ(allocator->Allocate(size), index);
		full_size -= size;
		EXPECT_EQ(allocator->Size(), full_size);
	}

	for (uint32_t index = index_begin; index < index_end; index += size)
	{
		EXPECT_TRUE(allocator->Free(index, size));
		full_size += size;
		EXPECT_EQ(allocator->Size(), full_size);
	}

	Errors no_errors(0, 0);
	EXPECT_EQ(allocator->GetErrors(), no_errors);
}

TEST(SegmentAllocator, OnlyErrors)
{
	Allocator allocator;

	EXPECT_EQ(allocator.Allocate(23), 15);

	EXPECT_EQ(allocator.Allocate(0), 0); // size = 0
	EXPECT_EQ(allocator.Allocate(65), 0); // size > 64
	EXPECT_EQ(allocator.GetErrors(), Errors(2, 0));

	// 4 errors for this case:
	//  ((size == 0) || (size > MaxBufferSize) || (start >= IndexEnd) || (start < IndexBegin))
	EXPECT_FALSE(allocator.Free(50, 0));
	EXPECT_FALSE(allocator.Free(50, 65));
	EXPECT_FALSE(allocator.Free(0, 10));
	EXPECT_FALSE(allocator.Free(500, 0));
	EXPECT_EQ(allocator.GetErrors(), Errors(6, 0));

	EXPECT_FALSE(allocator.Free(15, 27)); // segment size 27 != 23
	EXPECT_FALSE(allocator.Free(16, 23)); // segments starts at (15, 15+23, ...)
	EXPECT_FALSE(allocator.Free(38, 23)); // segment free
	EXPECT_EQ(allocator.GetErrors(), Errors(9, 0));
}

bool TestBlockSegmentAllocator(uint16_t segment_size, uint16_t groups, uint16_t count_group)
{
	static constexpr uint32_t counter_index_begin = (((uint32_t)common::globalBase::static_counter_type::size + 63) / 64) * 64;
	static constexpr uint32_t max_buffer_size = 64;
	using SegmentAllocatorType = SegmentAllocator<counter_index_begin, YANET_CONFIG_COUNTERS_SIZE, 64 * 64, max_buffer_size, 0>;
	SegmentAllocatorType::OneBlock block;

	block.Initialize(0, 0);
	block.SetSize(segment_size);
	int free_segments = block.free_segments;

	for (uint32_t retries = 0; retries < groups; retries++)
	{
		std::vector<uint16_t> data;
		// Try allocate "count_group" segments
		for (uint16_t index = 0; index < count_group && free_segments > 0; index++)
		{
			uint16_t value = block.Allocate();
			if (value == SegmentAllocatorType::error_in_block_)
			{
				std::cerr << "Error allocate segment in block\n";
				return false;
			}
			free_segments--;
			data.push_back(value);

			if (!block.CheckInvariants())
			{
				return false;
			}
		}

		for (uint16_t index = 0; index < data.size(); index += 2)
		{
			if (block.Free(data[index]) == SegmentAllocatorType::error_in_block_)
			{
				std::cout << "Error free segment in block\n";
				return false;
			}
			free_segments++;

			if (!block.CheckInvariants())
			{
				return false;
			}
		}
	}

	return true;
}

TEST(SegmentAllocator, Block)
{
	EXPECT_TRUE(TestBlockSegmentAllocator(2, 10, 1000));
	EXPECT_TRUE(TestBlockSegmentAllocator(4, 10, 500));
	EXPECT_TRUE(TestBlockSegmentAllocator(6, 10, 500));
	EXPECT_TRUE(TestBlockSegmentAllocator(37, 10, 100));
}

struct TestOneSizeInfo
{
	uint32_t size;
	uint32_t accumulated_weight;
	uint32_t elements_in_block;
	uint32_t used_blocks = 0;
	std::vector<uint32_t> segments;
	std::set<uint32_t> segments_map;
};

bool TestSegmentAllocatorDifferentSizes(std::vector<std::pair<uint32_t, uint32_t>> test_data)
{
	static constexpr uint32_t counter_index_begin = (((uint32_t)common::globalBase::static_counter_type::size + 63) / 64) * 64;
	static constexpr uint32_t max_buffer_size = 64;
	static constexpr uint32_t block_size = 64 * 64;
	static constexpr uint32_t counters_size = YANET_CONFIG_COUNTERS_SIZE / 8;
	static constexpr uint32_t total_full_blocks = (counters_size - counter_index_begin) / block_size;
	SegmentAllocator<counter_index_begin, counters_size, block_size, max_buffer_size, 0> allocator;

	uint32_t sizes = test_data.size();
	uint32_t total_weight = 0;
	std::vector<TestOneSizeInfo> tests_info(sizes);
	for (uint32_t index = 0; index < sizes; index++)
	{
		total_weight += test_data[index].second;
		TestOneSizeInfo& test_info = tests_info[index];
		test_info.size = test_data[index].first;
		test_info.accumulated_weight = total_weight;
		test_info.elements_in_block = block_size / test_info.size;
	}

	std::srand(17);
	uint32_t used_blocks = 0;
	while (used_blocks + sizes <= total_full_blocks)
	{
		// Select size
		uint32_t weight = std::rand() % total_weight;
		uint32_t cur_index = 0;
		for (uint32_t index = 1; index < sizes; index++)
		{
			if (weight >= tests_info[index - 1].accumulated_weight)
			{
				cur_index = index;
			}
		}

		// Select action
		TestOneSizeInfo& test_info = tests_info[cur_index];
		static constexpr int32_t probability_free = 30;
		bool action_free = ((std::rand() % 100) < probability_free);
		if (action_free)
		{
			// Free
			uint32_t current_size = test_info.segments.size();
			if (current_size != 0)
			{
				uint32_t index = std::rand() % current_size;
				uint32_t value = test_info.segments[index];
				test_info.segments_map.erase(value);
				test_info.segments[index] = test_info.segments.back();
				test_info.segments.pop_back();

				if (allocator.Free(value, test_info.size) == 0)
				{
					std::cout << "Error free segment in allocator\n";
					return false;
				}
			}
		}
		else
		{
			// Allocate
			uint32_t value = allocator.Allocate(test_info.size);
			if (value == 0)
			{
				std::cout << "can't allocate\n";
				return false;
			}
			else if (test_info.segments_map.find(value) != test_info.segments_map.end())
			{
				std::cout << "Allocated segment exists\n";
				return false;
			}
			test_info.segments_map.insert(value);
			test_info.segments.push_back(value);
			if (test_info.segments.size() % test_info.elements_in_block == 1)
			{
				used_blocks = 0;
				for (const TestOneSizeInfo& info : tests_info)
				{
					used_blocks += (info.segments.size() + info.elements_in_block - 1) / info.elements_in_block;
				}
			}
		}
	}

	EXPECT_EQ(allocator.GetErrors(), Errors(0, 0));

	uint32_t used_counters = 0;
	for (const TestOneSizeInfo& info : tests_info)
	{
		used_counters += info.size * info.segments.size();
	}
	uint32_t total_counters = counters_size - counter_index_begin;
	EXPECT_GE(used_counters, 0.95 * total_counters);

	return true;
}

TEST(SegmentAllocator, DifferentSizes)
{
	EXPECT_TRUE(TestSegmentAllocatorDifferentSizes({{2, 10}, {4, 5}, {6, 1}}));
	EXPECT_TRUE(TestSegmentAllocatorDifferentSizes({{8, 1}, {17, 1}, {37, 1}}));
}

TEST(SegmentAllocator, AddAndHalfDelete)
{
	static constexpr uint32_t counter_index_begin = (((uint32_t)common::globalBase::static_counter_type::size + 63) / 64) * 64;
	static constexpr uint32_t max_buffer_size = 64;
	SegmentAllocator<counter_index_begin, YANET_CONFIG_COUNTERS_SIZE, 64 * 64, max_buffer_size, 0> allocator;

	uint16_t size = 2;
	uint32_t count = 100000;
	bool errors = false;
	for (uint32_t retries = 0; retries < 10 && !errors; retries++)
	{
		std::vector<uint32_t> data;

		for (uint32_t index = 0; index < count && !errors; index++)
		{
			uint32_t value = allocator.Allocate(size);
			EXPECT_NE(value, 0);
			if (value == 0)
			{
				errors = true;
				break;
			}
			data.push_back(value);
		}

		for (uint32_t index = 0; index < count && !errors; index += 2)
		{
			EXPECT_TRUE(allocator.Free(data[index], size));
		}

		EXPECT_EQ(allocator.GetErrors(), Errors(0, 0));
	}
	EXPECT_EQ(allocator.GetErrors(), Errors(0, 0));
}

int main(int argc, char** argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
