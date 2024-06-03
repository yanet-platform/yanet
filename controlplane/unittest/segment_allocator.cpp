#include <gtest/gtest.h>

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
	AllocatorBig* allocator = new (data) AllocatorBig();

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

int main(int argc, char** argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
