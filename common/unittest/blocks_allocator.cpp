#include <gtest/gtest.h>
#include <memory>

#include "../blocks_allocator.h"

namespace
{

TEST(BlocksAllocator, SequentialAlocation)
{
	size_t blocks_number = 1024;
	uint32_t reserved = 2 * 64 + 32;

	size_t size = common::allocator::BlocksAllocator<64>::GetBufferSize(blocks_number);
	std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);
	common::allocator::BlocksAllocator<64> allocator;
	allocator.Init(buffer.get(), size, reserved);
	for (size_t i = reserved; i < blocks_number + 100; i++)
	{
		std::pair<uint64_t, uint64_t> stat(blocks_number, std::min(i, blocks_number));
		ASSERT_EQ(allocator.Stat(), stat) << "i = " << i;
		ASSERT_EQ(allocator.Allocate(), (i < blocks_number ? i : common::allocator::BlocksAllocator<64>::null_block));
	}
	for (size_t i = reserved; i < blocks_number; i++)
	{
		ASSERT_EQ(allocator[i], buffer.get() + 64 * i);
	}
}

TEST(BlocksAllocator, SizeNotAlignedBlockSize)
{
	size_t blocks_number = 1000;
	uint32_t reserved = 10;

	size_t size = common::allocator::BlocksAllocator<64>::GetBufferSize(blocks_number);
	std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);
	common::allocator::BlocksAllocator<64> allocator;
	allocator.Init(buffer.get(), size, reserved);
	for (size_t i = reserved; i < blocks_number; i++)
	{
		ASSERT_EQ(allocator.Allocate(), i);
	}
}

TEST(BlocksAllocator, AllocationWithFree)
{
	size_t blocks_number = 1024;
	uint32_t reserved = 0;

	size_t size = common::allocator::BlocksAllocator<64>::GetBufferSize(blocks_number);
	std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);
	common::allocator::BlocksAllocator<64> allocator;
	allocator.Init(buffer.get(), size, reserved);
	for (int i = 0; i < 70; i++)
	{
		ASSERT_EQ(allocator.Allocate(), i);
	}

	for (int i = 4; i < 64; i += 8)
	{
		allocator.Free(i);
	}

	for (int i = 0; i < 9; i++)
	{
		ASSERT_EQ(allocator.Allocate(), (i < 8 ? 4 + 8 * i : 62 + i));
	}
}

}
