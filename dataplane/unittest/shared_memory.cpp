#include <gtest/gtest.h>

#include "common/shared_memory.h"

TEST(SharedMemory, UsageHugeTlb)
{
	bool hugetlb_enabled = common::ipc::SharedMemory::HugeTlbEnabled();
	if (hugetlb_enabled)
	{
		YANET_LOG_DEBUG("HugeTLB Pages available\n");
	}
	else
	{
		YANET_LOG_DEBUG("HugeTLB Pages not available\n");
	}
}

TEST(SharedMemory, CreateAndOpenSharedMemoryBuffer)
{
	std::string filename("test_shared_memory.shm");
	uint64_t size = 1024;
	uint8_t* buffer_writer = static_cast<uint8_t*>(common::ipc::SharedMemory::CreateBuffer(filename, size, true, 0));
	EXPECT_TRUE(buffer_writer != nullptr);

	auto [buffer_reader, size_reader] = common::ipc::SharedMemory::OpenBuffer(filename, true);
	EXPECT_TRUE(buffer_reader != nullptr);
	EXPECT_EQ(size, size_reader);

	YANET_LOG_DEBUG("buffer writer: %p\n", buffer_writer);
	YANET_LOG_DEBUG("buffer reader: %p\n", buffer_reader);

	for (uint64_t index = 0; index < size; index++)
	{
		buffer_writer[index] = (index & 0xff);
	}

	uint8_t* buffer_reader8 = static_cast<uint8_t*>(buffer_reader);
	for (uint64_t index = 0; index < size; index++)
	{
		EXPECT_EQ(buffer_writer[index], buffer_reader8[index]);
	}

	EXPECT_EQ(munmap(buffer_writer, size), 0);
	EXPECT_EQ(munmap(buffer_reader, size), 0);
}
