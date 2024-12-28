#include <gtest/gtest.h>

#include "../shared_memory.h"

void TestForSize(void* buffer_writer, void* buffer_reader, size_t size, size_t size_reader)
{
	ASSERT_TRUE(buffer_writer != nullptr);
	ASSERT_TRUE(buffer_reader != nullptr);
	ASSERT_EQ(size, size_reader);

	auto* buffer_writer8 = reinterpret_cast<uint8_t*>(buffer_writer);
	auto* buffer_reader8 = reinterpret_cast<uint8_t*>(buffer_reader);

	for (uint64_t index = 0; index < size; index++)
	{
		buffer_writer8[index] = (index & 0xff);
	}

	for (uint64_t index = 0; index < size; index++)
	{
		ASSERT_EQ(buffer_writer8[index], buffer_reader8[index]);
	}
}

static std::vector<size_t> sizes_test = {1024, 512, 4096, 8192, 4096, 1024};

TEST(SharedMemory, CreateAndOpenSharedMemoryBufferFile)
{
	bool use_huge_tlb = common::ipc::SharedMemory::HugeTlbEnabled();
	std::string filename("test_shared_memory.shm");
	for (size_t size : sizes_test)
	{
		void* buffer_writer = common::ipc::SharedMemory::CreateBufferFile(filename, size, use_huge_tlb, 0);
		auto [buffer_reader, size_reader] = common::ipc::SharedMemory::OpenBufferFile(filename, use_huge_tlb);
		TestForSize(buffer_writer, buffer_reader, size, size_reader);
		ASSERT_EQ(munmap(buffer_writer, size), 0);
		ASSERT_EQ(munmap(buffer_reader, size), 0);
	}
}

TEST(SharedMemory, CreateAndOpenSharedMemoryBufferKey)
{
	bool use_huge_tlb = common::ipc::SharedMemory::HugeTlbEnabled();
	key_t key = 54321;
	for (size_t size : sizes_test)
	{
		void* buffer_writer = common::ipc::SharedMemory::CreateBufferKey(key, size, use_huge_tlb, 0);
		auto [buffer_reader, size_reader] = common::ipc::SharedMemory::OpenBufferKey(key, use_huge_tlb);
		TestForSize(buffer_writer, buffer_reader, size, size_reader);
		ASSERT_EQ(shmdt(buffer_writer), 0);
		ASSERT_EQ(shmdt(buffer_reader), 0);
	}
}
