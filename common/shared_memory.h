#pragma once

#include "define.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <numa.h>
#include <numaif.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <unistd.h>

namespace common::pde
{

class SharedMemory
{
public:
	static void* CreateBufferInSharedMemory(const char* filename, uint64_t size, bool useHugeMem, bool useMemoryBySockets, tSocketId socket_id)
	{
		// Open or creare shared memory file
		int flags_open = O_RDWR | O_CREAT;
		int mode = 0644;
		YANET_LOG_INFO("Run shm_open: %s\n", filename);
		int fd = shm_open(filename, O_RDWR | O_CREAT, 0644);
		if (fd == -1)
		{
			YANET_LOG_ERROR("shm_open(%s, %d, %o): %s\n", filename, flags_open, mode, strerror(errno));
			return nullptr;
		}

		// Truncate - set file size
		int res_trunc = ftruncate(fd, size);
		if (res_trunc < 0)
		{
			YANET_LOG_ERROR("filename=%s, ftruncate(%d, %lu): %s\n", filename, fd, size, strerror(errno));
			return nullptr;
		}

		struct bitmask* oldmask = nullptr;
		int oldpolicy;
		if (useMemoryBySockets)
		{
			// Set memory policy if necessary
			oldmask = numa_allocate_nodemask();
			if (get_mempolicy(&oldpolicy, oldmask->maskp, oldmask->size + 1, 0, 0) < 0)
			{
				YANET_LOG_WARNING("get_mempolicy(): %s\n", strerror(errno));
				oldpolicy = MPOL_DEFAULT;
			}
			numa_set_preferred(socket_id);
			if (errno != 0)
			{
				YANET_LOG_WARNING("numa_set_preferred(%d): %s\n", socket_id, strerror(errno));
			}
		}

		// Mmap memory
		int prot = PROT_READ | PROT_WRITE;
		int flags_mmap = (useHugeMem ? MAP_SHARED | MAP_HUGETLB : MAP_SHARED);
		YANET_LOG_INFO("Run mmap\n");
		void* addr = mmap(NULL, size, prot, flags_mmap, fd, 0);
		if (addr == MAP_FAILED)
		{
			// The error occurs when trying to use HugeMem when this feature is not enabled in the kernel
			YANET_LOG_ERROR("filename=%s, mmap(NULL, %lu, %d, %d, %d, 0)\n", filename, size, prot, flags_mmap, fd);
			return nullptr;
		}

		// Zero memory
		YANET_LOG_INFO("Run memset: %p [%lu]\n", addr, size);
		std::memset(addr, 0, size);
		YANET_LOG_INFO("After memset\n");

		if (useMemoryBySockets)
		{
			// Restore memory policy if necessary
			if (oldpolicy == MPOL_DEFAULT)
			{
				numa_set_localalloc();
			}
			else if (set_mempolicy(oldpolicy, oldmask->maskp, oldmask->size + 1) < 0)
			{
				YANET_LOG_WARNING("set_mempolicy(): %s\n", strerror(errno));
				numa_set_localalloc();
			}
			numa_free_cpumask(oldmask);
		}

		return addr;
	}

	static void* OpenBufferInSharedMemory(const char* filename, bool forWriting, bool useHugeMem, u_int64_t* size)
	{
		// Open shared memory file
		int flags_open = (forWriting ? O_RDWR : O_RDONLY);
		int mode = 0644;
		YANET_LOG_DEBUG("Run shm_open: %s\n", filename);
		int fd = shm_open(filename, flags_open, 0644);
		if (fd == -1)
		{
			YANET_LOG_ERROR("shm_open(%s, %d, %o): %s\n", filename, flags_open, mode, strerror(errno));
			return nullptr;
		}

		// Get the size of file
		struct stat buffer;
		int status = fstat(fd, &buffer);
		if (status != 0)
		{
			YANET_LOG_ERROR("filename=%s, fstat(%d, &buffer): %s\n", filename, fd, strerror(errno));
			return nullptr;
		}
		*size = buffer.st_size;

		// Mmap memory
		int prot = (forWriting ? PROT_READ | PROT_WRITE : PROT_READ);
		int flags_mmap = (useHugeMem ? MAP_SHARED | MAP_HUGETLB : MAP_SHARED);
		void* addr = mmap(NULL, *size, prot, flags_mmap, fd, 0);
		if (addr == MAP_FAILED)
		{
			YANET_LOG_ERROR("filename=%s, mmap(NULL, %lu, %d, %d, %d, 0)\n", filename, *size, prot, flags_mmap, fd);
			return nullptr;
		}

		return addr;
	}
};

} // namespace common::pde
