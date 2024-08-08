#pragma once

#include <fcntl.h>
#include <numa.h>
#include <numaif.h>
#include <optional>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "define.h"
#include "type.h"

namespace common::ipc
{

class SharedMemory
{
public:
	/*
	 * Check if HugeTLB Pages usage is available
	 * Searches for a string of the type "Hugetlb: zzz kB" in the /proc/meminfo and returns true
	 * if the parameter value is not 0
	 * Some details in the Linux kernel source file Documentation/admin-guide/mm/hugetlbpage.rst
	 */
	static bool HugeTlbEnabled()
	{
		const char* path_meminfo = "/proc/meminfo";
		const char* str_hugetlb = "Hugetlb:";

		FILE* fd = fopen(path_meminfo, "r");
		if (fd == NULL)
		{
			YANET_LOG_ERROR("Cannot open %s, error %d: %s\n", path_meminfo, errno, strerror(errno));
			return false;
		}

		bool hugetlb_enabled = false;
		bool line_found = false;
		unsigned hugetlb_len = sizeof(str_hugetlb);
		char buffer[256];
		while (fgets(buffer, sizeof(buffer), fd))
		{
			if (strncmp(buffer, str_hugetlb, hugetlb_len) == 0)
			{
				char* str = &buffer[hugetlb_len];
				while (isspace((int)*str))
				{
					str++;
				}
				char* endptr;
				unsigned long long size = strtoull(str, &endptr, 0);
				// The string still contains kB (or mB, gB), but it only matters to us
				// whether the value is 0 or not
				if (errno != 0)
				{
					YANET_LOG_ERROR("Error parsing size of %s in file %s\n", str_hugetlb, path_meminfo);
					return false;
				}
				hugetlb_enabled = (size != 0);
				line_found = true;
				break;
			}
		}
		fclose(fd);

		if (!line_found)
		{
			YANET_LOG_WARNING("Not found string '%s' in file: %s\n", str_hugetlb, path_meminfo);
		}

		return hugetlb_enabled;
	}

	/*
	 * Creating a buffer in shared memory
	 * Params:
	 * - filename - the name of the file without a path, the file is created in /dev/shm
	 * - size - buffer size
	 * - use_huge_tlb - if true, it will use MAP_HUGETLB
	 * - socket_id - id of the numa node on which one want to allocate a buffer,
	 *               if std::nullptr - it will be selected automatically by the system
	 * Return value:
	 * void* - address of the allocated buffer, nullptr if an error occurred
	 */
	static void* CreateBuffer(std::string filename, uint64_t size, bool use_huge_tlb, std::optional<tSocketId> socket_id)
	{
		// Open or creare shared memory file
		int flags_open = O_RDWR | O_CREAT;
		int mode = 0644;
		int fd = shm_open(filename.c_str(), flags_open, mode);
		if (fd == -1)
		{
			YANET_LOG_ERROR("shm_open(%s, %d, %o): %s\n", filename.c_str(), flags_open, mode, strerror(errno));
			return nullptr;
		}

		// Truncate - set file size
		int res_trunc = ftruncate(fd, size);
		if (res_trunc < 0)
		{
			YANET_LOG_ERROR("filename=%s, ftruncate(%d, %lu): %s\n", filename.c_str(), fd, size, strerror(errno));
			close(fd);
			return nullptr;
		}

		// Set memory policy if necessary
		struct bitmask* oldmask = nullptr;
		int oldpolicy;
		if (socket_id.has_value())
		{
			oldmask = numa_allocate_nodemask();
			if (get_mempolicy(&oldpolicy, oldmask->maskp, oldmask->size + 1, 0, 0) < 0)
			{
				YANET_LOG_WARNING("get_mempolicy(): %s, continue with the use of sockets turned off\n", strerror(errno));
				oldpolicy = MPOL_DEFAULT;
				socket_id = std::nullopt;
			}
			else
			{
				numa_set_preferred(*socket_id);
				if (errno != 0)
				{
					YANET_LOG_ERROR("numa_set_preferred(%d): %s\n", *socket_id, strerror(errno));
				}
			}
		}

		// Mmap memory
		int prot = PROT_READ | PROT_WRITE;
		int flags_mmap = MAP_SHARED;
		if (use_huge_tlb)
		{
			if (!HugeTlbEnabled())
			{
				YANET_LOG_ERROR("Attempt to use HugeTlb, but it is not enabled\n");
			}
			else
			{
				flags_mmap |= MAP_HUGETLB;
			}
		}
		void* addr = mmap(NULL, size, prot, flags_mmap, fd, 0);
		if (addr == MAP_FAILED)
		{
			// The error occurs when trying to use HugeTlb when this feature is not enabled in the kernel
			YANET_LOG_ERROR("filename=%s, mmap(NULL, %lu, %d, %d, %d, 0)\n", filename.c_str(), size, prot, flags_mmap, fd);
			return nullptr;
		}

		// Zero memory
		memset(addr, 0, size);

		// Restore memory policy if necessary
		if (socket_id.has_value())
		{
			if (oldpolicy == MPOL_DEFAULT)
			{
				numa_set_localalloc();
			}
			else if (set_mempolicy(oldpolicy, oldmask->maskp, oldmask->size + 1) < 0)
			{
				YANET_LOG_ERROR("set_mempolicy(): %s\n", strerror(errno));
				numa_set_localalloc();
			}
			numa_free_cpumask(oldmask);
		}

		// Close file
		if (close(fd) != 0)
		{
			YANET_LOG_ERROR("filename=%s, error fclose %d: %s\n", filename.c_str(), errno, strerror(errno));
		}

		return addr;
	}

	/*
	 * Open an existing buffer in shared memory
	 * Params:
	 * - filename - the name of the file without a path, the file is created in /dev/shm
	 * - use_huge_tlb - if true, it will use MAP_HUGETLB
	 * Return values:
	 * - void* - address of the allocated buffer, nullptr if an error occurred
	 * - size - buffer size
	 */
	static std::pair<void*, uint64_t> OpenBuffer(std::string filename, bool use_huge_tlb)
	{
		// Open shared memory file
		int flags_open = O_RDONLY;
		int mode = 0644;
		int fd = shm_open(filename.c_str(), flags_open, mode);
		if (fd == -1)
		{
			YANET_LOG_ERROR("shm_open(%s, %d, %o): %s\n", filename.c_str(), flags_open, mode, strerror(errno));
			return {nullptr, 0};
		}

		// Get the size of file
		struct stat buffer;
		int status = fstat(fd, &buffer);
		if (status != 0)
		{
			YANET_LOG_ERROR("filename=%s, fstat(%d, &buffer): %s\n", filename.c_str(), fd, strerror(errno));
			close(fd);
			return {nullptr, 0};
		}
		uint64_t size = buffer.st_size;

		// Mmap memory
		int prot = PROT_READ;
		int flags_mmap = MAP_SHARED;
		if (use_huge_tlb)
		{
			if (!HugeTlbEnabled())
			{
				YANET_LOG_ERROR("Attempt to use HugeTlb, but it is not enabled\n");
			}
			else
			{
				flags_mmap |= MAP_HUGETLB;
			}
		}
		void* addr = mmap(NULL, size, prot, flags_mmap, fd, 0);
		if (addr == MAP_FAILED)
		{
			YANET_LOG_ERROR("filename=%s, mmap(NULL, %lu, %d, %d, %d, 0)\n", filename.c_str(), size, prot, flags_mmap, fd);
			close(fd);
			return {nullptr, 0};
		}

		// Cloase file
		if (close(fd) != 0)
		{
			YANET_LOG_ERROR("filename=%s, error fclose %d: %s\n", filename.c_str(), errno, strerror(errno));
		}

		return {addr, size};
	}
};

} // namespace common::ipc
