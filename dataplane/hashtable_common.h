#pragma once

#include <cstdint>
#include <memory.h>

#include <cstdint>
#include <rte_byteorder.h>

#include "rte_crc_x86.h"

#include "common.h"

#include "ext/city.h"
#include "ext/murmurhash3.h"
#include "ext/xxhash32.h"

namespace dataplane
{

template<typename key_t>
using hash_function_t = uint32_t(const key_t&);

template<typename key_t>
inline uint32_t calculate_hash_crc(const key_t& key)
{
	uint32_t result = 0;

	unsigned int offset = 0;

	for (unsigned int i = 0;
	     i < sizeof(key_t) / 8;
	     i++)
	{
		result = rte_hash_crc_8byte(*(((const uint64_t*)&key) + offset / 8), result);
		offset += 8;
	}

	if (sizeof(key_t) & 0x4)
	{
		result = rte_hash_crc_4byte(*(((const uint32_t*)&key) + offset / 4), result);
		offset += 4;
	}

	if (sizeof(key_t) & 0x2)
	{
		result = rte_hash_crc_2byte(*(((const uint16_t*)&key) + offset / 2), result);
		offset += 2;
	}

	if (sizeof(key_t) & 0x1)
	{
		result = rte_hash_crc_1byte(*(((const uint8_t*)&key) + offset), result);
	}

	return result;
}

template<typename key_t>
inline uint32_t calculate_hash_murmur3(const key_t& key)
{
	uint32_t result = 0;
	MurmurHash3_x86_32(&key, sizeof(key), 19, &result);
	return result;
}

template<typename key_t>
inline uint32_t calculate_hash_xxh32(const key_t& key)
{
	return XXHash32::hash(&key, sizeof(key), 19);
}

template<typename key_t>
inline uint32_t calculate_hash_city(const key_t& key)
{
	return CityHash32((char*)&key, sizeof(key));
}

class spinlock_t final
{
public:
	spinlock_t()
	{
		rte_spinlock_recursive_init(&locker);
	}

public:
	void lock()
	{
		YADECAP_MEMORY_BARRIER_COMPILE;
		rte_spinlock_recursive_lock(&locker);
		YADECAP_MEMORY_BARRIER_COMPILE;
	}

	void unlock()
	{
		YADECAP_MEMORY_BARRIER_COMPILE;
		rte_spinlock_recursive_unlock(&locker);
		YADECAP_MEMORY_BARRIER_COMPILE;
	}

	/// @todo: guard

protected:
	rte_spinlock_recursive_t locker;
};

class spinlock_nonrecursive_t final
{
public:
	spinlock_nonrecursive_t()
	{
		rte_spinlock_init(&locker);
	}

public:
	void lock()
	{
		rte_spinlock_lock(&locker);
	}

	void unlock()
	{
		rte_spinlock_unlock(&locker);
	}

	/// @todo: guard

protected:
	rte_spinlock_t locker;
};

struct hashtable_gc_t
{
	uint32_t offset{};
	uint64_t valid_keys{};
	uint64_t iterations{};
};

}
