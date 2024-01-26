#pragma once

#include <memory.h>
#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_hash_crc.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>

#include "common/generation.h"
#include "common/result.h"
#include "common/type.h"

#include "common.h"

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
	uint32_t result;
	MurmurHash3_x86_32(&key, sizeof(key), 19, &result);
	return result;
}

template<typename key_t>
inline uint32_t calculate_hash_xxh32(const key_t& key)
{
	return XXHash32::hash(&key, sizeof(key), 19);
}

class spinlock_t final
{
public:
	spinlock_t()
	{
		rte_spinlock_recursive_init(&locker);
	}

public:
	inline void lock()
	{
		YADECAP_MEMORY_BARRIER_COMPILE;
		rte_spinlock_recursive_lock(&locker);
		YADECAP_MEMORY_BARRIER_COMPILE;
	}

	inline void unlock()
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
	inline void lock()
	{
		rte_spinlock_lock(&locker);
	}

	inline void unlock()
	{
		rte_spinlock_unlock(&locker);
	}

	/// @todo: guard

protected:
	rte_spinlock_t locker;
};

struct hashtable_gc_t
{
	hashtable_gc_t() :
	        offset(0),
	        valid_keys(0),
	        iterations(0)
	{
	}

	uint32_t offset;
	uint64_t valid_keys;
	uint64_t iterations;
};

template<typename TKey,
         typename TValue,
         uint32_t size_T,
         uint32_t extendedSize_T,
         unsigned int pairsPerChunk_T = 2,
         unsigned int pairsPerExtendedChunk_T = 4>
class hashtable_chain_t
{
public:
	hashtable_chain_t()
	{
		for (uint32_t id = 0; id < extendedSize_T - 1; ++id)
		{
			auto& extendedChunk = extendedChunks[id];
			extendedChunk.setNextExtendedChunkId(id + 1);
		}
		auto& extendedChunk = extendedChunks[extendedSize_T - 1];
		extendedChunk.setNextExtendedChunkId(extendedChunkIdUnknown);

		freeExtendedChunkId = 0;
	}

	constexpr static uint64_t keysSize = size_T * pairsPerChunk_T + extendedSize_T * pairsPerExtendedChunk_T;

public:
	inline void lookup(const TKey* keys,
	                   TValue** values,
	                   const unsigned int& count)
	{
		for (unsigned int key_i = 0;
		     key_i < count;
		     key_i++)
		{
			const TKey& key = keys[key_i];
			TValue*& value = values[key_i];
			const uint32_t hash = rte_hash_crc(&key, sizeof(TKey), 0);
			auto& chunk = chunks[hash & (size_T - 1)];

			value = nullptr;

			for (unsigned int chunk_key_i = 0; ///< @todo: iterator
			     chunk_key_i < pairsPerChunk_T;
			     chunk_key_i++)
			{
				if (chunk.isValid(chunk_key_i) &&
				    compareKeys(chunk.getKey(chunk_key_i), key))
				{
					/// found in chunk

					value = &chunk.getValue(chunk_key_i);

					break;
				}
			}

			if (value == nullptr)
			{
				uint32_t nextExtendedChunkId = chunk.getNextExtendedChunkId();
				while (nextExtendedChunkId != extendedChunkIdUnknown)
				{
					auto& extendedChunk = extendedChunks[nextExtendedChunkId];

					for (unsigned int extended_chunk_key_i = 0; ///< @todo: iterator
					     extended_chunk_key_i < pairsPerExtendedChunk_T;
					     extended_chunk_key_i++)
					{
						if (extendedChunk.isValid(extended_chunk_key_i) &&
						    compareKeys(extendedChunk.getKey(extended_chunk_key_i), key))
						{
							/// found in extended chunk

							value = &extendedChunk.getValue(extended_chunk_key_i);

							break;
						}
					}

					if (value != nullptr)
					{
						break;
					}

					nextExtendedChunkId = extendedChunk.getNextExtendedChunkId();
				}
			}
		}
	}

	inline bool lookup(const TKey& key,
	                   TValue*& value) const
	{
		lookup(&key, &value, 1);
		return (value != nullptr);
	}

	/// not atomic
	bool insert(const TKey& key,
	            const TValue& value)
	{
		YADECAP_MEMORY_BARRIER_COMPILE; ///< no time to explain. just put a memory barrier here

		const uint32_t hash = rte_hash_crc(&key, sizeof(TKey), 0);
		auto& chunk = chunks[hash & (size_T - 1)];

		unsigned int keyOfFree = pairsPerChunk_T;
		/// find key
		{
			for (unsigned int chunk_key_i = 0;
			     chunk_key_i < pairsPerChunk_T;
			     chunk_key_i++)
			{
				if (chunk.isValid(chunk_key_i))
				{
					if (compareKeys(chunk.getKey(chunk_key_i), key))
					{
						/// already exist in chunk

						chunk.getValue(chunk_key_i) = value;

						return true;
					}
				}
				else
				{
					keyOfFree = std::min(chunk_key_i, keyOfFree);
				}
			}

			uint32_t nextExtendedChunkId = chunk.getNextExtendedChunkId();
			while (nextExtendedChunkId != extendedChunkIdUnknown)
			{
				auto& extendedChunk = extendedChunks[nextExtendedChunkId];

				for (unsigned int extended_chunk_key_i = 0; ///< @todo: iterator
				     extended_chunk_key_i < pairsPerExtendedChunk_T;
				     extended_chunk_key_i++)
				{
					if (extendedChunk.isValid(extended_chunk_key_i) &&
					    compareKeys(extendedChunk.getKey(extended_chunk_key_i), key))
					{
						/// already exist in extended chunk

						extendedChunk.getValue(extended_chunk_key_i) = value;

						return true;
					}
				}

				nextExtendedChunkId = extendedChunk.getNextExtendedChunkId();
			}
		}

		/// key not found, insert
		{
			if (keyOfFree != pairsPerChunk_T)
			{
				/// insert in chunk

				chunk.getKey(keyOfFree) = key;
				chunk.getValue(keyOfFree) = value;

				YADECAP_MEMORY_BARRIER_COMPILE;

				chunk.setValid(keyOfFree);

				stats.pairs++;
				stats.longestChain = RTE_MAX(stats.longestChain, keyOfFree);
				return true;
			}

			uint64_t longestChain = pairsPerChunk_T;
			if (chunk.getNextExtendedChunkId() == extendedChunkIdUnknown)
			{
				/// create next extended chunk
				chunk.setNextExtendedChunkId(newExtendedChunk());
			}

			uint32_t nextExtendedChunkId = chunk.getNextExtendedChunkId();
			while (nextExtendedChunkId != extendedChunkIdUnknown) ///< @todo: longestChain < TVariable
			{
				auto& extendedChunk = extendedChunks[nextExtendedChunkId];

				for (unsigned int extended_chunk_key_i = 0; ///< @todo: iterator
				     extended_chunk_key_i < pairsPerExtendedChunk_T;
				     extended_chunk_key_i++)
				{
					longestChain++;

					if (!extendedChunk.isValid(extended_chunk_key_i))
					{
						/// insert in extended chunk

						extendedChunk.getKey(extended_chunk_key_i) = key;
						extendedChunk.getValue(extended_chunk_key_i) = value;

						YADECAP_MEMORY_BARRIER_COMPILE;

						extendedChunk.setValid(extended_chunk_key_i);

						stats.pairs++;
						stats.longestChain = RTE_MAX(stats.longestChain, longestChain);
						return true;
					}
				}

				if (extendedChunk.getNextExtendedChunkId() == extendedChunkIdUnknown)
				{
					/// create next extended chunk
					extendedChunk.setNextExtendedChunkId(newExtendedChunk());
				}

				nextExtendedChunkId = extendedChunk.getNextExtendedChunkId();
			}
		}

		/// hash table is full
		stats.insertFailed++;

		return false;
	}

	/// not atomic
	bool remove()
	{
		/// @todo
		return true;
	}

	void clear()
	{
		for (unsigned int chunk_i = 0;
		     chunk_i < size_T;
		     chunk_i++)
		{
			auto& chunk = chunks[chunk_i];
			chunk.clear();
		}

		for (uint32_t id = 0; id < extendedSize_T - 1; ++id)
		{
			auto& extendedChunk = extendedChunks[id];
			extendedChunk.setNextExtendedChunkId(id + 1);
		}
		auto& extendedChunk = extendedChunks[extendedSize_T - 1];
		extendedChunk.setNextExtendedChunkId(extendedChunkIdUnknown);
		freeExtendedChunkId = 0;

		memset(&stats, 0, sizeof(stats));
	}

	const auto& getStats() const
	{
		return stats;
	}

protected:
	constexpr static uint8_t flagExtendedChunkOccupied = 1 << 7;
	constexpr static uint32_t extendedChunkIdUnknown = 0x00FFFFFF;

	struct pair_t
	{
		TKey key;
		TValue value;
	};

	class chunk_t
	{
	public:
		chunk_t()
		{
			atomic = 0;
			nextExtendedChunkId = extendedChunkIdUnknown;
		}

	public:
		inline uint32_t getNextExtendedChunkId() const
		{
			return nextExtendedChunkId & 0x00FFFFFFu;
		}

		void setNextExtendedChunkId(const uint32_t& extendedChunkId)
		{
			nextExtendedChunkId = (nextExtendedChunkId & 0xFF000000u) | (extendedChunkId & 0x00FFFFFFu);
		}

		inline bool isValid(const unsigned int& key_i) const
		{
			return keyValids & (1 << key_i);
		}

		void setValid(const unsigned int& key_i)
		{
			keyValids |= (1 << key_i);
		}

		void clear()
		{
			YADECAP_MEMORY_BARRIER_COMPILE;
			nextExtendedChunkId = extendedChunkIdUnknown;
			YADECAP_MEMORY_BARRIER_COMPILE;
		}

		inline const TKey& getKey(unsigned int key_i) const
		{
			return pairs[key_i].key;
		}

		inline TKey& getKey(unsigned int key_i)
		{
			return pairs[key_i].key;
		}

		inline const TValue& getValue(unsigned int key_i) const
		{
			return pairs[key_i].value;
		}

		inline TValue& getValue(unsigned int key_i)
		{
			return pairs[key_i].value;
		}

	public:
		uint32_t nop0;

		union
		{
			struct
			{
				uint32_t nop1 : 24;
				uint8_t keyValids;
			} __attribute__((__packed__));

			uint32_t nextExtendedChunkId;

			uint32_t atomic;
		} __attribute__((__packed__));

		pair_t pairs[pairsPerChunk_T];
	};

	class extended_chunk_t
	{
	public:
		extended_chunk_t()
		{
			atomic = 0;
			nextExtendedChunkId = extendedChunkIdUnknown;
		}

	public:
		inline uint32_t getNextExtendedChunkId() const
		{
			return nextExtendedChunkId & 0x00FFFFFFu;
		}

		void setNextExtendedChunkId(const uint32_t& extendedChunkId)
		{
			nextExtendedChunkId = (nextExtendedChunkId & 0xFF000000u) | (extendedChunkId & 0x00FFFFFFu);
		}

		inline bool isValid(const unsigned int& key_i) const
		{
			return keyValids & (1 << key_i);
		}

		void setValid(const unsigned int& key_i)
		{
			keyValids |= (1 << key_i);
		}

		void clear()
		{
			YADECAP_MEMORY_BARRIER_COMPILE;
			nextExtendedChunkId = extendedChunkIdUnknown;
			YADECAP_MEMORY_BARRIER_COMPILE;
		}

		inline const TKey& getKey(unsigned int key_i) const
		{
			return pairs[key_i].key;
		}

		inline TKey& getKey(unsigned int key_i)
		{
			return pairs[key_i].key;
		}

		inline const TValue& getValue(unsigned int key_i) const
		{
			return pairs[key_i].value;
		}

		inline TValue& getValue(unsigned int key_i)
		{
			return pairs[key_i].value;
		}

	public:
		uint32_t nop0;

		union
		{
			struct
			{
				uint32_t nop : 24;
				uint8_t keyValids;
			} __attribute__((__packed__));

			uint32_t nextExtendedChunkId;

			uint32_t atomic;
		} __attribute__((__packed__));

		pair_t pairs[pairsPerExtendedChunk_T];
	};

protected:
	static inline bool compareKeys(const TKey& first,
	                               const TKey& second)
	{
		return !memcmp(&first, &second, sizeof(TKey));
	}

	uint32_t newExtendedChunk()
	{
		if (freeExtendedChunkId == extendedChunkIdUnknown)
		{
			return extendedChunkIdUnknown;
		}

		auto chunkId = freeExtendedChunkId;
		auto& extendedChunk = extendedChunks[chunkId];
		freeExtendedChunkId = extendedChunk.getNextExtendedChunkId();
		extendedChunk.setNextExtendedChunkId(extendedChunkIdUnknown);

		stats.extendedChunksCount++;

		return chunkId;
	}

	void freeExtendedChunk(const uint32_t& extendedChunkId)
	{
		if (extendedChunkId == extendedChunkIdUnknown)
		{
			return;
		}

		auto& extendedChunk = extendedChunks[extendedChunkId];
		extendedChunk.setNextExtendedChunkId(freeExtendedChunkId);
		freeExtendedChunkId = extendedChunkId;

		stats.extendedChunksCount--;
	}

protected:
	struct
	{
		uint64_t extendedChunksCount;
		uint64_t longestChain;
		uint64_t pairs; ///< keys
		uint64_t insertFailed;
	} stats;
	uint32_t freeExtendedChunkId;

	YADECAP_CACHE_ALIGNED(align1);

	chunk_t chunks[size_T];
	extended_chunk_t extendedChunks[extendedSize_T];

private:
	static_assert(sizeof(pair_t) % 8 == 0);
	static_assert(sizeof(chunk_t) % 8 == 0);
	static_assert(sizeof(extended_chunk_t) % 8 == 0);
	static_assert(__builtin_popcount(size_T) == 1);
	static_assert(extendedSize_T <= 0xFFFFFF);
	static_assert(pairsPerChunk_T <= 8);
	static_assert(pairsPerExtendedChunk_T <= 7);
} __rte_aligned(RTE_CACHE_LINE_SIZE);

template<typename key_T,
         typename value_T,
         uint32_t size_T,
         uint32_t extendedSize_T,
         unsigned int pairsPerChunk_T = 2,
         unsigned int pairsPerExtendedChunk_T = 4>
class hashtable_chain_spinlock_t
{
public:
	using hashtable_t = hashtable_chain_spinlock_t<key_T, value_T, size_T, extendedSize_T, pairsPerChunk_T, pairsPerExtendedChunk_T>;

public:
	hashtable_chain_spinlock_t() :
	        gcIndex(0)
	{
		for (uint32_t id = 0; id < extendedSize_T - 1; ++id)
		{
			auto& extendedChunk = extendedChunks[id];
			extendedChunk.setNextExtendedChunkId(id + 1);
		}
		auto& extendedChunk = extendedChunks[extendedSize_T - 1];
		extendedChunk.setNextExtendedChunkId(extendedChunkIdUnknown);

		freeExtendedChunkId = 0;
		memset(&stats, 0, sizeof(stats));
	}

	constexpr static uint64_t keysSize = size_T * pairsPerChunk_T + extendedSize_T * pairsPerExtendedChunk_T;

public:
	inline void lookup(const key_T& key,
	                   value_T*& value,
	                   spinlock_t*& locker)
	{
		const uint32_t hash = rte_hash_crc(&key, sizeof(key_T), 0);
		auto& chunk = chunks[hash & (size_T - 1)];

		value = nullptr;
		locker = &chunk.locker;

		locker->lock();

		for (unsigned int chunk_key_i = 0; ///< @todo: iterator
		     chunk_key_i < pairsPerChunk_T;
		     chunk_key_i++)
		{
			if (chunk.isValid(chunk_key_i) &&
			    compareKeys(chunk.getKey(chunk_key_i), key))
			{
				/// found in chunk

				value = &chunk.getValue(chunk_key_i);
				return;
			}
		}

		if (chunk.getNextExtendedChunkId() != extendedChunkIdUnknown)
		{
			auto& extendedChunk = extendedChunks[chunk.getNextExtendedChunkId()];

			for (unsigned int extended_chunk_key_i = 0; ///< @todo: iterator
			     extended_chunk_key_i < pairsPerExtendedChunk_T;
			     extended_chunk_key_i++)
			{
				if (extendedChunk.isValid(extended_chunk_key_i) &&
				    compareKeys(extendedChunk.getKey(extended_chunk_key_i), key))
				{
					/// found in extended chunk

					value = &extendedChunk.getValue(extended_chunk_key_i);
					return;
				}
			}
		}

		/// not found

		locker->unlock();
	}

	inline bool insert(const key_T& key,
	                   const value_T& value)
	{
		value_T* chunk_value{nullptr};
		spinlock_t* locker{nullptr};
		if (get(key, chunk_value, locker) != eResult::isFull)
		{
			*chunk_value = value;
			locker->unlock();
			return true;
		}

		return false;
	}

	/// Finds a chunk value and its locker for the given key, setting their
	/// pointers and returning either one "success", "isFull" or "alreadyExist" codes.
	///
	/// On "success" or "alreadyExist" the locker is automatically locked
	/// and it's the user's responsibility to unlock it.
	/// Also on success there is no need to check for "value" or "locker"
	/// for null-pointer.
	///
	/// Returns "false" when the table is full, in this case the lock is
	/// automatically unlocked.
	inline eResult get(const key_T& key, value_T*& value, spinlock_t*& locker)

	{
		const uint32_t hash = rte_hash_crc(&key, sizeof(key_T), 0);
		auto& chunk = chunks[hash & (size_T - 1)];

		chunk.locker.lock();
		locker = &chunk.locker;

		/// find key
		{
			for (unsigned int chunk_key_i = 0; ///< @todo: iterator
			     chunk_key_i < pairsPerChunk_T;
			     chunk_key_i++)
			{
				if (chunk.isValid(chunk_key_i) &&
				    compareKeys(chunk.getKey(chunk_key_i), key))
				{
					/// already exist in chunk

					value = &chunk.getValue(chunk_key_i);
					return eResult::alreadyExist;
				}
			}

			if (chunk.getNextExtendedChunkId() != extendedChunkIdUnknown)
			{
				auto& extendedChunk = extendedChunks[chunk.getNextExtendedChunkId()];

				for (unsigned int extended_chunk_key_i = 0; ///< @todo: iterator
				     extended_chunk_key_i < pairsPerExtendedChunk_T;
				     extended_chunk_key_i++)
				{
					if (extendedChunk.isValid(extended_chunk_key_i) &&
					    compareKeys(extendedChunk.getKey(extended_chunk_key_i), key))
					{
						/// already exist in extended chunk

						value = &extendedChunk.getValue(extended_chunk_key_i);
						return eResult::alreadyExist;
					}
				}
			}
		}

		/// key not found, insert
		{
			uint64_t longestChain = 0;

			for (unsigned int chunk_key_i = 0; ///< @todo: iterator
			     chunk_key_i < pairsPerChunk_T;
			     chunk_key_i++)
			{
				longestChain++;

				if (!chunk.isValid(chunk_key_i))
				{
					/// insert in chunk

					chunk.getKey(chunk_key_i) = key;
					value = &chunk.getValue(chunk_key_i);

					YADECAP_MEMORY_BARRIER_COMPILE;

					chunk.setValid(chunk_key_i);

					__atomic_add_fetch(&stats.pairs, 1, __ATOMIC_RELAXED);
					stats.longestChain = RTE_MAX(stats.longestChain, longestChain);

					return eResult::success;
				}
			}

			if (chunk.getNextExtendedChunkId() == extendedChunkIdUnknown)
			{
				/// create next extended chunk
				chunk.setNextExtendedChunkId(newExtendedChunk());
			}

			if (chunk.getNextExtendedChunkId() != extendedChunkIdUnknown)
			{
				auto& extendedChunk = extendedChunks[chunk.getNextExtendedChunkId()];

				for (unsigned int extended_chunk_key_i = 0; ///< @todo: iterator
				     extended_chunk_key_i < pairsPerExtendedChunk_T;
				     extended_chunk_key_i++)
				{
					longestChain++;

					if (!extendedChunk.isValid(extended_chunk_key_i))
					{
						/// insert in extended chunk

						extendedChunk.getKey(extended_chunk_key_i) = key;
						value = &extendedChunk.getValue(extended_chunk_key_i);

						YADECAP_MEMORY_BARRIER_COMPILE;

						extendedChunk.setValid(extended_chunk_key_i);

						__atomic_add_fetch(&stats.pairs, 1, __ATOMIC_RELAXED);
						stats.longestChain = RTE_MAX(stats.longestChain, longestChain);

						return eResult::success;
					}
				}
			}
		}

		/// chain is full

		__atomic_add_fetch(&stats.insertFailed, 1, __ATOMIC_RELAXED);

		chunk.locker.unlock();
		return eResult::isFull;
	}

	inline bool remove(const key_T& key)
	{
		const uint32_t hash = rte_hash_crc(&key, sizeof(key_T), 0);
		auto& chunk = chunks[hash & (size_T - 1)];

		chunk.locker.lock();

		/// find key
		{
			for (unsigned int chunk_key_i = 0; ///< @todo: iterator
			     chunk_key_i < pairsPerChunk_T;
			     chunk_key_i++)
			{
				if (chunk.isValid(chunk_key_i) &&
				    compareKeys(chunk.getKey(chunk_key_i), key))
				{
					/// exist in chunk

					chunk.unsetValid(chunk_key_i);

					__atomic_sub_fetch(&stats.pairs, 1, __ATOMIC_RELAXED);

					chunk.locker.unlock();
					return true;
				}
			}

			if (chunk.getNextExtendedChunkId() != extendedChunkIdUnknown)
			{
				auto& extendedChunk = extendedChunks[chunk.getNextExtendedChunkId()];

				for (unsigned int extended_chunk_key_i = 0; ///< @todo: iterator
				     extended_chunk_key_i < pairsPerExtendedChunk_T;
				     extended_chunk_key_i++)
				{
					if (extendedChunk.isValid(extended_chunk_key_i) &&
					    compareKeys(extendedChunk.getKey(extended_chunk_key_i), key))
					{
						/// exist in extended chunk

						extendedChunk.unsetValid(extended_chunk_key_i);

						/// use gc for remove extended chunk

						__atomic_sub_fetch(&stats.pairs, 1, __ATOMIC_RELAXED);

						chunk.locker.unlock();
						return true;
					}
				}
			}
		}

		/// key not found

		chunk.locker.unlock();
		return false;
	}

	void clear()
	{
		for (unsigned int chunk_i = 0;
		     chunk_i < size_T;
		     chunk_i++)
		{
			auto& chunk = chunks[chunk_i];

			chunk.locker.lock();

			{
				for (unsigned int chunk_key_i = 0; ///< @todo: iterator
				     chunk_key_i < pairsPerChunk_T;
				     chunk_key_i++)
				{
					if (chunk.isValid(chunk_key_i))
					{
						chunk.unsetValid(chunk_key_i);

						__atomic_sub_fetch(&stats.pairs, 1, __ATOMIC_RELAXED);
					}
				}

				if (chunk.getNextExtendedChunkId() != extendedChunkIdUnknown)
				{
					auto& extendedChunk = extendedChunks[chunk.getNextExtendedChunkId()];

					for (unsigned int extended_chunk_key_i = 0; ///< @todo: iterator
					     extended_chunk_key_i < pairsPerExtendedChunk_T;
					     extended_chunk_key_i++)
					{
						if (extendedChunk.isValid(extended_chunk_key_i))
						{
							extendedChunk.unsetValid(extended_chunk_key_i);

							__atomic_sub_fetch(&stats.pairs, 1, __ATOMIC_RELAXED);
						}
					}

					uint32_t extendedChunkId = chunk.getNextExtendedChunkId();
					chunk.setNextExtendedChunkId(extendedChunkIdUnknown);

					YADECAP_MEMORY_BARRIER_COMPILE;

					freeExtendedChunk(extendedChunkId);
				}
			}

			chunk.locker.unlock();
		}

		/// @todo: clear stats.longestChain, stats.insertFailed
	}

	class range_chunks_t
	{
	public:
		class iterator_t
		{
		public:
			void lock()
			{
				auto& chunk = hashtable->chunks[chunk_i];
				chunk.locker.lock();
			}

			void unlock()
			{
				auto& chunk = hashtable->chunks[chunk_i];
				chunk.locker.unlock();
			}

			key_T* key()
			{
				auto& chunk = hashtable->chunks[chunk_i];

				if (key_i < pairsPerChunk_T)
				{
					return &chunk.getKey(key_i);
				}
				else if (chunk.getNextExtendedChunkId() != extendedChunkIdUnknown)
				{
					auto& extendedChunk = hashtable->extendedChunks[chunk.getNextExtendedChunkId()];

					return &extendedChunk.getKey(key_i - pairsPerChunk_T);
				}

				return nullptr;
			}

			value_T* value()
			{
				auto& chunk = hashtable->chunks[chunk_i];

				if (key_i < pairsPerChunk_T)
				{
					return &chunk.getValue(key_i);
				}
				else if (chunk.getNextExtendedChunkId() != extendedChunkIdUnknown)
				{
					auto& extendedChunk = hashtable->extendedChunks[chunk.getNextExtendedChunkId()];

					return &extendedChunk.getValue(key_i - pairsPerChunk_T);
				}

				return nullptr;
			}

			bool isValid()
			{
				auto& chunk = hashtable->chunks[chunk_i];

				if (key_i < pairsPerChunk_T)
				{
					return chunk.isValid(key_i);
				}
				else if (chunk.getNextExtendedChunkId() != extendedChunkIdUnknown)
				{
					auto& extendedChunk = hashtable->extendedChunks[chunk.getNextExtendedChunkId()];

					return extendedChunk.isValid(key_i - pairsPerChunk_T);
				}

				return false;
			}

			void unsetValid()
			{
				auto& chunk = hashtable->chunks[chunk_i];

				if (key_i < pairsPerChunk_T)
				{
					chunk.unsetValid(key_i);

					__atomic_sub_fetch(&hashtable->stats.pairs, 1, __ATOMIC_RELAXED);
				}
				else if (chunk.getNextExtendedChunkId() != extendedChunkIdUnknown)
				{
					auto& extendedChunk = hashtable->extendedChunks[chunk.getNextExtendedChunkId()];

					extendedChunk.unsetValid(key_i - pairsPerChunk_T);

					__atomic_sub_fetch(&hashtable->stats.pairs, 1, __ATOMIC_RELAXED);
				}
			}

			void gc()
			{
				auto& chunk = hashtable->chunks[chunk_i];

				if (key_i == 0 &&
				    chunk.getNextExtendedChunkId() != extendedChunkIdUnknown)
				{
					/// @todo: stats

					auto& extendedChunk = hashtable->extendedChunks[chunk.getNextExtendedChunkId()];

					for (unsigned int extended_chunk_key_i = 0; ///< @todo: iterator
					     extended_chunk_key_i < pairsPerExtendedChunk_T;
					     extended_chunk_key_i++)
					{
						if (extendedChunk.isValid(extended_chunk_key_i))
						{
							return;
						}
					}

					/// remove extended chunk

					uint32_t extendedChunkId = chunk.getNextExtendedChunkId();
					chunk.setNextExtendedChunkId(extendedChunkIdUnknown);

					YADECAP_MEMORY_BARRIER_COMPILE;

					hashtable->freeExtendedChunk(extendedChunkId);
				}
			}

			void try_gc()
			{
				if (key_i != 0)
				{
					return;
				}

				auto& chunk = hashtable->chunks[chunk_i];
				chunk.locker.lock();

				if (chunk.getNextExtendedChunkId() != extendedChunkIdUnknown)
				{
					/// @todo: stats

					auto& extendedChunk = hashtable->extendedChunks[chunk.getNextExtendedChunkId()];

					for (unsigned int extended_chunk_key_i = 0; ///< @todo: iterator
					     extended_chunk_key_i < pairsPerExtendedChunk_T;
					     extended_chunk_key_i++)
					{
						if (extendedChunk.isValid(extended_chunk_key_i))
						{
							chunk.locker.unlock();
							return;
						}
					}

					/// remove extended chunk

					uint32_t extendedChunkId = chunk.getNextExtendedChunkId();
					chunk.setNextExtendedChunkId(extendedChunkIdUnknown);

					YADECAP_MEMORY_BARRIER_COMPILE;

					hashtable->freeExtendedChunk(extendedChunkId);
				}

				chunk.locker.unlock();
			}

		public:
			iterator_t operator++()
			{
				key_i++;

				if (key_i == pairsPerChunk_T + pairsPerExtendedChunk_T)
				{
					chunk_i++;
					key_i = 0;
				}

				return *this;
			}

			bool operator!=(const iterator_t& second) const
			{
				return chunk_i != second.chunk_i;
			}

			iterator_t& operator*()
			{
				return *this;
			}

		private:
			friend class range_chunks_t;

			iterator_t(hashtable_t* hashtable,
			           const uint32_t& chunk_i) :
			        hashtable(hashtable),
			        chunk_i(chunk_i),
			        key_i(0)
			{
			}

		private:
			hashtable_t* hashtable;

			uint32_t chunk_i;
			uint32_t key_i;
		};

		iterator_t begin() const
		{
			return {hashtable, RTE_MIN(from, size_T)};
		}

		iterator_t end() const
		{
			return {hashtable, RTE_MIN(from + steps, size_T)};
		}

	private:
		friend class hashtable_chain_spinlock_t;

		range_chunks_t(hashtable_t* hashtable,
		               const uint32_t& from,
		               const uint32_t& steps) :
		        hashtable(hashtable),
		        from(from),
		        steps(steps)
		{
		}

	private:
		hashtable_t* hashtable;
		uint32_t from;
		uint32_t steps;
	};

	range_chunks_t range(uint32_t& from, const uint32_t steps)
	{
		range_chunks_t result(this, from, steps);

		from += steps;
		if (from >= size_T)
		{
			from = 0;
		}

		return result;
	}

	/// only single thread
	range_chunks_t range(const uint32_t steps)
	{
		return range(gcIndex, steps);
	}

	const auto& getStats() const
	{
		return stats;
	}

protected:
	constexpr static uint8_t flagExtendedChunkOccupied = 1 << 7;
	constexpr static uint32_t extendedChunkIdUnknown = 0x00FFFFFF;

	struct pair_t
	{
		key_T key;
		value_T value;
	};

	class chunk_t
	{
	public:
		chunk_t()
		{
			atomic = 0;
			nextExtendedChunkId = extendedChunkIdUnknown;
		}

	public:
		inline uint32_t getNextExtendedChunkId() const
		{
			return nextExtendedChunkId & 0x00FFFFFFu;
		}

		inline void setNextExtendedChunkId(const uint32_t& extendedChunkId)
		{
			nextExtendedChunkId = (nextExtendedChunkId & 0xFF000000u) | (extendedChunkId & 0x00FFFFFFu);
		}

		inline bool isValid(const unsigned int& key_i) const
		{
			return keyValids & (1u << key_i);
		}

		inline void setValid(const unsigned int& key_i)
		{
			keyValids |= (1u << key_i);
		}

		inline void unsetValid(const unsigned int& key_i)
		{
			keyValids &= ~(1u << key_i);
		}

		void clear()
		{
			YADECAP_MEMORY_BARRIER_COMPILE;
			nextExtendedChunkId = extendedChunkIdUnknown;
			YADECAP_MEMORY_BARRIER_COMPILE;
		}

		inline const key_T& getKey(unsigned int key_i) const
		{
			return pairs[key_i].key;
		}

		inline key_T& getKey(unsigned int key_i)
		{
			return pairs[key_i].key;
		}

		inline const value_T& getValue(unsigned int key_i) const
		{
			return pairs[key_i].value;
		}

		inline value_T& getValue(unsigned int key_i)
		{
			return pairs[key_i].value;
		}

	public:
		spinlock_t locker;

		union
		{
			struct
			{
				uint32_t nop1 : 24;
				uint8_t keyValids;
			} __attribute__((__packed__));

			uint32_t nextExtendedChunkId;

			uint32_t atomic;
		} __attribute__((__packed__));

		pair_t pairs[pairsPerChunk_T];
	};

	class extended_chunk_t
	{
	public:
		extended_chunk_t()
		{
			atomic = 0;
			nextExtendedChunkId = extendedChunkIdUnknown;
		}

	public:
		inline uint32_t getNextExtendedChunkId() const
		{
			return nextExtendedChunkId & 0x00FFFFFFu;
		}

		inline void setNextExtendedChunkId(const uint32_t& extendedChunkId)
		{
			nextExtendedChunkId = (nextExtendedChunkId & 0xFF000000u) | (extendedChunkId & 0x00FFFFFFu);
		}

		inline bool isValid(const unsigned int& key_i) const
		{
			return keyValids & (1u << key_i);
		}

		inline void setValid(const unsigned int& key_i)
		{
			keyValids |= (1u << key_i);
		}

		inline void unsetValid(const unsigned int& key_i)
		{
			keyValids &= ~(1u << key_i);
		}

		void clear()
		{
			YADECAP_MEMORY_BARRIER_COMPILE;
			nextExtendedChunkId = extendedChunkIdUnknown;
			YADECAP_MEMORY_BARRIER_COMPILE;
		}

		inline const key_T& getKey(unsigned int key_i) const
		{
			return pairs[key_i].key;
		}

		inline key_T& getKey(unsigned int key_i)
		{
			return pairs[key_i].key;
		}

		inline const value_T& getValue(unsigned int key_i) const
		{
			return pairs[key_i].value;
		}

		inline value_T& getValue(unsigned int key_i)
		{
			return pairs[key_i].value;
		}

	public:
		uint32_t nop0;

		union
		{
			struct
			{
				uint32_t nop : 24;
				uint8_t keyValids;
			} __attribute__((__packed__));

			uint32_t nextExtendedChunkId;

			uint32_t atomic;
		} __attribute__((__packed__));

		pair_t pairs[pairsPerExtendedChunk_T];
	};

protected:
	static inline bool compareKeys(const key_T& first,
	                               const key_T& second)
	{
		return !memcmp(&first, &second, sizeof(key_T));
	}

	uint32_t newExtendedChunk()
	{
		extendedChunkLocker.lock();

		if (freeExtendedChunkId == extendedChunkIdUnknown)
		{
			extendedChunkLocker.unlock();
			return extendedChunkIdUnknown;
		}

		auto chunkId = freeExtendedChunkId;
		auto& extendedChunk = extendedChunks[chunkId];
		freeExtendedChunkId = extendedChunk.getNextExtendedChunkId();
		extendedChunk.setNextExtendedChunkId(extendedChunkIdUnknown);

		stats.extendedChunksCount++;
		extendedChunkLocker.unlock();

		return chunkId;
	}

	void freeExtendedChunk(const uint32_t& extendedChunkId)
	{
		extendedChunkLocker.lock();

		if (extendedChunkId == extendedChunkIdUnknown)
		{
			extendedChunkLocker.unlock();
			return;
		}

		auto& extendedChunk = extendedChunks[extendedChunkId];
		extendedChunk.setNextExtendedChunkId(freeExtendedChunkId);
		freeExtendedChunkId = extendedChunkId;

		stats.extendedChunksCount--;
		extendedChunkLocker.unlock();
	}

protected:
	struct
	{
		uint64_t extendedChunksCount;
		uint64_t longestChain;
		uint64_t pairs;
		uint64_t insertFailed;
	} stats;

	spinlock_t extendedChunkLocker;
	uint32_t gcIndex;
	uint32_t freeExtendedChunkId;

	YADECAP_CACHE_ALIGNED(align1);

	chunk_t chunks[size_T];
	extended_chunk_t extendedChunks[extendedSize_T];

private:
	static_assert(sizeof(pair_t) % 8 == 0);
	static_assert(sizeof(chunk_t) % 8 == 0);
	static_assert(sizeof(extended_chunk_t) % 8 == 0);
	static_assert(__builtin_popcount(size_T) == 1);
	static_assert(extendedSize_T <= 0xFFFFFF);
	static_assert(pairsPerChunk_T <= 8);
	static_assert(pairsPerExtendedChunk_T <= 7);
} __rte_aligned(RTE_CACHE_LINE_SIZE);

template<typename key_t,
         uint32_t total_size,
         uint32_t chunk_size,
         unsigned int valid_bit_offset = 0,
         unsigned int burst_size = YANET_CONFIG_BURST_SIZE,
         hash_function_t<key_t> calculate_hash = calculate_hash_crc<key_t>>
class hashtable_mod_id32
{
public:
	constexpr static uint32_t mask_full = 0xFFFFFFFFu;
	constexpr static uint32_t shift_valid = (32 - 1 - valid_bit_offset);
	constexpr static uint64_t pairs_size = total_size;
	constexpr static uint64_t longest_chain_size = chunk_size;

	static_assert(__builtin_popcount(total_size) == 1);
	static_assert(__builtin_popcount(chunk_size) == 1);
	static_assert(valid_bit_offset < 32);
	static_assert(burst_size > 0);
	static_assert(burst_size <= 32);

public:
	class updater
	{
	public:
		updater()
		{
			clear();
		}

		void clear()
		{
			keys_count = 0;
			keys_in_chunks.fill(0);
			longest_chain = 0;
			insert_failed = 0;
			rewrites = 0;
		}

	public:
		uint32_t keys_count;
		std::array<uint32_t, chunk_size + 1> keys_in_chunks;
		uint32_t longest_chain;
		uint64_t insert_failed;
		uint64_t rewrites;
	};

	template<typename list_T> ///< @todo: common::idp::limits::response
	void limits(list_T& list,
	            const std::string& name,
	            const std::optional<unsigned int>& socket_id,
	            const updater& updater) const
	{
		list.emplace_back(name + ".keys",
		                  socket_id,
		                  updater.keys_count,
		                  total_size);
		list.emplace_back(name + ".longest_collision",
		                  socket_id,
		                  updater.longest_chain,
		                  chunk_size);
	}

	template<typename list_T> ///< @todo: common::idp::limits::response
	void limits(list_T& list,
	            const std::string& name,
	            const updater& updater) const
	{
		limits(list, name, std::nullopt, updater);
	}

	template<typename json_t> ///< @todo: nlohmann::json
	void report(json_t& json,
	            const updater& updater) const
	{
		json["keys_count"] = updater.keys_count;
		for (unsigned int i = 0;
		     i < updater.keys_in_chunks.size();
		     i++)
		{
			json["keys_in_chunks"][i] = updater.keys_in_chunks[i];
		}
		json["longest_chain"] = updater.longest_chain;
		json["insert_failed"] = updater.insert_failed;
		json["rewrites"] = updater.rewrites;
	}

public:
	hashtable_mod_id32()
	{
		clear();
	}

public:
	/// value:
	/// valid	collision	invalid
	/// = 1VV	= 1VV		= 0VV
	/// & 1VV	& 0VV		& VVV
	/// ^ 100	^ 100		^ 100
	/// = 0VV	= 1VV		= 1VV
	inline uint32_t lookup(uint32_t (&hashes)[burst_size],
	                       const key_t (&keys)[burst_size],
	                       uint32_t (&values)[burst_size],
	                       const unsigned int count) const
	{
		uint32_t mask = mask_full;

		/// step 1: hash
		for (unsigned int i = 0;
		     i < count;
		     i++)
		{
			hashes[i] = calculate_hash(keys[i]);
			hashes[i] &= (total_size - 1);
		}

		/// step 2: first check
		for (unsigned int i = 0;
		     i < count;
		     i++)
		{
			values[i] = pairs[hashes[i]].value;
			if (is_valid(hashes[i]))
			{
				values[i] &= 0xFFFFFFFFu ^ (((uint32_t)!is_equal(hashes[i], keys[i])) << shift_valid);
			}
			values[i] ^= 1u << shift_valid;

			mask ^= ((values[i] >> shift_valid) & 1) << i;
		}

		if (chunk_size == 1)
		{
			return mask;
		}

		/// step 3: collision check
		if (mask != mask_full)
		{
			for (unsigned int i = 0;
			     i < count;
			     i++)
			{
				if (mask & (1u << i))
				{
					continue;
				}

				for (unsigned int try_i = 1;
				     try_i < chunk_size;
				     try_i++)
				{
					const uint32_t index = (hashes[i] + try_i) % total_size;

					if (!is_valid(index))
					{
						break;
					}
					else if (is_equal(index, keys[i]))
					{
						values[i] = pairs[index].value;
						values[i] ^= 1u << shift_valid;

						mask ^= 1u << i;

						break;
					}
				}
			}
		}

		return mask;
	}

	template<typename update_key_t>
	eResult update(updater& updater,
	               const std::vector<std::tuple<update_key_t, uint32_t>>& keys)
	{
		eResult result = eResult::success;

		updater.clear();

		for (const auto& [key, value] : keys)
		{
			eResult insert_result;
			if constexpr (std::is_same_v<update_key_t, key_t>)
			{
				insert_result = insert(updater, key, value);
			}
			else
			{
				insert_result = insert(updater, key_t::convert(key), value);
			}

			if (insert_result != eResult::success)
			{
				result = insert_result;
			}
		}

		for (uint32_t chunk_i = 0;
		     chunk_i < total_size / chunk_size;
		     chunk_i++)
		{
			unsigned int count = 0;

			for (uint32_t pair_i = 0;
			     pair_i < chunk_size;
			     pair_i++)
			{
				if (is_valid(chunk_i * chunk_size + pair_i))
				{
					count++;
				}
			}

			updater.keys_in_chunks[count]++;
		}

		return result;
	}

	eResult insert(updater& updater,
	               const key_t& key,
	               const uint32_t value)
	{
		const uint32_t hash = calculate_hash(key) & (total_size - 1);

		for (unsigned int try_i = 0;
		     try_i < chunk_size;
		     try_i++)
		{
			const uint32_t index = (hash + try_i) % total_size;

			if (!is_valid(index))
			{
				memcpy(&pairs[index].key, &key, sizeof(key_t));
				pairs[index].value = value;
				pairs[index].value |= 1u << shift_valid;

				updater.keys_count++;

				uint64_t longest_chain = try_i + 1;
				if (updater.longest_chain < longest_chain)
				{
					updater.longest_chain = longest_chain;
				}

				return eResult::success;
			}
			else if (is_valid_and_equal(index, key))
			{
				pairs[index].value = value;
				pairs[index].value |= 1u << shift_valid;

				updater.rewrites++;

				return eResult::success;
			}
		}

		updater.insert_failed++;

		return eResult::isFull;
	}

	void clear()
	{
		for (uint32_t i = 0;
		     i < total_size;
		     i++)
		{
			pairs[i].value = 0;
		}
	}

protected:
	struct
	{
		key_t key;
		uint32_t value;
	} pairs[total_size];

protected:
	inline bool is_valid(const uint32_t index) const
	{
		return (pairs[index].value >> shift_valid) & 1;
	}

	inline bool is_equal(const uint32_t index, const key_t& key) const
	{
		return !memcmp(&pairs[index].key, &key, sizeof(key_t));
	}

	inline bool is_valid_and_equal(const uint32_t index, const key_t& key) const
	{
		return is_valid(index) && is_equal(index, key);
	}
} __rte_aligned(RTE_CACHE_LINE_SIZE);

template<typename key_t,
         uint32_t chunk_size,
         unsigned int valid_bit_offset = 0,
         hash_function_t<key_t> calculate_hash = calculate_hash_crc<key_t>>
class hashtable_mod_id32_dynamic
{
public:
	using hashtable_t = hashtable_mod_id32_dynamic<key_t, chunk_size, valid_bit_offset, calculate_hash>;

	constexpr static uint32_t mask_full = 0xFFFFFFFFu;
	constexpr static uint32_t shift_valid = (32 - 1 - valid_bit_offset);
	constexpr static uint64_t longest_chain_size = chunk_size;
	constexpr static uint32_t pairs_size_min = 128;

	static_assert(__builtin_popcount(chunk_size) == 1);
	static_assert(valid_bit_offset < 32);

	struct stats_t
	{
		uint32_t pairs_count;
		uint32_t pairs_size;
		std::array<uint32_t, chunk_size + 1> pairs_in_chunks;
		uint32_t longest_chain;
		uint64_t insert_failed;
		uint64_t rewrites;
	};

	static uint64_t calculate_sizeof(const uint32_t pairs_size)
	{
		if (!pairs_size)
		{
			YANET_LOG_ERROR("wrong pairs_size: %u\n", pairs_size);
			return 0;
		}

		if (__builtin_popcount(pairs_size) != 1)
		{
			YANET_LOG_ERROR("wrong pairs_size: %u is non power of 2\n", pairs_size);
			return 0;
		}

		return sizeof(hashtable_t) + pairs_size * sizeof(pair);
	}

public:
	hashtable_mod_id32_dynamic(const uint32_t pairs_size) :
	        total_mask(pairs_size - 1)
	{
		for (uint32_t i = 0;
		     i < pairs_size;
		     i++)
		{
			pairs[i].value = 0;
		}
	}

	/// value:
	/// valid	invalid
	/// = 0VV	= 1VV
	template<unsigned int burst_size = YANET_CONFIG_BURST_SIZE>
	inline uint32_t lookup(uint32_t (&hashes)[burst_size],
	                       const key_t (&keys)[burst_size],
	                       uint32_t (&values)[burst_size],
	                       const unsigned int count) const
	{
		uint32_t mask = mask_full;

		/// step 1: hash
		for (unsigned int i = 0;
		     i < count;
		     i++)
		{
			hashes[i] = calculate_hash(keys[i]);
			hashes[i] &= total_mask;
			rte_prefetch0(&pairs[hashes[i]]);
		}

		/// step 2: first check
		for (unsigned int i = 0;
		     i < count;
		     i++)
		{
			values[i] = pairs[hashes[i]].value;
			if (is_valid(hashes[i]))
			{
				values[i] &= 0xFFFFFFFFu ^ (((uint32_t)!is_equal(hashes[i], keys[i])) << shift_valid);
			}
			values[i] ^= 1u << shift_valid;

			mask ^= ((values[i] >> shift_valid) & 1) << i;
		}

		if (chunk_size == 1)
		{
			return mask;
		}

		/// step 3: collision check
		if (mask != mask_full)
		{
			for (unsigned int i = 0;
			     i < count;
			     i++)
			{
				if (mask & (1u << i))
				{
					continue;
				}

				for (unsigned int try_i = 1;
				     try_i < chunk_size;
				     try_i++)
				{
					const uint32_t index = (hashes[i] + try_i) & total_mask;

					if (!is_valid(index))
					{
						break;
					}
					else if (is_equal(index, keys[i]))
					{
						values[i] = pairs[index].value;
						values[i] ^= 1u << shift_valid;

						mask ^= 1u << i;

						break;
					}
				}
			}
		}

		return mask;
	}

	eResult fill(stats_t& stats, const std::vector<std::tuple<key_t, uint32_t>>& pairs)
	{
		eResult result = eResult::success;

		stats.pairs_count = 0;
		stats.pairs_in_chunks.fill(0);
		stats.longest_chain = 0;
		stats.insert_failed = 0;
		stats.rewrites = 0;

		for (const auto& [key, value] : pairs)
		{
			eResult insert_result = insert(stats, key, value);
			if (insert_result != eResult::success)
			{
				result = insert_result;
			}
		}

		for (uint32_t chunk_i = 0;
		     chunk_i < stats.pairs_size / chunk_size;
		     chunk_i++)
		{
			unsigned int count = 0;

			for (uint32_t pair_i = 0;
			     pair_i < chunk_size;
			     pair_i++)
			{
				if (is_valid(chunk_i * chunk_size + pair_i))
				{
					count++;
				}
			}

			stats.pairs_in_chunks[count]++;
		}

		return result;
	}

	eResult insert(stats_t& stats,
	               const key_t& key,
	               const uint32_t value)
	{
		const uint32_t hash = calculate_hash(key) & total_mask;

		for (unsigned int try_i = 0;
		     try_i < chunk_size;
		     try_i++)
		{
			const uint32_t index = (hash + try_i) & total_mask;

			if (!is_valid(index))
			{
				memcpy(&pairs[index].key, &key, sizeof(key_t));
				pairs[index].value = value;
				pairs[index].value |= 1u << shift_valid;

				stats.pairs_count++;

				uint64_t longest_chain = try_i + 1;
				if (stats.longest_chain < longest_chain)
				{
					stats.longest_chain = longest_chain;
				}

				return eResult::success;
			}
			else if (is_valid_and_equal(index, key))
			{
				pairs[index].value = value;
				pairs[index].value |= 1u << shift_valid;

				stats.rewrites++;

				return eResult::success;
			}
		}

		stats.insert_failed++;

		return eResult::isFull;
	}

protected:
	inline bool is_valid(const uint32_t index) const
	{
		return (pairs[index].value >> shift_valid) & 1;
	}

	inline bool is_equal(const uint32_t index, const key_t& key) const
	{
		return !memcmp(&pairs[index].key, &key, sizeof(key_t));
	}

	inline bool is_valid_and_equal(const uint32_t index, const key_t& key) const
	{
		return is_valid(index) && is_equal(index, key);
	}

protected:
	uint32_t total_mask;

	struct pair
	{
		key_t key;
		uint32_t value;
	} pairs[];
};

class hashtable_mod_spinlock_stats ///< @todo: move to class::updater
{
public:
	hashtable_mod_spinlock_stats()
	{
		memset(this, 0, sizeof(*this));
	}

public:
	uint64_t valid_keys;
	uint64_t keys_in_chunks[32 + 1];
};

/// hashtable with spinlocks. multithread allowed
///
/// chunk
/// [
///   spinlock | valid_mask
///   key | value   <-- hash == 0
///   key | value   <-- hash == 1
///   key | value   <-- hash == 2
///   key | value   <-- hash == 3 (chunk_size)
/// ]
/// chunk
/// [
///   spinlock | valid_mask
///   key | value   <-- hash == 4
///   key | value   <-- hash == 5
///   key | value   <-- hash == 6
///   key | value   <-- hash == 7
/// ]
/// chunk
/// [
///   spinlock | valid_mask
///   key | value   <-- hash == 8
///   key | value   <-- hash == 9
///   key | value   <-- hash == 10
///   key | value   <-- hash == 11 (total_size)
/// ]
template<typename key_t,
         typename value_t,
         uint32_t total_size,
         uint32_t chunk_size,
         hash_function_t<key_t> calculate_hash = calculate_hash_crc<key_t>>
class hashtable_mod_spinlock
{
public:
	constexpr static uint32_t valid_mask_full = 0xFFFFFFFFu >> (32 - chunk_size);
	constexpr static uint64_t pairs_size = total_size;
	constexpr static uint64_t keys_in_chunk_size = chunk_size;
	constexpr static uint32_t hash_shift = __builtin_popcount(total_size / chunk_size - 1);

	static_assert(__builtin_popcount(total_size) == 1);
	static_assert(__builtin_popcount(chunk_size) == 1);
	static_assert(chunk_size <= 32);

public:
	hashtable_mod_spinlock()
	{
		clear();
	}

public:
	inline uint32_t lookup(const key_t& key,
	                       value_t*& value,
	                       spinlock_nonrecursive_t*& locker)
	{
		uint32_t hash = calculate_hash(key);
		auto& chunk = chunks[hash & (total_size / chunk_size - 1)];

		value = nullptr;
		locker = &chunk.locker;

		locker->lock();

		const uint32_t pair_index = (hash >> hash_shift) & (chunk_size - 1);
		if (is_valid_and_equal(chunk, pair_index, key))
		{
			value = &chunk.pairs[pair_index].value;
			return hash;
		}

		if (chunk_size == 1)
		{
			return hash;
		}

		/// check collision
		uint32_t valid_mask = chunk.valid_mask;
		for (unsigned int try_i = 1;
		     try_i < chunk_size && valid_mask;
		     try_i++)
		{
			const uint32_t pair_index = ((hash >> hash_shift) + try_i) & (chunk_size - 1);
			if (is_valid_and_equal(chunk, pair_index, key))
			{
				value = &chunk.pairs[pair_index].value;
				return hash;
			}
			valid_mask &= 0xFFFFFFFFu ^ (1u << pair_index);
		}

		/// not found
		return hash;
	}

	inline bool insert(const uint32_t hash,
	                   const key_t& key,
	                   const value_t& value)
	{
		auto& chunk = chunks[hash & (total_size / chunk_size - 1)];

		const uint32_t pair_index = (hash >> hash_shift) & (chunk_size - 1);
		if (!is_valid(chunk, pair_index))
		{
			memcpy(&chunk.pairs[pair_index].key, &key, sizeof(key_t));
			memcpy(&chunk.pairs[pair_index].value, &value, sizeof(value_t));
			chunk.valid_mask |= 1u << pair_index;

			return true;
		}
		/* else if (is_equal(chunk, pair_index, key))
		{
		        /// hashtable is broken
		} */

		if (chunk_size == 1)
		{
			return false;
		}

		/// collision
		if (chunk.valid_mask == valid_mask_full)
		{
			/// chunk is full
			return false;
		}

		for (unsigned int try_i = 1;
		     try_i < chunk_size;
		     try_i++)
		{
			const uint32_t pair_index = ((hash >> hash_shift) + try_i) & (chunk_size - 1);
			if (!is_valid(chunk, pair_index))
			{
				memcpy(&chunk.pairs[pair_index].key, &key, sizeof(key_t));
				memcpy(&chunk.pairs[pair_index].value, &value, sizeof(value_t));
				chunk.valid_mask |= 1u << pair_index;

				return true;
			}
			/* else if (is_equal(chunk, pair_index, key))
			{
			        /// hashtable is broken
			} */
		}

		/// chunk is full
		return false;
	}

	inline bool insert_or_update(const key_t& key,
	                             const value_t& value)
	{
		bool result = true;

		value_t* ht_value;
		spinlock_nonrecursive_t* locker;

		uint32_t hash = lookup(key, ht_value, locker);
		if (ht_value)
		{
			*ht_value = value;
		}
		else
		{
			result = insert(hash, key, value);
		}

		locker->unlock();
		return result;
	}

	void clear()
	{
		for (uint32_t i = 0;
		     i < total_size / chunk_size;
		     i++)
		{
			chunks[i].valid_mask = 0;
		}
	}

public:
	class iterator_t
	{
	public:
		iterator_t(hashtable_mod_spinlock* hashtable,
		           const uint32_t index) :
		        hashtable(hashtable),
		        index(index)
		{
		}

		iterator_t operator++()
		{
			index++;
			return *this;
		}

		bool operator!=(const iterator_t& second) const
		{
			return index != second.index;
		}

		iterator_t& operator*()
		{
			return *this;
		}

	public:
		void lock()
		{
			chunk().locker.lock();
		}

		void unlock()
		{
			chunk().locker.unlock();
		}

		bool is_valid()
		{
			const uint32_t pair_index = (index >> hash_shift) & (chunk_size - 1);
			return chunk().valid_mask & (1u << pair_index);
		}

		void unset_valid()
		{
			const uint32_t pair_index = (index >> hash_shift) & (chunk_size - 1);
			chunk().valid_mask &= 0xFFFFFFFFu ^ (1u << pair_index);
		}

		const key_t* key()
		{
			const uint32_t pair_index = (index >> hash_shift) & (chunk_size - 1);
			return &chunk().pairs[pair_index].key;
		}

		value_t* value()
		{
			const uint32_t pair_index = (index >> hash_shift) & (chunk_size - 1);
			return &chunk().pairs[pair_index].value;
		}

		void calculate_stats(hashtable_mod_spinlock_stats& stats)
		{
			const uint32_t pair_index = (index >> hash_shift) & (chunk_size - 1);
			if (pair_index != 0)
			{
				return;
			}

			uint32_t pairs_in_chunk = __builtin_popcount(chunk().valid_mask);
			stats.valid_keys += pairs_in_chunk;
			stats.keys_in_chunks[pairs_in_chunk]++;
		}

		auto& chunk()
		{
			return hashtable->chunks[index & (total_size / chunk_size - 1)];
		}

	protected:
		hashtable_mod_spinlock* hashtable;
		uint32_t index;
	};

	class range_t
	{
	public:
		range_t(hashtable_mod_spinlock* hashtable,
		        const uint32_t offset,
		        const uint32_t step) :
		        hashtable(hashtable),
		        offset(offset),
		        step(step)
		{
		}

		iterator_t begin() const
		{
			return {hashtable, RTE_MIN(offset, total_size)};
		}

		iterator_t end() const
		{
			return {hashtable, RTE_MIN(offset + step, total_size)};
		}

	protected:
		hashtable_mod_spinlock* hashtable;
		uint32_t offset;
		uint32_t step;
	};

	range_t range(uint32_t& offset, const uint32_t step)
	{
		range_t result(this, offset, step);

		offset += step;
		if (offset >= total_size)
		{
			offset = 0;
		}

		return result;
	}

	range_t range()
	{
		range_t result(this, 0, total_size);
		return result;
	}

protected:
	struct chunk_t
	{
		spinlock_nonrecursive_t locker;
		uint32_t valid_mask;
		struct
		{
			key_t key;
			value_t value;
		} pairs[chunk_size];
	} chunks[total_size / chunk_size];

	inline bool is_valid(const chunk_t& chunk, const uint32_t pair_index) const
	{
		return (chunk.valid_mask >> pair_index) & 1;
	}

	inline bool is_equal(const chunk_t& chunk, const uint32_t pair_index, const key_t& key) const
	{
		return !memcmp(&chunk.pairs[pair_index].key, &key, sizeof(key_t));
	}

	inline bool is_valid_and_equal(const chunk_t& chunk, const uint32_t pair_index, const key_t& key) const
	{
		return is_valid(chunk, pair_index) && is_equal(chunk, pair_index, key);
	}
} __rte_aligned(RTE_CACHE_LINE_SIZE);

//

/// hashtable with spinlocks. multithread allowed. runtime allocation.
///
/// chunk
/// [
///   spinlock | valid_mask
///   key | value   <-- hash == 0
///   key | value   <-- hash == 1
///   key | value   <-- hash == 2
///   key | value   <-- hash == 3 (chunk_size)
/// ]
/// chunk
/// [
///   spinlock | valid_mask
///   key | value   <-- hash == 4
///   key | value   <-- hash == 5
///   key | value   <-- hash == 6
///   key | value   <-- hash == 7
/// ]
/// chunk
/// [
///   spinlock | valid_mask
///   key | value   <-- hash == 8
///   key | value   <-- hash == 9
///   key | value   <-- hash == 10
///   key | value   <-- hash == 11 (total_size)
/// ]
template<typename key_t,
         typename value_t,
         uint32_t chunk_size,
         hash_function_t<key_t> calculate_hash = calculate_hash_crc<key_t>>
class hashtable_mod_spinlock_dynamic
{
public:
	using hashtable_t = hashtable_mod_spinlock_dynamic<key_t, value_t, chunk_size, calculate_hash>;

	constexpr static uint32_t valid_mask_full = 0xFFFFFFFFu >> (32 - chunk_size);
	constexpr static uint64_t keys_in_chunk_size = chunk_size;

	static_assert(__builtin_popcount(chunk_size) == 1);
	static_assert(chunk_size <= 32);

public:
	class iterator_t;
	class range_t;

	class stats_t
	{
	public:
		stats_t()
		{
			memset(this, 0, sizeof(*this));
		}

		uint32_t keys_count;
		std::array<uint32_t, chunk_size + 1> keys_in_chunks;
		uint32_t longest_chain;
	};

	class updater
	{
	public:
		void update_pointer(hashtable_t* hashtable,
		                    const tSocketId socket_id,
		                    const uint32_t total_size)
		{
			this->hashtable = hashtable;
			this->socket_id = socket_id;
			this->total_size = total_size;

			hashtable->total_mask = (total_size / chunk_size) - 1;
			hashtable->total_shift = __builtin_popcount(total_size / chunk_size - 1);
		}

	public:
		range_t range(uint32_t& offset,
		              const uint32_t step)
		{
			range_t result(hashtable, total_size, offset, step);

			offset += step;
			if (offset >= total_size)
			{
				offset = 0;
			}

			return result;
		}

		range_t gc(uint32_t& offset,
		           const uint32_t step)
		{
			range_t result(hashtable, total_size, offset, step);

			/// calculate_stats
			uint32_t from = offset;
			uint32_t to = offset + step;
			for (uint32_t chunk_id = (from / chunk_size) + !!(from % chunk_size);
			     chunk_id < RTE_MIN(to / chunk_size + !!(to % chunk_size),
			                        total_size / chunk_size);
			     chunk_id++)
			{
				const auto& chunk = hashtable->chunks[chunk_id];

				uint32_t pairs_in_chunk = __builtin_popcount(chunk.valid_mask);

				auto& stats_next = stats.next();
				stats_next.keys_count += pairs_in_chunk;
				stats_next.keys_in_chunks[pairs_in_chunk]++;
				stats_next.longest_chain = std::max(stats_next.longest_chain, pairs_in_chunk);
			}

			offset += step;
			if (offset >= total_size)
			{
				stats.switch_generation();
				offset = 0;
			}

			return result;
		}

		stats_t get_stats()
		{
			auto current_guard = stats.current_lock_guard();
			return stats.current();
		}

		template<typename list_T> ///< @todo: common::idp::limits::response
		void limits(list_T& list,
		            const std::string& name) const
		{
			auto current_guard = stats.current_lock_guard();

			list.emplace_back(name + ".keys",
			                  socket_id,
			                  stats.current().keys_count,
			                  total_size);
			list.emplace_back(name + ".longest_collision",
			                  socket_id,
			                  stats.current().longest_chain,
			                  chunk_size);
		}

		template<typename json_t> ///< @todo: nlohmann::json
		void report(json_t& json) const
		{
			auto current_guard = stats.current_lock_guard();

			json["total_size"] = total_size;
			json["keys_count"] = stats.current().keys_count;
			for (unsigned int i = 0;
			     i < stats.current().keys_in_chunks.size();
			     i++)
			{
				json["keys_in_chunks"][i] = stats.current().keys_in_chunks[i];
			}
			json["longest_chain"] = stats.current().longest_chain;
		}

	protected:
		hashtable_t* hashtable;
		tSocketId socket_id;
		uint32_t total_size;
		generation_manager<stats_t> stats;
	};

public:
	static size_t calculate_sizeof(const uint32_t total_size)
	{
		if (!(total_size / chunk_size))
		{
			YANET_LOG_ERROR("wrong total_size: %u\n", total_size);
			return 0;
		}

		if (__builtin_popcount(total_size) != 1)
		{
			YANET_LOG_ERROR("wrong total_size: %u is non power of 2\n", total_size);
			return 0;
		}

		return sizeof(hashtable_t) + (size_t)(total_size / chunk_size) * sizeof(chunk_t);
	}

public:
	inline uint32_t lookup(const key_t& key,
	                       value_t*& value,
	                       spinlock_nonrecursive_t*& locker)
	{
		uint32_t hash = calculate_hash(key);
		auto& chunk = chunks[hash & total_mask];

		value = nullptr;
		locker = &chunk.locker;

		locker->lock();

		const uint32_t pair_index = (hash >> total_shift) & (chunk_size - 1);
		if (is_valid_and_equal(chunk, pair_index, key))
		{
			value = &chunk.pairs[pair_index].value;
			return hash;
		}

		if (chunk_size == 1)
		{
			return hash;
		}

		/// check collision
		uint32_t valid_mask = chunk.valid_mask;
		for (unsigned int try_i = 1;
		     try_i < chunk_size && valid_mask;
		     try_i++)
		{
			const uint32_t pair_index = ((hash >> total_shift) + try_i) & (chunk_size - 1);
			if (is_valid_and_equal(chunk, pair_index, key))
			{
				value = &chunk.pairs[pair_index].value;
				return hash;
			}
			valid_mask &= 0xFFFFFFFFu ^ (1u << pair_index);
		}

		/// not found
		return hash;
	}

	inline bool insert(const uint32_t hash,
	                   const key_t& key,
	                   const value_t& value)
	{
		auto& chunk = chunks[hash & total_mask];

		const uint32_t pair_index = (hash >> total_shift) & (chunk_size - 1);
		if (!is_valid(chunk, pair_index))
		{
			memcpy(&chunk.pairs[pair_index].key, &key, sizeof(key_t));
			memcpy(&chunk.pairs[pair_index].value, &value, sizeof(value_t));
			chunk.valid_mask |= 1u << pair_index;

			return true;
		}
		/* else if (is_equal(chunk, pair_index, key))
		{
		        /// hashtable is broken
		} */

		if (chunk_size == 1)
		{
			return false;
		}

		/// collision
		if (chunk.valid_mask == valid_mask_full)
		{
			/// chunk is full
			return false;
		}

		for (unsigned int try_i = 1;
		     try_i < chunk_size;
		     try_i++)
		{
			const uint32_t pair_index = ((hash >> total_shift) + try_i) & (chunk_size - 1);
			if (!is_valid(chunk, pair_index))
			{
				memcpy(&chunk.pairs[pair_index].key, &key, sizeof(key_t));
				memcpy(&chunk.pairs[pair_index].value, &value, sizeof(value_t));
				chunk.valid_mask |= 1u << pair_index;

				return true;
			}
			/* else if (is_equal(chunk, pair_index, key))
			{
			        /// hashtable is broken
			} */
		}

		/// chunk is full
		return false;
	}

	inline bool insert_or_update(const key_t& key,
	                             const value_t& value)
	{
		bool result = true;

		value_t* ht_value;
		spinlock_nonrecursive_t* locker;

		uint32_t hash = lookup(key, ht_value, locker);
		if (ht_value)
		{
			*ht_value = value;
		}
		else
		{
			result = insert(hash, key, value);
		}

		locker->unlock();
		return result;
	}

	inline void remove(const key_t& key)
	{
		uint32_t hash = calculate_hash(key);
		auto& chunk = chunks[hash & total_mask];

		auto& locker = chunk.locker;
		locker.lock();

		const uint32_t pair_index = (hash >> total_shift) & (chunk_size - 1);
		if (is_valid_and_equal(chunk, pair_index, key))
		{
			chunk.valid_mask ^= 1u << pair_index;
			locker.unlock();
			return;
		}

		if (chunk_size == 1)
		{
			/// not found
			locker.unlock();
			return;
		}

		/// check collision
		uint32_t valid_mask = chunk.valid_mask;
		for (unsigned int try_i = 1;
		     try_i < chunk_size && valid_mask;
		     try_i++)
		{
			const uint32_t pair_index = ((hash >> total_shift) + try_i) & (chunk_size - 1);
			if (is_valid_and_equal(chunk, pair_index, key))
			{
				chunk.valid_mask ^= 1u << pair_index;
				locker.unlock();
				return;
			}
			valid_mask &= 0xFFFFFFFFu ^ (1u << pair_index);
		}

		/// not found
		locker.unlock();
		return;
	}

	void clear()
	{
		for (uint32_t i = 0;
		     i <= total_mask;
		     i++)
		{
			auto& chunk = chunks[i];
			chunk.valid_mask = 0;
		}
	}

public:
	class iterator_t
	{
	public:
		iterator_t(hashtable_t* hashtable,
		           const uint32_t index) :
		        hashtable(hashtable),
		        index(index)
		{
		}

		iterator_t operator++()
		{
			index++;
			return *this;
		}

		bool operator!=(const iterator_t& second) const
		{
			return index != second.index;
		}

		iterator_t& operator*()
		{
			return *this;
		}

	public:
		void lock()
		{
			chunk().locker.lock();
		}

		void unlock()
		{
			chunk().locker.unlock();
		}

		bool is_valid()
		{
			const uint32_t pair_index = index % chunk_size;
			return chunk().valid_mask & (1u << pair_index);
		}

		void unset_valid()
		{
			const uint32_t pair_index = index % chunk_size;
			chunk().valid_mask &= 0xFFFFFFFFu ^ (1u << pair_index);
		}

		const key_t* key()
		{
			const uint32_t pair_index = index % chunk_size;
			return &chunk().pairs[pair_index].key;
		}

		value_t* value()
		{
			const uint32_t pair_index = index % chunk_size;
			return &chunk().pairs[pair_index].value;
		}

		auto& chunk()
		{
			return hashtable->chunks[index / chunk_size];
		}

	protected:
		friend class updater;
		hashtable_t* hashtable;
		uint32_t index;
	};

	class range_t
	{
	public:
		range_t(hashtable_t* hashtable,
		        const uint32_t total_size,
		        const uint32_t offset,
		        const uint32_t step) :
		        hashtable(hashtable),
		        total_size(total_size),
		        offset(offset),
		        step(step)
		{
		}

		iterator_t begin() const
		{
			return {hashtable,
			        RTE_MIN(offset, total_size)};
		}

		iterator_t end() const
		{
			return {hashtable,
			        RTE_MIN(offset + step, total_size)};
		}

	protected:
		hashtable_t* hashtable;
		uint32_t total_size;
		uint32_t offset;
		uint32_t step;
	};

	range_t range(const updater& updater,
	              uint32_t& offset,
	              const uint32_t step)
	{
		range_t result(this, updater.total_size, offset, step);

		offset += step;
		if (offset >= updater.total_size)
		{
			offset = 0;
		}

		return result;
	}

protected:
	uint32_t total_mask;
	uint32_t total_shift;

	struct chunk_t
	{
		spinlock_nonrecursive_t locker;
		uint32_t valid_mask;
		struct
		{
			key_t key;
			value_t value;
		} pairs[chunk_size];
	} chunks[];

	inline bool is_valid(const chunk_t& chunk, const uint32_t pair_index) const
	{
		return (chunk.valid_mask >> pair_index) & 1;
	}

	inline bool is_equal(const chunk_t& chunk, const uint32_t pair_index, const key_t& key) const
	{
		return !memcmp(&chunk.pairs[pair_index].key, &key, sizeof(key_t));
	}

	inline bool is_valid_and_equal(const chunk_t& chunk, const uint32_t pair_index, const key_t& key) const
	{
		return is_valid(chunk, pair_index) && is_equal(chunk, pair_index, key);
	}
};

/// hashtable. only single thread. runtime allocation.
///
/// chunk
/// [
///   valid_mask
///   key | value   <-- hash == 0
///   key | value   <-- hash == 1
///   key | value   <-- hash == 2
///   key | value   <-- hash == 3 (chunk_size)
/// ]
/// chunk
/// [
///   valid_mask
///   key | value   <-- hash == 4
///   key | value   <-- hash == 5
///   key | value   <-- hash == 6
///   key | value   <-- hash == 7
/// ]
/// chunk
/// [
///   valid_mask
///   key | value   <-- hash == 8
///   key | value   <-- hash == 9
///   key | value   <-- hash == 10
///   key | value   <-- hash == 11 (total_size)
/// ]
template<typename key_t,
         typename value_t,
         uint32_t chunk_size,
         hash_function_t<key_t> calculate_hash = calculate_hash_crc<key_t>>
class hashtable_mod_dynamic
{
public:
	using hashtable_t = hashtable_mod_dynamic<key_t, value_t, chunk_size, calculate_hash>;

	constexpr static uint32_t valid_mask_full = 0xFFFFFFFFu >> (32 - chunk_size);
	constexpr static uint64_t keys_in_chunk_size = chunk_size;

	static_assert(__builtin_popcount(chunk_size) == 1);
	static_assert(chunk_size <= 32);

public:
	class iterator_t;
	class range_t;

	class stats_t
	{
	public:
		stats_t()
		{
			memset(this, 0, sizeof(*this));
		}

		uint32_t keys_count;
		std::array<uint32_t, chunk_size + 1> keys_in_chunks;
		uint32_t longest_chain;
	};

	class updater
	{
	public:
		updater() :
		        hashtable(nullptr)
		{
		}

		void update_pointer(hashtable_t* hashtable,
		                    const tSocketId socket_id,
		                    const uint32_t total_size)
		{
			this->hashtable = hashtable;
			this->socket_id = socket_id;
			this->total_size = total_size;

			hashtable->total_mask = (total_size / chunk_size) - 1;
			hashtable->total_shift = __builtin_popcount(total_size / chunk_size - 1);
		}

		hashtable_t* get_pointer()
		{
			return hashtable;
		}

		const hashtable_t* get_pointer() const
		{
			return hashtable;
		}

		range_t range(uint32_t& offset,
		              const uint32_t step)
		{
			range_t result(hashtable, total_size, offset, step);

			offset += step;
			if (offset >= total_size)
			{
				offset = 0;
			}

			return result;
		}

		range_t range(uint32_t& offset,
		              const uint32_t step) const
		{
			range_t result(hashtable, total_size, offset, step);

			offset += step;
			if (offset >= total_size)
			{
				offset = 0;
			}

			return result;
		}

		range_t range()
		{
			return range_t(hashtable, total_size, 0, total_size);
		}

		range_t range() const
		{
			return range_t(hashtable, total_size, 0, total_size);
		}

		range_t gc(uint32_t& offset,
		           const uint32_t step)
		{
			range_t result(hashtable, total_size, offset, step);

			/// calculate_stats
			uint32_t from = offset;
			uint32_t to = offset + step;
			for (uint32_t chunk_id = (from / chunk_size) + !!(from % chunk_size);
			     chunk_id < RTE_MIN(to / chunk_size + !!(to % chunk_size),
			                        total_size / chunk_size);
			     chunk_id++)
			{
				const auto& chunk = hashtable->chunks[chunk_id];

				uint32_t pairs_in_chunk = __builtin_popcount(chunk.valid_mask);

				auto& stats_next = stats.next();
				stats_next.keys_count += pairs_in_chunk;
				stats_next.keys_in_chunks[pairs_in_chunk]++;
				stats_next.longest_chain = std::max(stats_next.longest_chain, pairs_in_chunk);
			}

			offset += step;
			if (offset >= total_size)
			{
				stats.switch_generation();
				offset = 0;
			}

			return result;
		}

		stats_t get_stats()
		{
			auto current_guard = stats.current_lock_guard();
			return stats.current();
		}

		template<typename list_T> ///< @todo: common::idp::limits::response
		void limits(list_T& list,
		            const std::string& name) const
		{
			auto current_guard = stats.current_lock_guard();

			list.emplace_back(name + ".keys",
			                  socket_id,
			                  stats.current().keys_count,
			                  total_size);
			list.emplace_back(name + ".longest_collision",
			                  socket_id,
			                  stats.current().longest_chain,
			                  chunk_size);
		}

		template<typename json_t> ///< @todo: nlohmann::json
		void report(json_t& json) const
		{
			auto current_guard = stats.current_lock_guard();

			json["total_size"] = total_size;
			json["keys_count"] = stats.current().keys_count;
			for (unsigned int i = 0;
			     i < stats.current().keys_in_chunks.size();
			     i++)
			{
				json["keys_in_chunks"][i] = stats.current().keys_in_chunks[i];
			}
			json["longest_chain"] = stats.current().longest_chain;
		}

	protected:
		hashtable_t* hashtable;
		tSocketId socket_id;
		uint32_t total_size;
		generation_manager<stats_t> stats;
	};

public:
	static size_t calculate_sizeof(const uint32_t total_size)
	{
		if (!(total_size / chunk_size))
		{
			YANET_LOG_ERROR("wrong total_size: %u\n", total_size);
			return 0;
		}

		if (__builtin_popcount(total_size) != 1)
		{
			YANET_LOG_ERROR("wrong total_size: %u is non power of 2\n", total_size);
			return 0;
		}

		return sizeof(hashtable_t) + (size_t)(total_size / chunk_size) * sizeof(chunk_t);
	}

public:
	inline uint32_t lookup(const key_t& key,
	                       value_t*& value)
	{
		uint32_t hash = calculate_hash(key);
		auto& chunk = chunks[hash & total_mask];

		value = nullptr;

		const uint32_t pair_index = (hash >> total_shift) & (chunk_size - 1);
		if (is_valid_and_equal(chunk, pair_index, key))
		{
			value = &chunk.pairs[pair_index].value;
			return hash;
		}

		if (chunk_size == 1)
		{
			return hash;
		}

		/// check collision
		uint32_t valid_mask = chunk.valid_mask;
		for (unsigned int try_i = 1;
		     try_i < chunk_size && valid_mask;
		     try_i++)
		{
			const uint32_t pair_index = ((hash >> total_shift) + try_i) & (chunk_size - 1);
			if (is_valid_and_equal(chunk, pair_index, key))
			{
				value = &chunk.pairs[pair_index].value;
				return hash;
			}
			valid_mask &= 0xFFFFFFFFu ^ (1u << pair_index);
		}

		/// not found
		return hash;
	}

	inline uint32_t lookup(const key_t& key,
	                       value_t const*& value) const
	{
		uint32_t hash = calculate_hash(key);
		auto& chunk = chunks[hash & total_mask];

		value = nullptr;

		const uint32_t pair_index = (hash >> total_shift) & (chunk_size - 1);
		if (is_valid_and_equal(chunk, pair_index, key))
		{
			value = &chunk.pairs[pair_index].value;
			return hash;
		}

		if (chunk_size == 1)
		{
			return hash;
		}

		/// check collision
		uint32_t valid_mask = chunk.valid_mask;
		for (unsigned int try_i = 1;
		     try_i < chunk_size && valid_mask;
		     try_i++)
		{
			const uint32_t pair_index = ((hash >> total_shift) + try_i) & (chunk_size - 1);
			if (is_valid_and_equal(chunk, pair_index, key))
			{
				value = &chunk.pairs[pair_index].value;
				return hash;
			}
			valid_mask &= 0xFFFFFFFFu ^ (1u << pair_index);
		}

		/// not found
		return hash;
	}

	inline bool insert(const uint32_t hash,
	                   const key_t& key,
	                   const value_t& value)
	{
		auto& chunk = chunks[hash & total_mask];

		const uint32_t pair_index = (hash >> total_shift) & (chunk_size - 1);
		if (!is_valid(chunk, pair_index))
		{
			memcpy(&chunk.pairs[pair_index].key, &key, sizeof(key_t));
			memcpy(&chunk.pairs[pair_index].value, &value, sizeof(value_t));
			chunk.valid_mask |= 1u << pair_index;

			return true;
		}
		/* else if (is_equal(chunk, pair_index, key))
		{
		        /// hashtable is broken
		} */

		if (chunk_size == 1)
		{
			return false;
		}

		/// collision
		if (chunk.valid_mask == valid_mask_full)
		{
			/// chunk is full
			return false;
		}

		for (unsigned int try_i = 1;
		     try_i < chunk_size;
		     try_i++)
		{
			const uint32_t pair_index = ((hash >> total_shift) + try_i) & (chunk_size - 1);
			if (!is_valid(chunk, pair_index))
			{
				memcpy(&chunk.pairs[pair_index].key, &key, sizeof(key_t));
				memcpy(&chunk.pairs[pair_index].value, &value, sizeof(value_t));
				chunk.valid_mask |= 1u << pair_index;

				return true;
			}
			/* else if (is_equal(chunk, pair_index, key))
			{
			        /// hashtable is broken
			} */
		}

		/// chunk is full
		return false;
	}

	inline bool insert_or_update(const key_t& key,
	                             const value_t& value)
	{
		bool result = true;

		value_t* ht_value;

		uint32_t hash = lookup(key, ht_value);
		if (ht_value)
		{
			*ht_value = value;
		}
		else
		{
			result = insert(hash, key, value);
		}

		return result;
	}

	inline bool remove(const key_t& key)
	{
		uint32_t hash = calculate_hash(key);
		auto& chunk = chunks[hash & total_mask];

		const uint32_t pair_index = (hash >> total_shift) & (chunk_size - 1);
		if (is_valid_and_equal(chunk, pair_index, key))
		{
			chunk.valid_mask ^= 1u << pair_index;
			return true;
		}

		if (chunk_size == 1)
		{
			/// not found
			return false;
		}

		/// check collision
		uint32_t valid_mask = chunk.valid_mask;
		for (unsigned int try_i = 1;
		     try_i < chunk_size && valid_mask;
		     try_i++)
		{
			const uint32_t pair_index = ((hash >> total_shift) + try_i) & (chunk_size - 1);
			if (is_valid_and_equal(chunk, pair_index, key))
			{
				chunk.valid_mask ^= 1u << pair_index;
				return true;
			}
			valid_mask &= 0xFFFFFFFFu ^ (1u << pair_index);
		}

		/// not found
		return false;
	}

	void clear()
	{
		for (uint32_t i = 0;
		     i <= total_mask;
		     i++)
		{
			auto& chunk = chunks[i];
			chunk.valid_mask = 0;
		}
	}

public:
	class iterator_t
	{
	public:
		iterator_t(hashtable_t* hashtable,
		           const uint32_t index) :
		        hashtable(hashtable),
		        index(index)
		{
		}

		iterator_t operator++()
		{
			index++;
			return *this;
		}

		bool operator!=(const iterator_t& second) const
		{
			return index != second.index;
		}

		iterator_t& operator*()
		{
			return *this;
		}

	public:
		bool is_valid()
		{
			const uint32_t pair_index = index % chunk_size;
			return chunk().valid_mask & (1u << pair_index);
		}

		void unset_valid()
		{
			const uint32_t pair_index = index % chunk_size;
			chunk().valid_mask &= 0xFFFFFFFFu ^ (1u << pair_index);
		}

		const key_t* key()
		{
			const uint32_t pair_index = index % chunk_size;
			return &chunk().pairs[pair_index].key;
		}

		value_t* value()
		{
			const uint32_t pair_index = index % chunk_size;
			return &chunk().pairs[pair_index].value;
		}

		auto& chunk()
		{
			return hashtable->chunks[index / chunk_size];
		}

	protected:
		friend class updater;
		hashtable_t* hashtable;
		uint32_t index;
	};

	class range_t
	{
	public:
		range_t(hashtable_t* hashtable,
		        const uint32_t total_size,
		        const uint32_t offset,
		        const uint32_t step) :
		        hashtable(hashtable),
		        total_size(total_size),
		        offset(offset),
		        step(step)
		{
		}

		iterator_t begin() const
		{
			return {hashtable,
			        RTE_MIN(offset, total_size)};
		}

		iterator_t end() const
		{
			return {hashtable,
			        RTE_MIN(offset + step, total_size)};
		}

	protected:
		hashtable_t* hashtable;
		uint32_t total_size;
		uint32_t offset;
		uint32_t step;
	};

	range_t range(const updater& updater,
	              uint32_t& offset,
	              const uint32_t step)
	{
		range_t result(this, updater.total_size, offset, step);

		offset += step;
		if (offset >= updater.total_size)
		{
			offset = 0;
		}

		return result;
	}

protected:
	uint32_t total_mask;
	uint32_t total_shift;

	struct chunk_t
	{
		uint64_t valid_mask;
		struct
		{
			key_t key;
			value_t value;
		} pairs[chunk_size];
	} chunks[];

	inline bool is_valid(const chunk_t& chunk, const uint32_t pair_index) const
	{
		return (chunk.valid_mask >> pair_index) & 1;
	}

	inline bool is_equal(const chunk_t& chunk, const uint32_t pair_index, const key_t& key) const
	{
		return !memcmp(&chunk.pairs[pair_index].key, &key, sizeof(key_t));
	}

	inline bool is_valid_and_equal(const chunk_t& chunk, const uint32_t pair_index, const key_t& key) const
	{
		return is_valid(chunk, pair_index) && is_equal(chunk, pair_index, key);
	}
};

}
