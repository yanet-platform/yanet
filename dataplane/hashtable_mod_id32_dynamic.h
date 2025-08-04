#pragma once

#include <algorithm>
#include <array>
#include <bitset>
#include <cstring>
#include <limits>
#include <tuple>
#include <vector>

#include <rte_prefetch.h>

#include "common/result.h"
#include "hashtable_common.h"

namespace dataplane
{

/**
 * A hash table with a dynamically allocated size, using open addressing
 * and limited linear probing for collision resolution. Key is provided as
 * a template arument, value is an unsigned 32-bit integer.
 *
 * Instead of a single contiguous memory block, it uses an array of pointers to
 * smaller "chunks", making it suitable for very large allocations that would
 * otherwise fail due to memory fragmentation.
 *
 * Uses a single bit from the value to indicate whether a slot is occupied.
 * Collisions are resolved by probing a `chunk_size` amount of subsequent slots
 *
 * @tparam key_t            The type of the keys to be stored.
 * @tparam chunk_size       The number of slots to probe in case of a hash collision.
 * @tparam valid_bit_offset The bit position in the 32-bit value to use as the validity flag
 * @tparam calculate_hash   Function to calculate hash of a key
 */
template<typename key_t,
         uint32_t chunk_size,
         unsigned int valid_bit_offset = 0,
         hash_function_t<key_t> calculate_hash = calculate_hash_crc<key_t>>
class hashtable_mod_id32_dynamic
{
	using value_t = uint32_t;
	static constexpr std::size_t value_bits = std::numeric_limits<value_t>::digits;

	static constexpr bool is_power_of_two(uint32_t n)
	{
		return (n > 0) && ((n & (n - 1)) == 0);
	}

	static_assert(is_power_of_two(chunk_size), "chunk_size must be a power of 2");
	static_assert(valid_bit_offset < value_bits, "valid_bit_offset must be less than 32");

public:
	using hashtable_t = hashtable_mod_id32_dynamic<key_t, chunk_size, valid_bit_offset, calculate_hash>;

	constexpr static uint32_t pairs_size_min = 128;

	struct pair
	{
		key_t key;
		value_t value;
	};

	struct stats_t
	{
		uint32_t pairs_count;
		uint32_t pairs_size;
		std::array<uint32_t, chunk_size + 1> pairs_in_chunks;
		uint32_t longest_chain;
		uint64_t insert_failed;
		uint64_t rewrites;
	};

	/**
	 * Calculates the memory required for the header of the hash table.
	 * The main data is stored in separate chunks.
	 */
	static uint64_t calculate_sizeof(uint32_t pairs_size)
	{
		if (!pairs_size)
		{
			YANET_LOG_ERROR("wrong pairs_size: %u\n", pairs_size);
			return 0;
		}

		if (!is_power_of_two(pairs_size))
		{
			YANET_LOG_ERROR("wrong pairs_size: %u is non power of 2\n", pairs_size);
			return 0;
		}

		return sizeof(hashtable_t);
	}

public:
	/**
	 * Constructs the hash table header. The updater is responsible for allocating
	 * and attaching the memory chunks.
	 *
	 * @param pairs_size Total number of pairs the table can hold. Must be a power of two.
	 * @param pairs_per_chunk_shift Log2 of the number of pairs in each chunk.
	 */
	hashtable_mod_id32_dynamic(const uint32_t pairs_size,
	                           const uint32_t pairs_per_chunk_shift) :
	        total_mask(pairs_size - 1),
	        pairs_size_(pairs_size),
	        ppc_shift_(pairs_per_chunk_shift),
	        ppc_mask_((1u << pairs_per_chunk_shift) - 1),
	        num_chunks_((pairs_size_ + ppc_mask_) >> ppc_shift_),
	        chunks_(nullptr)
	{
	}

	// Called by the updater to link the allocated chunks to this object.
	void attach_chunks(pair** chunks)
	{
		chunks_ = chunks;
	}

	// Accessors for the updater to use during deallocation.
	[[nodiscard]] uint32_t pairs_size() const { return pairs_size_; }
	[[nodiscard]] uint32_t num_chunks() const { return num_chunks_; }
	[[nodiscard]] uint32_t pairs_per_chunk() const { return (1u << ppc_shift_); }
	pair** chunks() const { return chunks_; }

	/**
	 * Performs a batched lookup for multiple keys.
	 *
	 * It processes an array of keys and tries to find their corresponding values.
	 *
	 * The returned values in the `values` array have their validity bit set to 0
	 * on successful lookup and 1 on failure.
	 *
	 * @tparam     burst_size The maximum number of keys to look up in a single call.
	 * @param[out] hashes     An array to store the computed hash for each key.
	 * @param[in]  keys       The array of keys to look up.
	 * @param[out] values     An array where the found values will be stored.
	 * @param[in]  count      The number of keys to process in this batch.
	 *
	 * @return A bitmask indicating which keys were found. A '1' in the i-th bit means success.
	 */
	template<unsigned int burst_size = YANET_CONFIG_BURST_SIZE>
	uint32_t lookup(uint32_t (&hashes)[burst_size],
	                const key_t (&keys)[burst_size],
	                uint32_t (&values)[burst_size],
	                const unsigned int count) const
	{
		// A '1' at bit `i` means success, '0' means not yet found.
		std::bitset<burst_size> success_mask;

		for (unsigned int i = 0; i < count; i++)
		{
			hashes[i] = calculate_hash(keys[i]) & total_mask;
			rte_prefetch0(get_pair_ptr(hashes[i]));
		}

		// Perform the first check at the primary hash location.
		for (unsigned int i = 0; i < count; i++)
		{
			values[i] = get_pair(hashes[i]).value;
			if (is_valid(values[i]) && is_equal(hashes[i], keys[i]))
			{
				success_mask.set(i);
				clear_valid_flag(values[i]);
			}
			else
			{
				set_valid_flag(values[i]);
			}
		}

		// Collistion check not needed
		if constexpr (chunk_size == 1)
		{
			return success_mask.to_ulong();
		}

		// Handle collisions for any lookups that failed the first check.
		if (!success_mask.all())
		{
			for (unsigned int i = 0; i < count; i++)
			{
				// Skip if already found in the primary slot.
				if (success_mask.test(i))
				{
					continue;
				}

				// Linearly probe the next slots in the chunk to find the key.
				for (unsigned int try_i = 1; try_i < chunk_size; try_i++)
				{
					const uint32_t index = (hashes[i] + try_i) & total_mask;
					const value_t probed_value = get_pair(index).value;

					if (!is_valid(probed_value))
					{
						// Stop probing if we find an empty slot, as the key cannot be further.
						break;
					}
					else if (is_equal(index, keys[i]))
					{
						// Key found in a secondary slot.
						values[i] = probed_value;
						clear_valid_flag(values[i]);
						success_mask.set(i);
						break;
					}
				}
			}
		}

		return success_mask.to_ulong();
	}

	/**
	 * Fills the hash table from a vector of key-value pairs and collects stats.
	 *
	 * @param[out] stats A struct to be filled with statistics about the fill operation.
	 * @param[in]  data  A vector of key-value tuples to insert.
	 *
	 * @return eResult::success on success, or an error code if any insertion fails.
	 */
	eResult fill(stats_t& stats, const std::vector<std::tuple<key_t, value_t>>& data)
	{
		eResult result = eResult::success;
		stats = {}; // Zero-initialize stats

		for (const auto& [key, value] : data)
		{
			eResult insert_result = insert(stats, key, value);
			if (insert_result != eResult::success)
			{
				result = insert_result;
			}
		}

		stats.pairs_size = pairs_size_;
		// Calculate statistics on how many pairs are in each chunk.
		for (uint32_t chunk_i = 0; chunk_i < stats.pairs_size / chunk_size; chunk_i++)
		{
			unsigned int count = 0;
			for (uint32_t pair_i = 0; pair_i < chunk_size; pair_i++)
			{
				if (is_valid(get_pair(chunk_i * chunk_size + pair_i).value))
				{
					count++;
				}
			}
			stats.pairs_in_chunks[count]++;
		}

		return result;
	}

	/**
	 * Inserts a single key-value pair into the hash table.
	 *
	 * It linearly probes up to `chunk_size` slots starting from the key's
	 * hash index. It will either find an empty slot to insert into or an
	 * existing entry with the same key to update.
	 *
	 * @param[out] stats Statistics object to update.
	 * @param[in]  key   The key to insert.
	 * @param[in]  value The value to associate with the key.
	 *
	 * @return eResult::success if inserted/updated, or eResult::isFull if no slot was found.
	 */
	eResult insert(stats_t& stats,
	               const key_t& key,
	               const value_t value)
	{
		const uint32_t hash = calculate_hash(key) & total_mask;

		for (unsigned int try_i = 0; try_i < chunk_size; try_i++)
		{
			const uint32_t index = (hash + try_i) & total_mask;
			auto& p = get_pair(index);

			if (!is_valid(p.value))
			{
				p.key = key;
				p.value = value;
				set_valid_flag(p.value);

				stats.pairs_count++;
				stats.longest_chain = std::max(stats.longest_chain, try_i + 1);

				return eResult::success;
			}
			else if (is_equal(index, key))
			{
				p.value = value;
				set_valid_flag(p.value);
				stats.rewrites++;
				return eResult::success;
			}
		}

		// After probing `chunk_size` slots, no space was found.
		stats.insert_failed++;
		return eResult::isFull;
	}

private:
	// Bitmask to wrap around the hash table array using bitwise AND.
	uint32_t total_mask;

	uint32_t pairs_size_;
	uint32_t ppc_shift_; // pairs-per-chunk shift (log2)
	uint32_t ppc_mask_; // pairs-per-chunk mask

	uint32_t num_chunks_;

	// Pointer to an array of pointers, where each element points to a memory chunk.
	pair** chunks_;

	// Get a pointer to a pair at a given logical index.
	[[nodiscard]] struct pair* get_pair_ptr(uint32_t index) const
	{
		const uint32_t chunk_id = index >> ppc_shift_;
		const uint32_t id_in_chunk = index & ppc_mask_;
		return &chunks_[chunk_id][id_in_chunk];
	}

	// Get a reference to a pair at a given logical index.
	[[nodiscard]] struct pair& get_pair(uint32_t index) const
	{
		return *get_pair_ptr(index);
	}

	// Checks if the key at the given index is equal to the provided key.
	[[nodiscard]] constexpr bool is_equal(const uint32_t index, const key_t& key) const
	{
		return get_pair(index).key == key;
	}

	static constexpr value_t validity_mask = 1u << (value_bits - valid_bit_offset - 1);

	[[nodiscard]] constexpr bool is_valid(value_t value) const
	{
		return (value & validity_mask) != 0;
	}

	void set_valid_flag(value_t& value) const
	{
		value |= validity_mask;
	}

	void clear_valid_flag(value_t& value) const
	{
		value &= ~validity_mask;
	}
};

} // namespace dataplane
