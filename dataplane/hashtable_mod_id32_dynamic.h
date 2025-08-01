#pragma once

#include "common/result.h"
#include "hashtable_common.h"

namespace dataplane
{

// Used by transport_table, total_table
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

}
