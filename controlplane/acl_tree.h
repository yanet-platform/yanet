#pragma once

#include <cinttypes>

#include "common/acl.h"

namespace acl::compiler
{

/*
 * prepare_gapped: a000bc00/f000fc00
 *     F        0        0        0        F        C        0        0
 *   a[ ]----->[ ]----->[ ]----->[ ]----->[ ] // first last_multiref chunk
 *    [ ]      [ ]--^   [ ]--^   [ ]--^   [ ]
 *    [ ]      [ ]--^   [ ]--^   [ ]--^   [ ]
 *    [ ]      [ ]--^   [ ]--^   [ ]--^   [ ]
 *
 *                                        [ ] // warp chunk
 *                                        [ ]
 *                                        [ ]
 *                                        [ ]
 *
 * prepare_simple: aff00000/fff00000
 *     F        F        F        0        0        0        0        0
 *   a[ ]----->[ ]----->[ ]----->[ ]----->[ ]
 *    [ ]      [ ]--^   [ ]--^   [ ]--^   [ ]
 *    [ ]      [ ]--^   [ ]--^   [ ]--^   [ ]
 *    [ ]     f[ ]--v   [ ]--^   [ ]--^   [ ]
 *                  v        ^
 *                  --->[ ]--^
 *                      [ ]--^
 *                      [ ]--^
 *                     f[ ]----->[ ]----->[ ] // second last_multiref chunk
 *                               [ ]--^   [ ]
 *                               [ ]--^   [ ]
 *                               [ ]--^   [ ]
 *
 * insert: aff00000/fff00000
 *     F        F        F        0        0        0        0        0
 *   a[ ]----->[ ]----->[ ]----->[ ]----->[ ]
 *    [ ]      [ ]--^   [ ]--^   [ ]--^   [ ]
 *    [ ]      [ ]--^   [ ]--^   [ ]--^   [ ]
 *    [ ]     f[ ]--v   [ ]--^   [ ]--^   [ ]
 *                  v        ^
 *                  --->[ ]--^
 *                      [ ]--^
 *                      [ ]--^
 *                     f[ ]----->[ ]----->[1]
 *                               [ ]--^   [1]
 *                               [ ]--^   [1]
 *                               [ ]--^   [1]
 *
 * insert: afffcbbb:/ffffffff
 *     F        F        F        F        F        F        F        F
 *   a[ ]----->[ ]----->[ ]----->[ ]----->[ ]
 *    [ ]      [ ]--^   [ ]--^   [ ]--^   [ ]
 *    [ ]      [ ]--^   [ ]--^   [ ]--^   [ ]
 *    [ ]     f[ ]--v   [ ]--^   [ ]--^   [ ]
 *                  v        ^
 *                  --->[ ]--^
 *                      [ ]--^
 *                      [ ]--^
 *                     f[ ]----->[ ]----->[1]
 *                               [ ]--^   [1]
 *                               [ ]--^   [1]
 *                              f[ ]--v   [1]
 *                                    v
 *                                    --->[1] // third last_multiref chunk
 *                                        [1]
 *                                       c[ ]--v
 *                                        [1]  v
 *                                             v
 *                                             --->[1]  --->[1]  --->[1]
 *                                                b[ ]--^  b[ ]--^  b[2]
 *                                                 [1]      [1]      [1]
 *                                                 [1]      [1]      [1]
 *
 * insert: a000bc00/f000fc00
 *     F        0        0        0        F        C        0        0
 *                            warp chunk: [ ]  --->[ ]
 *                                       b[ ]--^   [ ]
 *                                        [ ]     c[3]
 *                                        [ ]      [3]
 *
 * merge:
 *    [ ]----->[ ]----->[ ]----->[ ]----->[ ]  --->[ ]
 *    [ ]      [ ]--^   [ ]--^   [ ]--^   [ ]--^   [ ]
 *    [ ]      [ ]--^   [ ]--^   [ ]--^   [ ]      [4]
 *    [ ]      [ ]--v   [ ]--^   [ ]--^   [ ]      [4]
 *                  v        ^
 *                  --->[ ]--^
 *                      [ ]--^
 *                      [ ]--^
 *                      [ ]----->[ ]----->[1]  --->[1]
 *                               [ ]--^   [ ]--^   [1]
 *                               [ ]--^   [1]      [5]
 *                               [ ]--v   [1]      [5]
 *                                    v
 *                                    --->[1]  --->[1]
 *                                        [ ]--^   [1]
 *                                        [ ]--v   [5]
 *                                        [1]  v   [5]
 *                                             v
 *                                             --->[1]  --->[1]  --->[1]
 *                                                 [ ]--^   [ ]--^   [2]
 *                                                 [1]      [1]      [1]
 *                                                 [1]      [1]      [1]
 */

template<typename type_t,
         unsigned int bits = 8>
class tree_t
{
	static_assert(bits >= 1);
	static_assert(bits < 32);

	constexpr static unsigned int root_chunk_id = 0;
	constexpr static uint32_t bits_mask = 0xFFFFFFFFu >> (32 - bits);

public:
	tree_t(const unsigned int chunks_bucket_size = YANET_CONFIG_ACL_TREE_CHUNKS_BUCKET_SIZE) :
	        chunks_bucket_size(chunks_bucket_size)
	{
		clear();
	}

	void clear()
	{
		chunks.clear();
		chunks.reserve(chunks_bucket_size);
		chunks.emplace_back(); ///< root_chunk
		prefixes.clear();
		intersection_prefixes.clear();
		saved_group_ids.clear();
		multirefs_chunk_ids.clear();
		warp_chunk_ids.clear();
		merge_group_id = 0;
		merge_warp_extended_chunk_ids.clear();
		merge_remap_chunks.clear();
	}

	/*
	 * not supported:
	 *  - double gapped mask (like ffff:0000:ff00:ffff:ff00::)
	 *  - gapped mask, where last part not 8bit aligned (like ffff:003f:ff00::)
	 *  - two gapped mask, where last part start not with the same shift (like 2222:0000:2200::/ffff:0000:ff00::
	 *                                                                         2222:0000:2200::/ffff:00ff:ff00::)
	 */
	void collect(const type_t& address,
	             const type_t& mask)
	{
		unsigned int gap_size = 0; ///< need for correct sorting gapped prefixes
		if (is_mask_gapped(mask))
		{
			type_t warp_mask = mask | (mask - 1);
			gap_size = common::popcount_u128(warp_mask); ///< actually not gapped bits
		}

		auto it = prefixes.find(std::tie(gap_size, address, mask));
		if (it == prefixes.end())
		{
			prefixes.emplace_hint(it, std::tie(gap_size, address, mask));
		}
	}

	void prepare()
	{
		for (const auto& [gap_size, address, mask] : prefixes)
		{
			(void)gap_size;

			if (is_mask_gapped(mask))
			{
				reserve_chunks();
				prepare_gapped(address, mask);
			}
		}

		for (const auto& [gap_size, address, mask] : prefixes)
		{
			(void)gap_size;

			if (!is_mask_gapped(mask))
			{
				reserve_chunks();
				prepare_simple(address, mask);
			}
		}
	}

	void insert(const type_t& address,
	            const type_t& mask,
	            tAclGroupId& group_id,
	            std::vector<tAclGroupId>& remap_group_ids)
	{
		if (is_mask_gapped(mask))
		{
			/// mask:             ffff:ff00:0000:ffff:0000
			/// mask - 1:         ffff:ff00:0000:fffe:ffff
			/// warp_mask:        ffff:ff00:0000:ffff:ffff
			/// warp_mask + 1:    ffff:ff00:0001:0000:0000
			/// warp_shadow_mask: ffff:ff00:0000:0000:0000

			type_t warp_mask = mask | (mask - 1);
			type_t warp_shadow_mask = warp_mask & (warp_mask + 1);
			type_t warp_address = address & warp_shadow_mask;

			auto it = warp_chunk_ids.find(std::tie(warp_address, warp_mask));
			if (it == warp_chunk_ids.end())
			{
				auto it = intersection_prefixes.find(std::tie(warp_address, warp_mask));
				if (it == intersection_prefixes.end())
				{
					throw std::runtime_error("prefix " + to_string(address, mask) + " not prepared");
				}

				{
					insert(address & warp_shadow_mask,
					       warp_shadow_mask,
					       group_id,
					       remap_group_ids);
				}

				{
					insert(address & it->second,
					       mask & it->second,
					       group_id,
					       remap_group_ids);
				}
			}
			else
			{
				const auto& [shift, warp_chunk_id] = it->second;

				reserve_chunks();
				insert_step(address << shift,
				            mask << shift,
				            group_id,
				            remap_group_ids,
				            warp_chunk_id);
			}
		}
		else
		{
			reserve_chunks();
			insert_step(address,
			            mask,
			            group_id,
			            remap_group_ids,
			            root_chunk_id);
		}
	}

	/*
	 *  warp  origin    result
	 *  G  N   G  N      G  N
	 * [-  -] [-  -] -> [-  -]
	 * [-  -] [-  Y] -> [-  Y]
	 * [-  -] [B  -] -> [B  -]
	 *
	 * [-  X] [-  -] -> [-  Q]
	 * [-  X] [-  Y] -> [-  Q]
	 * [-  X] [B  -] -> [-  Q]
	 *
	 * [A  -] [-  -] -> [C  -]
	 * [A  -] [-  Y] -> [-  Z]
	 * [A  -] [B  -] -> [D  -]
	 */
	void merge(tAclGroupId& group_id)
	{
		for (const auto& [map_key, map_value] : warp_chunk_ids)
		{
			const auto& [warp_address, warp_mask] = map_key;
			const auto& [shift, warp_chunk_id] = map_value;
			(void)shift;

			std::set<unsigned int> last_multirefs_chunk_ids;
			get_last_gapped_chunks_step(warp_address, warp_mask, last_multirefs_chunk_ids, root_chunk_id);

			YANET_LOG_DEBUG("acl::network: last_multirefs: %lu\n", last_multirefs_chunk_ids.size());

			for (const auto& chunk_id : last_multirefs_chunk_ids)
			{
				merge_group_id = group_id;

				reserve_chunks();
				merge_chunk(warp_chunk_id, chunk_id, group_id);
			}

			multirefs_chunk_ids.emplace(map_key, std::move(last_multirefs_chunk_ids));
		}
	}

	//TODO: занимает всё время в network_t::populate
	void get(const type_t& address,
	         const type_t& mask,
	         std::vector<uint8_t>& group_ids_bitmask) ///< @todo: static_bitmask_t
	{
		auto it = saved_group_ids.find(std::tie(address, mask));
		if (it == saved_group_ids.end())
		{
			std::vector<uint8_t> bitmask;
			bitmask.resize(group_ids_bitmask.size(), 0);

			if (is_mask_gapped(mask))
			{
				type_t warp_mask = mask | (mask - 1);
				type_t warp_shadow_mask = warp_mask & (warp_mask + 1);
				type_t warp_address = address & warp_shadow_mask;

				auto it = multirefs_chunk_ids.find(std::tie(warp_address, warp_mask));
				if (it == multirefs_chunk_ids.end())
				{
					auto it = intersection_prefixes.find(std::tie(warp_address, warp_mask));
					if (it == intersection_prefixes.end())
					{
						throw std::runtime_error("prefix " + to_string(address, mask) + " not merged");
					}

					std::vector<uint8_t> bitmask1;
					std::vector<uint8_t> bitmask2;
					bitmask1.resize(group_ids_bitmask.size(), 0);
					bitmask2.resize(group_ids_bitmask.size(), 0);

					{
						get(address & warp_shadow_mask,
						    warp_shadow_mask,
						    bitmask1);
					}

					{
						get(address & it->second,
						    mask & it->second,
						    bitmask2);
					}

					for (unsigned int i = 0;
					     i < group_ids_bitmask.size();
					     i++)
					{
						bitmask[i] = bitmask1[i] & bitmask2[i];
					}
				}
				else
				{
					unsigned int shift = common::popcount_u128(warp_mask) - common::popcount_u128(warp_shadow_mask);
					shift = 8 * sizeof(type_t) - shift;

					for (const auto& chunk_id : it->second)
					{
						get_step(address << shift,
						         mask << shift,
						         bitmask,
						         chunk_id);
					}
				}
			}
			else
			{
				get_step(address,
				         mask,
				         bitmask,
				         root_chunk_id);
			}

			for (unsigned int i = 0;
			     i < group_ids_bitmask.size();
			     i++)
			{
				group_ids_bitmask[i] |= bitmask[i];
			}

			saved_group_ids.emplace_hint(it, std::tie(address, mask), bitmask);
		}
		else
		{
			for (unsigned int i = 0;
			     i < group_ids_bitmask.size();
			     i++)
			{
				group_ids_bitmask[i] |= it->second[i];
			}
		}
	}

	tAclGroupId lookup(const type_t& address)
	{
		return lookup_step(address,
		                   root_chunk_id);
	}

	void remap(const std::vector<tAclGroupId>& remap_group_ids)
	{
		std::set<unsigned int> prev_chunk_ids; ///< @todo: vector, bitmask?
		remap_chunk(root_chunk_id, remap_group_ids, prev_chunk_ids);
	}

public:
	unsigned int chunks_bucket_size;

	std::vector<common::acl::tree_chunk_t<bits>> chunks;

	std::set<std::tuple<unsigned int, ///< gap_size
	                    type_t,
	                    type_t>>
	        prefixes;
	std::map<std::tuple<type_t, type_t>,
	         type_t>
	        intersection_prefixes;

	std::map<std::tuple<type_t, type_t>,
	         std::vector<uint8_t>>
	        saved_group_ids;
	std::map<std::tuple<type_t, type_t>,
	         std::set<unsigned int>>
	        multirefs_chunk_ids;

	std::map<std::tuple<type_t, type_t>,
	         std::tuple<unsigned int, ///< shift
	                    unsigned int>>
	        warp_chunk_ids;

	unsigned int merge_group_id; ///< only for check
	std::map<common::acl::tree_value_t, unsigned int> merge_warp_extended_chunk_ids;
	std::map<std::tuple<common::acl::tree_value_t, ///< left
	                    common::acl::tree_value_t>, ///< right
	         common::acl::tree_value_t>
	        merge_remap_chunks;

protected:
	inline static bool is_mask_gapped(const type_t& mask)
	{
		return (mask | (mask - 1)) + 1;
	}

	inline static std::string to_string(const type_t& address,
	                                    const type_t& mask)
	{
		std::string result;

		if constexpr (std::is_same_v<type_t, uint32_t>)
		{
			result = common::ipv4_address_t(address).toString();
			result += "/";
			result += std::to_string(__builtin_popcount(mask));
		}
		else if constexpr (std::is_same_v<type_t, common::uint128_t>)
		{
			result = common::ipv6_address_t(address).toString();
			result += "/";
			if (is_mask_gapped(mask))
			{
				result += common::ipv6_address_t(mask).toString();
			}
			else
			{
				result += std::to_string(common::popcount_u128(mask));
			}
		}

		return result;
	}

	void reserve_chunks()
	{
		if (chunks.capacity() - chunks.size() < chunks_bucket_size)
		{
			YANET_LOG_DEBUG("acl::network: reserve chunks (free: %lu): %lu -> %lu\n",
			                chunks.capacity() - chunks.size(),
			                chunks.capacity(),
			                chunks.capacity() + chunks_bucket_size);
			chunks.reserve(chunks.capacity() + chunks_bucket_size);
		}
	}

	inline unsigned int allocate_chunk()
	{
		if (chunks.size() == chunks.capacity())
		{
			throw std::runtime_error("not enough chunks");
		}

		unsigned int new_chunk_id = chunks.size();
		chunks.emplace_back();

		return new_chunk_id;
	}

	void prepare_gapped(const type_t& address,
	                    const type_t& mask)
	{
		/// @todo: check mask

		type_t warp_mask = mask | (mask - 1);
		type_t warp_shadow_mask = warp_mask & (warp_mask + 1);
		type_t warp_address = address & warp_shadow_mask;

		auto it = warp_chunk_ids.find(std::tie(warp_address, warp_mask));
		if (it == warp_chunk_ids.end())
		{
			if ((((warp_shadow_mask - 1) | warp_shadow_mask) + 1) != 0)
			{
				throw std::runtime_error("unsupported gapped masks (double gapped)");
			}

			unsigned int shift = common::popcount_u128(warp_mask) - common::popcount_u128(warp_shadow_mask);
			shift = 8 * sizeof(type_t) - shift;

			if (shift % 8 != 0)
			{
				throw std::runtime_error("unsupported gapped masks (last part not 8bit aligned)");
			}

			for (const auto& [key, value] : warp_chunk_ids)
			{
				const auto& [prev_address, prev_mask] = key;
				const auto& [prev_shift, prev_warp_chunk_id] = value;
				(void)prev_warp_chunk_id;

				type_t shared_shadow_mask = warp_shadow_mask & (prev_mask & (prev_mask + 1));

				if ((warp_address & shared_shadow_mask) == (prev_address & shared_shadow_mask))
				{
					if (prev_shift != shift)
					{
						/// example:
						/// ffff:0000:0000:ffff:ffff::
						/// &
						/// ffff:ffff:0000:0000:ffff::
						///
						/// or:
						/// ffff:0000:0000:0000:ffff::
						/// &
						/// ffff:0000:0000:ffff:ffff::
						throw std::runtime_error("unsupported gapped masks");
					}

					auto it = intersection_prefixes.find(std::tie(warp_address, warp_mask));
					if (it == intersection_prefixes.end())
					{
						YANET_LOG_DEBUG("acl::network: prepare intersection: %s\n", to_string(warp_address, warp_mask).data());

						/// for prepare_simple
						prefixes.emplace(0, warp_address, warp_shadow_mask);

						intersection_prefixes.emplace_hint(it, std::tie(warp_address, warp_mask), prev_mask);
					}

					return;
				}
			}

			YANET_LOG_DEBUG("acl::network: prepare gapped: %s\n", to_string(warp_address, warp_mask).data());

			unsigned int warp_chunk_id = 0;
			prepare_gapped_step(warp_address, warp_mask, root_chunk_id, warp_chunk_id);

			if (!warp_chunk_id)
			{
				throw std::runtime_error("internal error (no warp_chunk_id)");
			}

			warp_chunk_ids.emplace_hint(it, std::tie(warp_address, warp_mask), std::tie(shift, warp_chunk_id));
		}
	}

	void prepare_simple(const type_t& address,
	                    const type_t& mask)
	{
		for (const auto& [map_key, map_value] : warp_chunk_ids)
		{
			const auto& [warp_address, warp_mask] = map_key;
			const auto& [shift, warp_chunk_id] = map_value;

			(void)shift;
			(void)warp_chunk_id;

			type_t warp_shadow_mask = warp_mask & (warp_mask + 1);

			if (common::popcount_u128(mask) > common::popcount_u128(warp_shadow_mask) &&
			    common::popcount_u128(mask) <= shift &&
			    (address & warp_shadow_mask) == warp_address)
			{
				YANET_LOG_DEBUG("acl::network: prepare simple: %s\n", to_string(address, mask).data());
				prepare_simple_step(address, mask, warp_mask, root_chunk_id);
			}
		}
	}

	void prepare_gapped_step(const type_t& address,
	                         const type_t& mask,
	                         const unsigned int chunk_id,
	                         unsigned int& warp_chunk_id)
	{
		auto& chunk = chunks[chunk_id];

		uint32_t step_mask = (mask >> (sizeof(type_t) * 8 - bits)) & bits_mask;
		uint32_t step_address = (address >> (sizeof(type_t) * 8 - bits)) & step_mask;
		type_t next_mask = mask << bits;

		if (!is_mask_gapped(mask))
		{
			warp_chunk_id = allocate_chunk();
			return;
		}
		else
		{
			if (step_mask == bits_mask)
			{
				auto& chunk_value = chunk.values[step_address];

				if (!chunk_value.is_chunk_id())
				{
					chunk_value.set_chunk_id(allocate_chunk());
				}

				prepare_gapped_step(address << bits,
				                    next_mask,
				                    chunk_value.get_chunk_id(),
				                    warp_chunk_id);
			}
			else
			{
				/// allocate gapped chunk

				const auto new_chunk_id = allocate_chunk();
				auto& new_chunk = chunks[new_chunk_id];
				new_chunk.is_multirefs = 1;

				for (uint32_t i = 0;
				     i <= ((~step_mask) & bits_mask);
				     i++)
				{
					auto& chunk_value = chunk.values[step_address + i];

					if (chunk_value.is_chunk_id())
					{
						throw std::runtime_error("internal error (is chunk_id)");
					}
					else
					{
						chunk_value.set_chunk_id(new_chunk_id);
					}
				}

				prepare_gapped_step(address << bits,
				                    next_mask,
				                    new_chunk_id,
				                    warp_chunk_id);
			}
		}
	}

	void prepare_simple_step(const type_t& address,
	                         const type_t& mask,
	                         const type_t& warp_mask,
	                         const unsigned int chunk_id)
	{
		auto& chunk = chunks[chunk_id];

		uint32_t step_mask = (mask >> (sizeof(type_t) * 8 - bits)) & bits_mask;
		uint32_t step_address = (address >> (sizeof(type_t) * 8 - bits)) & step_mask;
		type_t next_mask = mask << bits;

		if (!is_mask_gapped(warp_mask))
		{
			return;
		}
		else
		{
			if (step_mask == bits_mask)
			{
				auto& chunk_value = chunk.values[step_address];

				if (chunk_value.is_chunk_id())
				{
					auto& next_chunk = chunks[chunk_value.get_chunk_id()];

					if (next_chunk.is_multirefs)
					{
						const auto new_chunk_id = allocate_chunk();

						{
							auto& new_chunk = chunks[new_chunk_id];

							new_chunk = next_chunk;
							new_chunk.is_multirefs = 0;
						}

						chunk_value.set_chunk_id(new_chunk_id);
					}
				}
				else
				{
					throw std::runtime_error("internal error (is not chunk_id)");
				}

				prepare_simple_step(address << bits,
				                    next_mask,
				                    warp_mask << bits,
				                    chunk_value.get_chunk_id());
			}
			else
			{
				/// allocate gapped chunk

				const auto new_chunk_id = allocate_chunk();
				auto& new_chunk = chunks[new_chunk_id];
				new_chunk.is_multirefs = 1;

				for (uint32_t i = 0;
				     i <= ((~step_mask) & bits_mask);
				     i++)
				{
					auto& chunk_value = chunk.values[step_address + i];

					if (chunk_value.is_chunk_id())
					{
						auto& next_chunk = chunks[chunk_value.get_chunk_id()];

						if (next_chunk.is_multirefs)
						{
							chunk_value.set_chunk_id(new_chunk_id);
						}
					}
					else
					{
						chunk_value.set_chunk_id(new_chunk_id);
					}
				}

				prepare_simple_step(address << bits,
				                    next_mask,
				                    warp_mask << bits,
				                    new_chunk_id);
			}
		}
	}

	void insert_step(const type_t& address,
	                 const type_t& mask,
	                 tAclGroupId& group_id,
	                 std::vector<tAclGroupId>& remap_group_ids,
	                 const unsigned int chunk_id)
	{
		auto& chunk = chunks[chunk_id];

		uint32_t step_mask = (mask >> (sizeof(type_t) * 8 - bits)) & bits_mask;
		uint32_t step_address = (address >> (sizeof(type_t) * 8 - bits)) & step_mask;
		type_t next_mask = mask << bits;

		/* -------mask-------
		 *  stepmask nextmask
		 * [11111111]11111111 <-- next_mask  --> insert_step_next
		 * [11111111]11110000 <-- next_mask  --> insert_step_next
		 * [11111111]00000000 <-- !next_mask --> insert_step_last
		 * [11110000]00000000 <-- !next_mask --> insert_step_last
		 */
		if (next_mask)
		{
			/// insert_step_next

			auto& chunk_value = chunk.values[step_address];

			if (!chunk_value.is_chunk_id())
			{
				const auto new_chunk_id = allocate_chunk();

				if (chunk_value.get_group_id())
				{
					auto& new_chunk = chunks[new_chunk_id];

					for (uint32_t i = 0;
					     i <= bits_mask;
					     i++)
					{
						new_chunk.values[i].set_group_id(chunk_value.get_group_id());
					}
				}

				chunk_value.set_chunk_id(new_chunk_id);
			}
			else
			{
				auto& next_chunk = chunks[chunk_value.get_chunk_id()];

				if (next_chunk.is_multirefs)
				{
					const auto new_chunk_id = allocate_chunk();

					{
						auto& new_chunk = chunks[new_chunk_id];
						new_chunk = next_chunk;
						new_chunk.is_multirefs = 0;
					}

					chunk_value.set_chunk_id(new_chunk_id);
				}
			}

			insert_step(address << bits,
			            next_mask,
			            group_id,
			            remap_group_ids,
			            chunk_value.get_chunk_id());
		}
		else
		{
			/// insert_step_last

			std::set<unsigned int> prev_chunk_ids; ///< @todo: vector, bitmask?

			for (uint32_t i = 0;
			     i <= ((~step_mask) & bits_mask);
			     i++)
			{
				auto& chunk_value = chunk.values[step_address + i];

				if (chunk_value.is_chunk_id())
				{
					auto& next_chunk = chunks[chunk_value.get_chunk_id()];

					if (next_chunk.is_multirefs)
					{
						const auto new_chunk_id = allocate_chunk();

						{
							auto& new_chunk = chunks[new_chunk_id];
							new_chunk = next_chunk;
							new_chunk.is_multirefs = 0;
						}

						chunk_value.set_chunk_id(new_chunk_id);
					}
				}

				update_group_id_next(group_id,
				                     remap_group_ids,
				                     chunk_value,
				                     prev_chunk_ids);
			}
		}
	}

	void update_group_id_next(tAclGroupId& group_id,
	                          std::vector<tAclGroupId>& remap_group_ids,
	                          common::acl::tree_value_t& chunk_value,
	                          std::set<unsigned int>& prev_chunk_ids)
	{
		if (chunk_value.is_chunk_id())
		{
			auto it = prev_chunk_ids.find(chunk_value.get_chunk_id());
			if (it == prev_chunk_ids.end())
			{
				auto& next_chunk = chunks[chunk_value.get_chunk_id()];

				for (uint32_t i = 0;
				     i <= bits_mask;
				     i++)
				{
					auto& next_chunk_value = next_chunk.values[i];
					update_group_id_next(group_id, remap_group_ids, next_chunk_value, prev_chunk_ids);
				}

				prev_chunk_ids.emplace_hint(it, chunk_value.get_chunk_id());
			}
		}
		else
		{
			if (chunk_value.get_group_id() < remap_group_ids.size()) ///< check: don't override self rule
			{
				auto& step_remap = remap_group_ids[chunk_value.get_group_id()];
				if (!step_remap)
				{
					step_remap = group_id;
					group_id++;
				}

				chunk_value.set_group_id(step_remap);
			}
			else
			{
				/// dont panic. this is fine
			}
		}
	}

	void get_last_gapped_chunks_step(const type_t& address,
	                                 const type_t& mask,
	                                 std::set<unsigned int>& last_gapped_chunks,
	                                 const unsigned int chunk_id)
	{
		auto& chunk = chunks[chunk_id];

		uint32_t step_mask = (mask >> (sizeof(type_t) * 8 - bits)) & bits_mask;
		uint32_t step_address = (address >> (sizeof(type_t) * 8 - bits)) & step_mask;
		type_t next_mask = mask << bits;

		if (!is_mask_gapped(mask))
		{
			last_gapped_chunks.emplace(chunk_id);
		}
		else
		{
			std::set<unsigned int> prev_chunk_ids; ///< @todo: vector, bitmask?

			for (uint32_t i = 0;
			     i <= ((~step_mask) & bits_mask);
			     i++)
			{
				auto& chunk_value = chunk.values[step_address + i];

				if (chunk_value.is_chunk_id())
				{
					auto it = prev_chunk_ids.find(chunk_value.get_chunk_id());
					if (it == prev_chunk_ids.end())
					{
						get_last_gapped_chunks_step(address << bits,
						                            next_mask,
						                            last_gapped_chunks,
						                            chunk_value.get_chunk_id());
						prev_chunk_ids.emplace_hint(it, chunk_value.get_chunk_id());
					}
				}
				else
				{
					throw std::runtime_error("internal error (is not chunk_id)");
				}
			}
		}
	}

	void merge_chunk(unsigned int warp_chunk_id,
	                 unsigned int origin_chunk_id,
	                 tAclGroupId& group_id)
	{
		const auto& warp_chunk = chunks[warp_chunk_id];
		auto& origin_chunk = chunks[origin_chunk_id];

		for (uint32_t i = 0;
		     i <= bits_mask;
		     i++)
		{
			const auto& warp_chunk_value = warp_chunk.values[i];
			auto& origin_chunk_value = origin_chunk.values[i];

			if (warp_chunk_value.is_empty())
			{
			}
			else if (warp_chunk_value.is_chunk_id())
			{
				auto map_key = std::make_tuple(warp_chunk_value, origin_chunk_value);

				auto it = merge_remap_chunks.find(map_key);
				if (it == merge_remap_chunks.end())
				{
					if (origin_chunk_value.is_chunk_id())
					{
						merge_chunk(warp_chunk_value.get_chunk_id(), origin_chunk_value.get_chunk_id(), group_id);
					}
					else
					{
						const auto new_chunk_id = allocate_chunk();

						{
							auto& new_chunk = chunks[new_chunk_id];

							for (uint32_t i = 0;
							     i <= bits_mask;
							     i++)
							{
								new_chunk.values[i].set_group_id(origin_chunk_value.get_group_id());
							}
						}

						origin_chunk_value.set_chunk_id(new_chunk_id);

						merge_chunk(warp_chunk_value.get_chunk_id(), origin_chunk_value.get_chunk_id(), group_id);
					}

					merge_remap_chunks.emplace_hint(it, map_key, origin_chunk_value);
				}
				else
				{
					origin_chunk_value = it->second;
				}
			}
			else
			{
				auto map_key = std::make_tuple(warp_chunk_value, origin_chunk_value);

				auto it = merge_remap_chunks.find(map_key);
				if (it == merge_remap_chunks.end())
				{
					if (origin_chunk_value.is_chunk_id())
					{
						auto it = merge_warp_extended_chunk_ids.find(warp_chunk_value);
						if (it == merge_warp_extended_chunk_ids.end())
						{
							const auto new_chunk_id = allocate_chunk();

							{
								auto& new_chunk = chunks[new_chunk_id];

								for (uint32_t i = 0;
								     i <= bits_mask;
								     i++)
								{
									new_chunk.values[i].set_group_id(warp_chunk_value.get_group_id());
								}
							}

							it = merge_warp_extended_chunk_ids.emplace_hint(it, warp_chunk_value, new_chunk_id);
						}

						merge_chunk(it->second, origin_chunk_value.get_chunk_id(), group_id);
					}
					else
					{
						if (origin_chunk_value.get_group_id() >= merge_group_id)
						{
							throw std::runtime_error("internal error (unknown error)");
						}

						origin_chunk_value.set_group_id(group_id);
						group_id++;
					}

					merge_remap_chunks.emplace_hint(it, map_key, origin_chunk_value);
				}
				else
				{
					origin_chunk_value = it->second;
				}
			}
		}
	}

	void get_step(const type_t& address,
	              const type_t& mask,
	              std::vector<uint8_t>& group_ids_bitmask,
	              const unsigned int chunk_id)
	{
		auto& chunk = chunks[chunk_id];

		uint32_t step_mask = (mask >> (sizeof(type_t) * 8 - bits)) & bits_mask;
		uint32_t step_address = (address >> (sizeof(type_t) * 8 - bits)) & step_mask;
		type_t next_mask = mask << bits;

		/* -------mask-------
		 *  stepmask nextmask
		 * [11111111]11111100 <-- !is_mask_gapped(mask) && next_mask  --> get_step_next
		 * [11111111]00000000 <-- !is_mask_gapped(mask) && !next_mask --> get_step_last
		 * [11110000]00000000 <-- !is_mask_gapped(mask) && !next_mask --> get_step_last
		 * [11110000]11111100 <-- is_mask_gapped(mask)  && next_mask  --> get_step_gapped
		 * [00000000]11111100 <-- is_mask_gapped(mask)  && next_mask  --> get_step_gapped
		 */
		if (!is_mask_gapped(mask))
		{
			if (next_mask)
			{
				/// get_step_next

				auto& chunk_value = chunk.values[step_address];

				if (!chunk_value.is_chunk_id())
				{
					group_ids_bitmask[chunk_value.get_group_id()] = 1;
					return;
				}

				get_step(address << bits,
				         next_mask,
				         group_ids_bitmask,
				         chunk_value.get_chunk_id());
			}
			else
			{
				/// get_step_last

				std::set<unsigned int> prev_chunk_ids; ///< @todo: vector, bitmask?

				for (uint32_t i = 0;
				     i <= ((~step_mask) & bits_mask);
				     i++)
				{
					auto& chunk_value = chunk.values[step_address + i];
					get_group_id_next(group_ids_bitmask, chunk_value, prev_chunk_ids);
				}
			}
		}
		else
		{
			/// get_step_gapped

			std::set<unsigned int> prev_chunk_ids; ///< @todo: vector, bitmask?

			for (uint32_t i = 0;
			     i <= ((~step_mask) & bits_mask);
			     i++)
			{
				auto& chunk_value = chunk.values[step_address + i];

				if (chunk_value.is_chunk_id())
				{
					auto it = prev_chunk_ids.find(chunk_value.get_chunk_id());
					if (it == prev_chunk_ids.end())
					{
						get_step(address << bits,
						         next_mask,
						         group_ids_bitmask,
						         chunk_value.get_chunk_id());
						prev_chunk_ids.emplace_hint(it, chunk_value.get_chunk_id());
					}
				}
				else
				{
					throw std::runtime_error("internal error (is not chunk_id)");
				}
			}
		}
	}

	void get_group_id_next(std::vector<uint8_t>& group_ids_bitmask,
	                       common::acl::tree_value_t& chunk_value,
	                       std::set<unsigned int>& prev_chunk_ids)
	{
		if (chunk_value.is_chunk_id())
		{
			auto it = prev_chunk_ids.find(chunk_value.get_chunk_id());
			if (it == prev_chunk_ids.end())
			{
				auto& next_chunk = chunks[chunk_value.get_chunk_id()];

				for (uint32_t i = 0;
				     i <= bits_mask;
				     i++)
				{
					auto& next_chunk_value = next_chunk.values[i];
					get_group_id_next(group_ids_bitmask, next_chunk_value, prev_chunk_ids);
				}

				prev_chunk_ids.emplace_hint(it, chunk_value.get_chunk_id());
			}
		}
		else
		{
			group_ids_bitmask[chunk_value.get_group_id()] = 1;
		}
	}

	tAclGroupId lookup_step(const type_t& address,
	                        const unsigned int chunk_id) const
	{
		const auto& chunk = chunks[chunk_id];

		uint32_t step_address = (address >> (sizeof(type_t) * 8 - bits)) & bits_mask;

		auto& chunk_value = chunk.values[step_address];
		if (chunk_value.is_chunk_id())
		{
			return lookup_step(address << bits, chunk_value.get_chunk_id());
		}

		return chunk_value.get_group_id();
	}

	void remap_chunk(const unsigned int chunk_id,
	                 const std::vector<tAclGroupId>& remap_group_ids,
	                 std::set<unsigned int>& prev_chunk_ids)
	{
		auto& chunk = chunks[chunk_id];

		std::set<unsigned int> next_chunk_ids;

		for (uint32_t i = 0;
		     i <= bits_mask;
		     i++)
		{
			auto& chunk_value = chunk.values[i];

			if (chunk_value.is_chunk_id())
			{
				auto it = prev_chunk_ids.find(chunk_value.get_chunk_id());
				if (it == prev_chunk_ids.end())
				{
					next_chunk_ids.emplace(chunk_value.get_chunk_id());
					prev_chunk_ids.emplace_hint(it, chunk_value.get_chunk_id());
				}
			}
			else
			{
				chunk_value.set_group_id(remap_group_ids[chunk_value.get_group_id()]);
			}
		}

		for (const auto& next_chunk_id : next_chunk_ids)
		{
			remap_chunk(next_chunk_id, remap_group_ids, prev_chunk_ids);
		}
	}
};

}
