#pragma once

#include <cstddef>
#include <cstdint>
#include <rte_build_config.h>

namespace common
{

// Each buffer ring has the following structure:
//
//                _________memory_to_store_the_packets_______________
//               |                                                   |
//               |          __________item_t_________                |
//               |         |                         |               |
// [["b","a",...]({}{}{}...{["s","t",...]............}...........{}{})]
//  |___________|           |___________|____________|
//      ^                           ^                 \__memory[]
//      |                           |
//      |                        item_header_t: "s" -- size
//      |                                       "t" -- tag
//   ring_header_t: "b" -- before              ... -- padding
//                  "a" -- after
//                  ... -- padding
struct PacketBufferRing
{
	PacketBufferRing() = default;

	// static function, helps to get capacity in Raw dump ring
	static size_t GetCapacity(size_t ring_size, size_t item_count, size_t unit_size = 0)
	{
		if (unit_size == 0)
		{
			unit_size = sizeof(item_header_t) + ring_size;

			if (unit_size % RTE_CACHE_LINE_SIZE != 0)
			{
				unit_size += RTE_CACHE_LINE_SIZE - unit_size % RTE_CACHE_LINE_SIZE; /// round up
			}
		}

		size_t capacity = sizeof(ring_header_t) + unit_size * item_count;

		if (capacity % RTE_CACHE_LINE_SIZE != 0)
		{
			capacity += RTE_CACHE_LINE_SIZE - capacity % RTE_CACHE_LINE_SIZE; /// round up
		}

		return capacity;
	}

	PacketBufferRing(void* memory, size_t ring_size, size_t item_count) :
	        unit_size(sizeof(item_header_t) + ring_size), units_number(item_count)
	{
		if (unit_size % RTE_CACHE_LINE_SIZE != 0)
		{
			unit_size += RTE_CACHE_LINE_SIZE - unit_size % RTE_CACHE_LINE_SIZE; /// round up
		}

		capacity = GetCapacity(ring_size, item_count, unit_size);

		ring = (ring_t*)memory;
	}

	struct ring_header_t
	{
		uint64_t before;
		uint64_t after;
	} __attribute__((__aligned__(64)));

	struct ring_t
	{
		ring_header_t header;
		uint8_t memory[];
	};

	struct item_header_t
	{
		uint32_t size;
		uint32_t tag;
		uint32_t in_logicalport_id;
		uint32_t out_logicalport_id;
		uint8_t flow_type;
	} __attribute__((__aligned__(64)));

	struct item_t
	{
		item_header_t header;
		uint8_t memory[];
	};

	size_t unit_size;
	size_t units_number;
	size_t capacity;
	ring_t* ring;
};
}
