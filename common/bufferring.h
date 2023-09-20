#include <inttypes.h>

namespace common
{

// Each buffer ring has the following structure:
//
//				  _________memory_to_store_the_packets_______________
//				 |												 	 |
//				 |		    __________item_t_________				 |
//				 |		   |					 	 |				 |
// [["b","a",...]({}{}{}...{["s","t",...]............}...........{}{})]
//  |___________|			|___________|____________|
//   	 ^						  ^                  \__memory[]
//   	 |						  |
//   	 |					  item_header_t: "s" -- size
//   	 |								  	 "t" -- tag
//   ring_header_t: "b" -- before            ... -- padding
//                  "a" -- after
// 					... -- padding
class bufferring
{
public:
	bufferring()
	{
	}
	bufferring(void* memory, int unit_size, int units_number) :
		unit_size(unit_size),
		units_number(units_number)
	{
		ring = (ring_t*)memory;
	}

    struct ring_header_t
	{
		uint64_t before;
		uint64_t after;
	}__attribute__((__aligned__(64)));

	struct ring_t
	{
		ring_header_t header;
		uint8_t memory[];
	};

	struct item_header_t
	{
		uint32_t size;
		uint32_t tag;
	}__attribute__((__aligned__(64)));

	struct item_t
	{
		item_header_t header;
		uint8_t memory[];
	};

	int unit_size;
	int units_number;
	ring_t* ring;
};

}
