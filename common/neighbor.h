#pragma once

#include <inttypes.h>

namespace common::neighbor
{

struct stats
{
	uint64_t hashtable_insert_success;
	uint64_t hashtable_insert_error;
	uint64_t hashtable_remove_success;
	uint64_t hashtable_remove_error;
	uint64_t netlink_neighbor_update;
	uint64_t resolve;
};

}
