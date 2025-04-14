#pragma once

#include "type.h"

namespace balancer
{

enum class service_counter : tCounterId
{
	packets,
	bytes,
	real_disabled_packets,
	real_disabled_bytes,
	size
};

enum class real_counter : tCounterId
{
	packets,
	bytes,
	sessions_created,
	sessions_destroyed,
	size
};

using gc_real_counter = real_counter;

}

namespace nat64stateful
{

enum class module_counter : tCounterId
{
	lan_packets,
	lan_bytes,
	wan_packets,
	wan_bytes,
	pool_is_empty,
	tries_array_start,
	tries_array_end = tries_array_start + YANET_CONFIG_NAT64STATEFUL_INSERT_TRIES - 1,
	tries_failed,
	wan_state_not_found,
	wan_state_insert,
	wan_state_insert_failed = wan_state_insert,
	wan_state_insert_success,
	wan_state_cross_numa_insert,
	wan_state_cross_numa_insert_failed = wan_state_cross_numa_insert,
	wan_state_cross_numa_insert_success,
	lan_state_insert,
	lan_state_insert_failed = lan_state_insert,
	lan_state_insert_success,
	lan_state_cross_numa_insert,
	lan_state_cross_numa_insert_failed = lan_state_cross_numa_insert,
	lan_state_cross_numa_insert_success,
	size
};

}
