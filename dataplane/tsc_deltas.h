#pragma once

#include <cstdint>
#include <rte_build_config.h>
#include <sys/types.h>

#include "type.h"

namespace dataplane
{

namespace perf
{

struct num_of_workers
{
	uint64_t number;
} __attribute__((__aligned__(64)));

struct tsc_deltas
{
	uint64_t iter_num;
	uint64_t logicalPort_ingress_handle;
	uint64_t acl_ingress_handle4;
	uint64_t acl_ingress_handle6;
	uint64_t tun64_ipv4_handle;
	uint64_t tun64_ipv6_handle;
	uint64_t route_handle4;
	uint64_t route_handle6;

	uint64_t decap_handle;
	uint64_t nat64stateful_lan_handle;
	uint64_t route_tunnel_handle4;
	uint64_t route_tunnel_handle6;
	uint64_t acl_egress_handle4;
	uint64_t acl_egress_handle6;
	uint64_t logicalPort_egress_handle;
	uint64_t controlPlane_handle;
} __attribute__((__aligned__(128)));

static_assert(sizeof(tsc_deltas) <= 2 * RTE_CACHE_LINE_SIZE,
              "too much deltas");
}

}
