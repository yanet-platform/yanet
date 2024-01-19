#pragma once

#include <climits>
#include <cmath>
#include <cstdint>
#include <rte_build_config.h>
#include <sys/types.h>
#include <x86intrin.h>

#define YANET_TSC_BINS_SHIFT 4

namespace dataplane
{

namespace perf
{

struct tsc_base_values
{
	uint32_t logicalPort_ingress_handle = 18;
	uint32_t acl_ingress_handle4 = 0;
	uint32_t acl_ingress_handle6 = 124;
	uint32_t tun64_ipv4_handle = 0;
	uint32_t tun64_ipv6_handle = 0;
	uint32_t route_handle4 = 0;
	uint32_t route_handle6 = 81;
	uint32_t decap_handle = 0;

	uint32_t nat64stateful_lan_handle = 0;
	uint32_t nat64stateful_wan_handle = 0;
	uint32_t nat64stateless_egress_handle = 0;
	uint32_t nat64stateless_ingress_handle = 0;
	uint32_t balancer_handle = 259;
	uint32_t balancer_icmp_reply_handle = 0;
	uint32_t balancer_icmp_forward_handle = 0;
	uint32_t route_tunnel_handle4 = 0;

	uint32_t route_tunnel_handle6 = 0;
	uint32_t acl_egress_handle4 = 0;
	uint32_t acl_egress_handle6 = 0;
	uint32_t logicalPort_egress_handle = 0;
	uint32_t controlPlane_handle = 0;
} __attribute__((__aligned__(2 * RTE_CACHE_LINE_SIZE)));

struct tsc_deltas
{
	uint64_t iter_num;
	uint16_t logicalPort_ingress_handle[4];
	uint16_t acl_ingress_handle4[4];
	uint16_t acl_ingress_handle6[4];
	uint16_t tun64_ipv4_handle[4];
	uint16_t tun64_ipv6_handle[4];
	uint16_t route_handle4[4];
	uint16_t route_handle6[4];

	uint16_t decap_handle[4];
	uint16_t nat64stateful_lan_handle[4];
	uint16_t nat64stateful_wan_handle[4];
	uint16_t nat64stateless_egress_handle[4];
	uint16_t nat64stateless_ingress_handle[4];
	uint16_t balancer_handle[4];
	uint16_t balancer_icmp_reply_handle[4];
	uint16_t balancer_icmp_forward_handle[4];

	uint16_t route_tunnel_handle4[4];
	uint16_t route_tunnel_handle6[4];
	uint16_t acl_egress_handle4[4];
	uint16_t acl_egress_handle6[4];
	uint16_t logicalPort_egress_handle[4];
	uint16_t controlPlane_handle[4];
} __attribute__((__aligned__(2 * RTE_CACHE_LINE_SIZE)));

static_assert(sizeof(tsc_deltas) <= 4 * RTE_CACHE_LINE_SIZE,
              "too much deltas");

inline void write_to_hist(uint64_t counter, uint16_t bins[4], uint32_t base)
{
	int64_t cnt = (int64_t)counter - base;
	if (cnt > 0)
	{
		int floor_log_2 = sizeof(uint64_t) * CHAR_BIT - _lzcnt_u64(cnt) - 1;
		int bin_idx = std::min(std::max(floor_log_2 - YANET_TSC_BINS_SHIFT, 0), 4 - 1);
		bins[bin_idx]++;
	}
}

}

}
