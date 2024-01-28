#pragma once

#include <climits>
#include <cstdint>
#include <rte_branch_prediction.h>
#include <rte_build_config.h>
#include <rte_cycles.h>
#include <sys/types.h>
#include <x86intrin.h>

#include "common/define.h"

#define YANET_TSC_BINS_SHIFT 2
#define YANET_TSC_BINS_N 4

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
	uint16_t logicalPort_ingress_handle[YANET_TSC_BINS_N];
	uint16_t acl_ingress_handle4[YANET_TSC_BINS_N];
	uint16_t acl_ingress_handle6[YANET_TSC_BINS_N];
	uint16_t tun64_ipv4_handle[YANET_TSC_BINS_N];
	uint16_t tun64_ipv6_handle[YANET_TSC_BINS_N];
	uint16_t route_handle4[YANET_TSC_BINS_N];
	uint16_t route_handle6[YANET_TSC_BINS_N];

	uint16_t decap_handle[YANET_TSC_BINS_N];
	uint16_t nat64stateful_lan_handle[YANET_TSC_BINS_N];
	uint16_t nat64stateful_wan_handle[YANET_TSC_BINS_N];
	uint16_t nat64stateless_egress_handle[YANET_TSC_BINS_N];
	uint16_t nat64stateless_ingress_handle[YANET_TSC_BINS_N];
	uint16_t balancer_handle[YANET_TSC_BINS_N];
	uint16_t balancer_icmp_reply_handle[YANET_TSC_BINS_N];
	uint16_t balancer_icmp_forward_handle[YANET_TSC_BINS_N];

	uint16_t route_tunnel_handle4[YANET_TSC_BINS_N];
	uint16_t route_tunnel_handle6[YANET_TSC_BINS_N];
	uint16_t acl_egress_handle4[YANET_TSC_BINS_N];
	uint16_t acl_egress_handle6[YANET_TSC_BINS_N];
	uint16_t logicalPort_egress_handle[YANET_TSC_BINS_N];
	uint16_t controlPlane_handle[YANET_TSC_BINS_N];

	YANET_ALWAYS_INLINE void write(uint64_t& tsc_start, uint32_t stack_size, uint16_t bins[YANET_TSC_BINS_N], uint32_t base)
	{
		if (!tsc_start || unlikely(stack_size == 0))
		{
			return;
		}

		auto tsc_end = rte_get_tsc_cycles();
		auto shifted_delta = (int64_t)((tsc_end - tsc_start) / stack_size) - base;

		if (shifted_delta > 0)
		{
			int floor_log_4 = (sizeof(uint64_t) * CHAR_BIT - _lzcnt_u64(shifted_delta) - 1) >> 1;
			int bin_idx = std::min(std::max(floor_log_4 - YANET_TSC_BINS_SHIFT, 0), 4 - 1);
			bins[bin_idx]++;
		}
		else
		{
			bins[0]++;
		}

		tsc_start = tsc_end;
	}

} __attribute__((__aligned__(2 * RTE_CACHE_LINE_SIZE)));

static_assert(sizeof(tsc_deltas) <= 8 * RTE_CACHE_LINE_SIZE,
              "too many deltas");

static_assert(std::is_pod_v<tsc_deltas> == true,
              "tsc structure is not pod");

}

}
