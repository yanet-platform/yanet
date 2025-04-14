#pragma once

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <rte_branch_prediction.h>
#include <rte_build_config.h>
#include <rte_cycles.h>
#include <sys/types.h>
#include <x86intrin.h>

#include "common/define.h"

constexpr auto YANET_TSC_BINS_SHIFT = 2;
constexpr auto YANET_TSC_BINS_N = 4;

namespace dataplane::perf
{

using CountersArray = std::array<uint16_t, YANET_TSC_BINS_N>;

struct alignas(2 * RTE_CACHE_LINE_SIZE) tsc_base_values
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
	uint32_t nat46clat_lan_handle = 0;
	uint32_t nat46clat_wan_handle = 0;
	uint32_t balancer_handle = 259;
	uint32_t balancer_icmp_reply_handle = 0;

	uint32_t balancer_icmp_forward_handle = 0;
	uint32_t route_tunnel_handle4 = 0;
	uint32_t route_tunnel_handle6 = 0;
	uint32_t acl_egress_handle4 = 0;
	uint32_t acl_egress_handle6 = 0;
	uint32_t logicalPort_egress_handle = 0;
	uint32_t controlPlane_handle = 0;
};

struct alignas(2 * RTE_CACHE_LINE_SIZE) tsc_deltas
{
	uint64_t iter_num;
	CountersArray logicalPort_ingress_handle{};

	CountersArray acl_ingress_handle4{};
	CountersArray acl_ingress_handle6{};
	CountersArray tun64_ipv4_handle{};
	CountersArray tun64_ipv6_handle{};
	CountersArray route_handle4{};
	CountersArray route_handle6{};

	CountersArray decap_handle{};
	CountersArray nat64stateful_lan_handle{};
	CountersArray nat64stateful_wan_handle{};
	CountersArray nat64stateless_egress_handle{};
	CountersArray nat64stateless_ingress_handle{};
	CountersArray nat46clat_lan_handle{};
	CountersArray nat46clat_wan_handle{};
	CountersArray balancer_handle{};

	CountersArray balancer_icmp_reply_handle{};
	CountersArray balancer_icmp_forward_handle{};
	CountersArray route_tunnel_handle4{};
	CountersArray route_tunnel_handle6{};
	CountersArray acl_egress_handle4{};
	CountersArray acl_egress_handle6{};
	CountersArray logicalPort_egress_handle{};

	CountersArray controlPlane_handle{};

	YANET_ALWAYS_INLINE void write(uint64_t& tsc_start, uint32_t stack_size, CountersArray& bins, uint32_t base)
	{
		if (!tsc_start || unlikely(stack_size == 0))
		{
			return;
		}

		auto tsc_end = rte_get_tsc_cycles();
		auto shifted_delta = static_cast<int64_t>((tsc_end - tsc_start) / stack_size) - base;

		if (shifted_delta > 0)
		{
			uint16_t floor_log_4 = (sizeof(uint64_t) * CHAR_BIT - _lzcnt_u64(shifted_delta) - 1) >> 1;
			uint16_t bin_idx = std::clamp(floor_log_4 - YANET_TSC_BINS_SHIFT, 0, YANET_TSC_BINS_N - 1);
			bins[bin_idx]++;
		}
		else
		{
			bins[0]++;
		}

		tsc_start = tsc_end;
	}

	[[nodiscard]] auto as_tuple() const
	{
		return std::tie(logicalPort_ingress_handle,
		                acl_ingress_handle4,
		                acl_ingress_handle6,
		                tun64_ipv4_handle,
		                tun64_ipv6_handle,
		                route_handle4,
		                route_handle6,
		                decap_handle,
		                nat64stateful_lan_handle,
		                nat64stateful_wan_handle,
		                nat64stateless_egress_handle,
		                nat64stateless_ingress_handle,
		                nat46clat_lan_handle,
		                nat46clat_wan_handle,
		                balancer_handle,
		                balancer_icmp_reply_handle,
		                balancer_icmp_forward_handle,
		                route_tunnel_handle4,
		                route_tunnel_handle6,
		                acl_egress_handle4,
		                acl_egress_handle6,
		                logicalPort_egress_handle,
		                controlPlane_handle);
	}
};

static_assert(sizeof(tsc_deltas) <= 8 * RTE_CACHE_LINE_SIZE, "tsc_deltas size exceeds cache line size");
static_assert(std::is_trivially_copyable<tsc_deltas>::value, "tsc_deltas should be trivially copyable");
static_assert(std::is_standard_layout<tsc_deltas>::value, "tsc_deltas should have a standard layout");
}
