#pragma once
#include <variant>

#include <inttypes.h>

namespace balancer
{

enum class scheduler : uint8_t
{
	rr,
	wrr,
	wlc,
	chash
};

struct wlc_params
{
	uint32_t wlc_power;
};

struct chash_params
{
	uint32_t siderings_count;
	uint32_t segments_per_weight;
};

using scheduler_params = std::variant<wlc_params, chash_params>;

[[maybe_unused]] constexpr const char* to_string(const scheduler& scheduler)
{
	switch (scheduler)
	{
		case scheduler::rr:
			return "rr";
		case scheduler::wrr:
			return "wrr";
		case scheduler::wlc:
			return "wlc";
		case scheduler::chash:
			return "chash";
		default:
			return "unknown";
	}
}

}
