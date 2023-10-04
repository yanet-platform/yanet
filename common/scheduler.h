#pragma once

#include "type.h"

namespace balancer
{

enum class scheduler : uint8_t
{
	rr,
	wrr,
	wlc,
};

class scheduler_params
{
public:
	scheduler_params() = default;
	uint32_t wlc_power;
};

YANET_UNUSED
constexpr const char* to_string(const scheduler& scheduler)
{
	switch (scheduler)
	{
		case scheduler::rr:
		{
			return "rr";
		}
		case scheduler::wrr:
		{
			return "wrr";
		}
		case scheduler::wlc:
		{
			return "wlc";
		}
	}

	return "unknown";
}

}
