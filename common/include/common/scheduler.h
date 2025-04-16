#pragma once

#include <cstdint>
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

[[maybe_unused]] constexpr const char* to_string(const scheduler& scheduler)
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
