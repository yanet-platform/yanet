#pragma once

#include <inttypes.h>

namespace balancer
{

enum class forwarding_method : uint8_t
{
	ipip, // in services.conf it means lvs_method: TUN
	gre,
};

constexpr const char* to_string(const forwarding_method& forwarding_method)
{
	switch (forwarding_method)
	{
		case forwarding_method::ipip:
		{
			return "ipip";
		}
		case forwarding_method::gre:
		{
			return "gre";
		}
	}

	return "unknown";
}

}
