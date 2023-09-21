#pragma once

#include "type.h"

namespace balancer
{

enum class tunnel : uint8_t
{
	ipip,  // in services.conf it means lvs_method: TUN
	gre,
};

constexpr const char* to_string(const tunnel& tunnel)
{
	switch (tunnel)
	{
		case tunnel::ipip:
		{
			return "ipip";
		}
		case tunnel::gre:
		{
			return "gre";
		}
	}

	return "unknown";
}

}
