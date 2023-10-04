#pragma once

#include <arpa/inet.h>
#include <memory.h>

#include <array>
#include <map>
#include <string>
#include <tuple>
#include <variant>

#include "common/define.h"

template<unsigned int TIndex,
         typename TTuple>
inline int64_t getDiff(const TTuple& curr,
                       const TTuple& prev)
{
	return std::get<TIndex>(curr) - std::get<TIndex>(prev);
}

static inline uint32_t applyMask(const uint32_t& ipAddress,
                                 const uint8_t& mask)
{
	if (mask == 0)
	{
		return 0;
	}

	return ipAddress & (0xFFFFFFFFu << (32u - mask));
}

static inline std::array<uint8_t, 16> applyMask(const std::array<uint8_t, 16>& ipv6Address,
                                                const uint8_t& mask)
{
	std::array<uint8_t, 16> result;

	uint8_t stepMask = mask;
	for (unsigned int step = 0;
	     step < 4;
	     step++)
	{
		uint32_t& from = *(((uint32_t*)ipv6Address.data()) + step);
		uint32_t& to = *(((uint32_t*)result.data()) + step);

		if (stepMask > 32)
		{
			to = from;

			stepMask -= 32;
		}
		else if (stepMask > 0)
		{
			to = applyMask(ntohl(from), stepMask);
			to = htonl(to);

			stepMask = 0;
		}
		else
		{
			to = 0;
		}
	}

	return result;
}

inline bool equal(const std::array<uint8_t, 6>& first, const std::array<uint8_t, 6>& second)
{
	return !memcmp(first.data(), second.data(), 6);
}
