#pragma once

#include <cctype>
#include <cstdint>
#include <string>

#include "common/type.h"
#include "libfwparser/fw_parser.h"

namespace acl
{

using common::uint128_t;

/// Checks whether the given string is a decimal number.
static inline bool is_dec_number(const std::string& v)
{
	if (v.empty())
	{
		return false;
	}

	return std::all_of(v.begin(), v.end(), [](unsigned char c) {
		return std::isdigit(c);
	});
}

struct network_t
{
	uint8_t family;
	uint128_t addr;
	uint128_t mask;

	network_t(const std::string& string)
	{
		int mask_n = -1;
		const auto pos = string.find('/');
		const auto addr_s = string.substr(0, pos);
		const bool is_ipv4 = addr_s.find(':') == std::string::npos;

		if (pos != std::string::npos)
		{
			const auto mask_s = string.substr(pos + 1);
			if (is_dec_number(mask_s))
			{
				mask_n = std::stol(mask_s, nullptr, 10);

				// Left shifting N-bit unsigned integer by N is UB.
				if (is_ipv4)
				{
					mask = mask_n == 0 ? 0 : (uint32_t)(-1) << (32 - mask_n);
				}
				else
				{
					mask = mask_n == 0 ? 0 : (uint128_t)(-1) << (128 - mask_n);
				}
			}
			else
			{
				if (is_ipv4)
				{
					mask = common::ipv4_address_t(mask_s);
				}
				else
				{
					mask = common::ipv6_address_t(mask_s).getAddress128();
				}
			}
		}
		else
		{
			// Implicit either "/128" or "/32".
			if (is_ipv4)
			{
				mask = (uint32_t)(-1);
			}
			else
			{
				mask = (uint128_t)(-1);
			}
		}

		if (is_ipv4)
		{
			family = 4;
			addr = common::ipv4_address_t(addr_s);
		}
		else
		{
			family = 6;
			addr = common::ipv6_address_t(addr_s).getAddress128();
		}
	}

	network_t(const common::ip_address_t& ip)
	{
		if (ip.is_ipv4())
		{
			family = 4;
			addr = ip.get_ipv4();
			mask = (uint32_t)(-1);
		}
		else
		{
			family = 6;
			addr = ip.get_ipv6().getAddress128();
			mask = (uint128_t)(-1);
		}
	}

	network_t(const common::ipv4_prefix_t& pref) :
	        family(4),
	        addr(pref.address()),
	        mask(pref.mask() == 0 ? 0 : (uint32_t)(-1) << (32 - pref.mask()))
	{
	}

	network_t(const common::ipv6_prefix_t& pref) :
	        family(6),
	        addr(pref.address().getAddress128()),
	        mask(pref.mask() == 0 ? 0 : (uint128_t)(-1) << (128 - pref.mask()))
	{
	}

	network_t(const ipfw::ipv4_prefix_mask_t& pref) :
	        family(4), addr(std::get<0>(pref)), mask(std::get<1>(pref))
	{
	}

	network_t(const ipfw::ipv6_prefix_mask_t& pref) :
	        family(6), addr(std::get<0>(pref).getAddress128()), mask(std::get<1>(pref).getAddress128())
	{
	}

	network_t(const common::ip_prefix_t& pref)
	{
		if (pref.is_ipv4())
		{
			family = 4;
			addr = pref.get_ipv4().address();
			mask = pref.mask() == 0 ? 0 : (uint32_t)(-1) << (32 - pref.mask());
		}
		else
		{
			family = 6;
			addr = pref.get_ipv6().address().getAddress128();
			mask = pref.mask() == 0 ? 0 : (uint128_t)(-1) << (128 - pref.mask());
		}
	}

	network_t(const uint8_t family,
	          const uint128_t addr,
	          const uint128_t mask) :
	        family(family),
	        addr(addr),
	        mask(mask)
	{
	}

	[[nodiscard]] std::string to_string() const
	{
		std::stringstream ret;
		if (family == 4)
		{
			ret << common::ipv4_address_t(addr).toString();
			if (mask != 0)
			{
				ret << "/" << std::hex << common::ipv4_address_t(mask).toString();
			}
		}
		else
		{
			ret << common::ipv6_address_t(addr).toString();
			if (mask != 0)
			{
				ret << "/" << std::hex << common::ipv6_address_t(mask).toString();
			}
		}

		return ret.str();
	}

	bool operator==(const network_t& o) const
	{
		return family == o.family && mask == o.mask && addr == o.addr;
	}

	constexpr bool operator<(const network_t& second) const
	{
		return std::tie(family, mask, addr) < std::tie(second.family, second.mask, second.addr);
	}

	[[nodiscard]] network_t normalize() const
	{
		return {family, addr & mask, mask};
	}
};

} // namespace
