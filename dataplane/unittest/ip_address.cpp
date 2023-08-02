#include <gtest/gtest.h>

#include "../src/type.h"

namespace
{

TEST(IpAddress, Basic)
{
	ipv6_address_t zero;
	memset(zero.bytes, 0, std::size(zero.bytes));

	const common::ipv6_address_t commonAddr(std::string("1:2:3:4:5:6:7:8"));

	{
		ipv6_address_t addr = {};

		EXPECT_EQ(addr, zero);
		EXPECT_EQ(addr.empty(), true);
	}

	{
		ipv6_address_t addr = ipv6_address_t::convert(commonAddr);
		ipv6_address_t expected {0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8};
		EXPECT_EQ(addr, expected);

		addr.reset();
		EXPECT_EQ(addr, zero);
	}
}

}
