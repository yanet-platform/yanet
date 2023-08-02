#include <gtest/gtest.h>

#include "../src/acl/network.h"

namespace
{

using acl::network_t;
using common::uint128_t;
using namespace common::literals;

TEST(network_t, IPv4)
{
	const network_t net("0.0.0.0");

	EXPECT_EQ(4, net.family);
	EXPECT_EQ(0, net.addr);
	EXPECT_EQ(0xffffffff, net.mask);
}

TEST(network_t, IPv4Mask)
{
	const network_t net("10.0.0.0/24");

	EXPECT_EQ(4, net.family);
	EXPECT_EQ(0x0a000000, net.addr);
	EXPECT_EQ(0xffffff00, net.mask);
}

TEST(network_t, IPv4MaskExt)
{
	const network_t net("10.0.0.0/255.255.255.0");

	EXPECT_EQ(4, net.family);
	EXPECT_EQ(0x0a000000, net.addr);
	EXPECT_EQ(0xffffff00, net.mask);
}

TEST(network_t, IPv6)
{
	const network_t net("::");

	EXPECT_EQ(6, net.family);
	EXPECT_EQ(0x00000000000000000000000000000000_uint128_t, net.addr);
	EXPECT_EQ(0xffffffffffffffffffffffffffffffff_uint128_t, net.mask);
}

TEST(network_t, IPv6Mask)
{
	const network_t net("2300::/112");

	EXPECT_EQ(6, net.family);
	EXPECT_EQ(0x23000000000000000000000000000000_uint128_t, net.addr);
	EXPECT_EQ(0xffffffffffffffffffffffffffff0000_uint128_t, net.mask);
}

TEST(network_t, IPv6MaskExt)
{
	const network_t net("2300::/ffff:ffff:ffff:ffff:ffff:ffff:ffff::");

	EXPECT_EQ(6, net.family);
	EXPECT_EQ(0x23000000000000000000000000000000_uint128_t, net.addr);
	EXPECT_EQ(0xffffffffffffffffffffffffffff0000_uint128_t, net.mask);
}

TEST(network_t, IPv6MaskGapped)
{
	const network_t net("1111:2222:3333:0:aaaa:bbbb::/ffff:ffff:ffff:0000:ffff:ffff::");

	EXPECT_EQ(6, net.family);
	EXPECT_EQ(0x1111222233330000aaaabbbb00000000_uint128_t, net.addr);
	EXPECT_EQ(0xffffffffffff0000ffffffff00000000_uint128_t, net.mask);
}

TEST(network_t, IPWithoutMaskAfterSlash)
{
	EXPECT_THROW(network_t("1.2.3.4/"), std::string); // todo: WUT? Make normal exception type.
	EXPECT_THROW(network_t("::1/"), std::string);
}

} // namespace
