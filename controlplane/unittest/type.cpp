#include <gtest/gtest.h>

#include "common/type.h"

namespace
{

using common::ipv6_address_t;

TEST(ipv6_address_t, is_multicast)
{
	EXPECT_TRUE(ipv6_address_t("ff00::").is_multicast());
	EXPECT_TRUE(ipv6_address_t("ff00::1").is_multicast());

	EXPECT_FALSE(ipv6_address_t("fe00::1").is_multicast());
	EXPECT_FALSE(ipv6_address_t("::ffff:c00a:2ff").is_multicast());
}

TEST(ipv6_address_t, from_bytes_rejects_short_address)
{
	EXPECT_FALSE(ipv6_address_t::from_bytes(std::string(4, '\0')));
}

TEST(ipv6_address_t, from_bytes_copies_address)
{
	const ipv6_address_t address("2001:db8::1");
	const std::array<uint8_t, 16>& bytes = address;
	EXPECT_EQ(ipv6_address_t::from_bytes(std::string(bytes.begin(), bytes.end())), address);
}

} // namespace
