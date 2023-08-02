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

} // namespace
