#include <gtest/gtest.h>

#include "../local_pool.h"

namespace {
TEST(LocalPoolTest, Allocate)
{
    dataplane::proxy::LocalPool pool;

    EXPECT_EQ(pool.Allocate(1, 1), std::nullopt);

    common::ipv4_prefix_t prefix("192.168.0.0/24");
    uint32_t ip1 = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.1")).address;
    pool.Add(1, ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()});
    EXPECT_EQ(pool.Allocate(1, 1), std::make_pair(ip1, rte_cpu_to_be_16((uint16_t)1025)));
    EXPECT_EQ(pool.Allocate(1, 1), std::make_pair(ip1, rte_cpu_to_be_16((uint16_t)1026)));
    EXPECT_EQ(pool.Allocate(2, 1), std::make_pair(ip1, rte_cpu_to_be_16((uint16_t)1027)));

    EXPECT_EQ(pool.Allocate(1, 2), std::make_pair(ip1, rte_cpu_to_be_16((uint16_t)1025)));

    common::ipv4_prefix_t prefix2("192.168.1.0/30");
    uint32_t ip2 = ipv4_address_t::convert(common::ipv4_address_t("192.168.1.2")).address;
    pool.Add(2, ipv4_prefix_t{ipv4_address_t{prefix2.address()}, prefix2.mask()});
    for(uint16_t i = 1025; i < UINT16_MAX; i++) {pool.Allocate(2, 3);}
    EXPECT_EQ(pool.Allocate(2, 3), std::make_pair(ip2, rte_cpu_to_be_16((uint16_t)1025)));
    EXPECT_EQ(pool.Allocate(2, 3), std::make_pair(ip2, rte_cpu_to_be_16((uint16_t)1026)));

    for(uint16_t i = 1025; i < UINT16_MAX-2; i++) {pool.Allocate(2, 3);}
    EXPECT_EQ(pool.Allocate(2, 3), std::nullopt);

    pool.Free(3, rte_be_to_cpu_32(ip2), 1337);
    EXPECT_EQ(pool.Allocate(2, 3), std::make_pair(ip2, rte_cpu_to_be_16((uint16_t)1337)));
}

}