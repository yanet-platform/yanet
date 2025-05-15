#include <gtest/gtest.h>

#include "../local_pool.h"

namespace {
TEST(LocalPoolTest, Allocate)
{
    common::ipv4_prefix_t prefix("192.168.0.0/30");
    dataplane::proxy::LocalPool pool;
    pool.Add(ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()});
    pool._TestInit();

    uint32_t client_addr = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.1")).address;
    tPortId client_port = 12345;

    uint32_t ip = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.1")).address;
    EXPECT_EQ(pool.Allocate(client_addr, client_port), std::make_pair(ip, rte_cpu_to_be_16((uint16_t)1025)));
    EXPECT_EQ(pool.Allocate(client_addr, client_port), std::make_pair(ip, rte_cpu_to_be_16((uint16_t)1026)));
    EXPECT_EQ(pool.Allocate(client_addr, client_port), std::make_pair(ip, rte_cpu_to_be_16((uint16_t)1027)));
    EXPECT_EQ(pool.FindClientByLocal(ip, rte_cpu_to_be_16(1025)), std::make_pair(client_addr, client_port));

    uint32_t ip2 = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.2")).address;
    for(uint32_t i = 1025+3; i <= UINT16_MAX; i++) {pool.Allocate(client_addr, client_port);}
    EXPECT_EQ(pool.Allocate(client_addr, client_port), std::make_pair(ip2, rte_cpu_to_be_16((uint16_t)1025)));
    EXPECT_EQ(pool.Allocate(client_addr, client_port), std::make_pair(ip2, rte_cpu_to_be_16((uint16_t)1026)));
    EXPECT_EQ(pool.Allocate(client_addr, client_port), std::make_pair(ip2, rte_cpu_to_be_16((uint16_t)1027)));

    for(uint32_t i = 1025+3; i <= UINT16_MAX; i++) {pool.Allocate(client_addr, client_port);}
    EXPECT_EQ(pool.Allocate(client_addr, client_port), std::nullopt);

    pool.Free(ip, rte_cpu_to_be_16(1337));
    EXPECT_EQ(pool.FindClientByLocal(ip, rte_cpu_to_be_16(1337)), std::nullopt);
    EXPECT_EQ(pool.Allocate(client_addr, client_port), std::make_pair(ip, rte_cpu_to_be_16((uint16_t)1337)));

    pool._TestFree();
};

}