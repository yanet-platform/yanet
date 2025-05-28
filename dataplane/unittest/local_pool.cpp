#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <future>
#include <thread>

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

TEST(LocalPoolTest, Benchmark)
{
    common::ipv4_prefix_t prefix("192.168.0.0/24");

    unsigned int concurrent = std::thread::hardware_concurrency();
    if (concurrent == 0)
    {
        concurrent = 8;
    }
    const int samples = 64;
    const int iterations = 8'000'000;
    std::array<std::chrono::duration<double>, samples> allocations;
    std::array<std::chrono::duration<double>, samples> frees;
    std::array<std::future<std::pair<std::chrono::duration<double>, std::chrono::duration<double>>>, 100> futures;
    for (int s = 0; s < samples; s += concurrent)
    {
        for (unsigned int j = s; j < s + concurrent && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::pair<std::chrono::duration<double>, std::chrono::duration<double>> {
                dataplane::proxy::LocalPool pool;
                pool.Add(ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()});
            
                std::vector<std::optional<std::pair<uint32_t, uint16_t>>> addresses(iterations);
                
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    auto local = pool.Allocate(1, 1);
                    addresses[i] = local;
                }
                auto alloc_elapsed = std::chrono::steady_clock::now() - start;
            
                start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    if (addresses[i].has_value())
                        pool.Free(addresses[i]->first, addresses[i]->second);
                }
                auto free_elapsed = std::chrono::steady_clock::now() - start;
            
                pool._TestFree();
    
                return std::make_pair(alloc_elapsed, free_elapsed);
            });
        }
        for (unsigned int i = s; i < s + concurrent && i < samples; i++)
        {
            auto [alloc, free] = futures[i].get();
            allocations[i] = alloc;
            frees[i] = free;
        }
    }

    std::sort(allocations.begin(), allocations.end());
    std::sort(frees.begin(), frees.end());

    std::cout << "Samples: " << samples << " Concurrent: " << concurrent << "\nIterations: " << iterations << "\n";
    std::cout << "Allocate:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[allocations.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[allocations.size() / 2]).count() << "ms\n";
    std::cout << "Free:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[frees.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[frees.size() / 2]).count() << "ms\n";
}

}