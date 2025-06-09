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
    pool._TestInit(ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()});

    uint32_t client_addr = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.1")).address;
    tPortId client_port = 12345;

    uint32_t ip = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.1")).address;
    uint64_t expect = dataplane::proxy::LocalPool::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32768));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = dataplane::proxy::LocalPool::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32769));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = dataplane::proxy::LocalPool2::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32770));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    EXPECT_EQ(pool.FindClientByLocal(ip, rte_cpu_to_be_16(32768)),
              dataplane::proxy::LocalPool::PackTuple(client_addr, client_port));

    uint32_t ip2 = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.2")).address;
    for(uint32_t i = dataplane::proxy::LocalPool::min_port+3; i <= UINT16_MAX; i++) {pool.Allocate(0, client_addr, client_port);}
    expect = dataplane::proxy::LocalPool::PackTuple(ip2, rte_cpu_to_be_16((uint16_t)32768));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = dataplane::proxy::LocalPool::PackTuple(ip2, rte_cpu_to_be_16((uint16_t)32769));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = dataplane::proxy::LocalPool::PackTuple(ip2, rte_cpu_to_be_16((uint16_t)32770));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);

    for(uint32_t i = dataplane::proxy::LocalPool::min_port+3; i <= UINT16_MAX; i++) {pool.Allocate(0, client_addr, client_port);}
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), 0);

    pool.Free(0, dataplane::proxy::LocalPool::PackTuple(ip, rte_cpu_to_be_16(33333)));
    EXPECT_EQ(pool.FindClientByLocal(ip, rte_cpu_to_be_16(33333)), 0);
    expect = dataplane::proxy::LocalPool::PackTuple(ip, rte_cpu_to_be_16((uint16_t)33333));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);

    pool._TestFree();
};

TEST(LocalPool2Test, Allocate)
{
    common::ipv4_prefix_t prefix("192.168.0.0/30");
    dataplane::proxy::LocalPool2 pool;
    pool._TestInit(ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()});

    uint32_t client_addr = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.1")).address;
    tPortId client_port = 12345;

    uint32_t ip = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.1")).address;
    uint64_t expect = dataplane::proxy::LocalPool2::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32768));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = dataplane::proxy::LocalPool2::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32769));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = dataplane::proxy::LocalPool2::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32770));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    EXPECT_EQ(pool.FindClientByLocal(ip, rte_cpu_to_be_16(32768)), 
              dataplane::proxy::LocalPool2::PackTuple(client_addr, client_port));

    uint32_t ip2 = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.2")).address;
    for(uint32_t i = dataplane::proxy::LocalPool2::min_port+3; i <= UINT16_MAX; i++) {pool.Allocate(0, client_addr, client_port);}
    expect = dataplane::proxy::LocalPool2::PackTuple(ip2, rte_cpu_to_be_16((uint16_t)32768));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = dataplane::proxy::LocalPool2::PackTuple(ip2, rte_cpu_to_be_16((uint16_t)32769));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = dataplane::proxy::LocalPool2::PackTuple(ip2, rte_cpu_to_be_16((uint16_t)32770));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);

    for(uint32_t i = dataplane::proxy::LocalPool2::min_port+3; i <= UINT16_MAX; i++) {pool.Allocate(0, client_addr, client_port);}
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), 0);

    pool.Free(0, dataplane::proxy::LocalPool2::PackTuple(ip, rte_cpu_to_be_16(33333)));
    EXPECT_EQ(pool.FindClientByLocal(ip, rte_cpu_to_be_16(33333)), 0);
    for(uint32_t i = 1; i < dataplane::proxy::LocalPool2::chunk_size; i++)
        pool.Free(0, dataplane::proxy::LocalPool2::PackTuple(ip, rte_cpu_to_be_16(33333+i)));
    expect = dataplane::proxy::LocalPool2::PackTuple(ip, rte_cpu_to_be_16(33333));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);

    pool._TestFree();
};

TEST(LocalPoolTest, Benchmark)
{
    common::ipv4_prefix_t prefix("192.168.0.0/24");

    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    const int samples = 64;
    const int iterations = 8'000'000;

    std::array<std::chrono::duration<double>, samples> allocations;
    std::array<std::chrono::duration<double>, samples> finds;
    std::array<std::chrono::duration<double>, samples> frees;
    std::array<std::future<std::tuple<std::chrono::duration<double>, 
                                      std::chrono::duration<double>,
                                      std::chrono::duration<double>>>, samples> futures;
    for (int s = 0; s < samples; s += concurrency)
    {
        for (unsigned int j = s; j < s + concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::tuple<std::chrono::duration<double>, 
                                                                            std::chrono::duration<double>,
                                                                            std::chrono::duration<double>> {
                dataplane::proxy::LocalPool pool;
                pool._TestInit(ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()});
            
                std::vector<uint64_t> addresses(iterations);
                
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    addresses[i] = pool.Allocate(0, 1, 1);
                }
                auto alloc_elapsed = std::chrono::steady_clock::now() - start;
            
                start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    if (addresses[i])
                    {
                        uint32_t addr;
                        tPortId port;
                        dataplane::proxy::LocalPool::UnpackTuple(addresses[i], addr, port);
                        pool.FindClientByLocal(addr, port);
                    }
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;

                start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    if (addresses[i])
                        pool.Free(0, addresses[i]);
                }
                auto free_elapsed = std::chrono::steady_clock::now() - start;
            
                pool._TestFree();
    
                return std::make_tuple(alloc_elapsed, find_elapsed, free_elapsed);
            });
        }
        for (unsigned int i = s; i < s + concurrency && i < samples; i++)
        {
            auto [alloc, find, free] = futures[i].get();
            allocations[i] = alloc;
            finds[i] = find;
            frees[i] = free;
        }
    }

    std::sort(allocations.begin(), allocations.end());
    std::sort(finds.begin(), finds.end());
    std::sort(frees.begin(), frees.end());

    std::cout << "Samples: " << samples << " (Concurrent: " << concurrency << ")\nIterations: " << iterations << "\n";
    std::cout << "Allocate:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[allocations.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[allocations.size() / 2]).count() << "ms\n";
    std::cout << "FindClientByLocal:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[finds.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[finds.size() / 2]).count() << "ms\n";
    std::cout << "Free:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[frees.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[frees.size() / 2]).count() << "ms\n";
}

TEST(LocalPoolTest, BenchmarkConcurrent)
{
    common::ipv4_prefix_t prefix("192.168.0.0/24");

    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    unsigned int sample_concurrency = std::sqrt(concurrency);
    unsigned int access_concurrency = sample_concurrency;
    
    const unsigned int samples = 64;
    const unsigned int iterations = 8'000'000;
    unsigned int iter_per_future = iterations / access_concurrency;
    std::array<std::chrono::duration<double>, samples> allocations;
    std::array<std::chrono::duration<double>, samples> finds;
    std::array<std::chrono::duration<double>, samples> frees;
    std::array<std::future<std::tuple<std::chrono::duration<double>,
                                      std::chrono::duration<double>,
                                      std::chrono::duration<double>>>, samples> futures;
    std::cout << "Samples: " << samples << " (Concurrent: " << sample_concurrency 
              << ")\nIterations: " << iterations << " (Concurrent: " << access_concurrency << ")\n";
    for (unsigned int s = 0; s < samples; s += sample_concurrency)
    {
        for (unsigned int j = s; j < s + sample_concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::tuple<std::chrono::duration<double>,
                                                                            std::chrono::duration<double>,
                                                                            std::chrono::duration<double>> {
                dataplane::proxy::LocalPool pool;
                pool._TestInit(ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()});
            
                std::vector<uint64_t> addresses(iterations);
                
                std::vector<std::future<void>> fs(access_concurrency);
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &addresses, &pool]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            addresses[k] = pool.Allocate(i, 1, 1);
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto alloc_elapsed = std::chrono::steady_clock::now() - start;

                start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &addresses, &pool]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            if (addresses[k])
                            {
                                uint32_t addr;
                                uint16_t port;
                                dataplane::proxy::LocalPool::UnpackTuple(addresses[k], addr, port);
                                pool.FindClientByLocal(addr, port);
                            }
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;

                start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &addresses, &pool]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            if (addresses[k])
                                pool.Free(i, addresses[k]);
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto free_elapsed = std::chrono::steady_clock::now() - start;
            
                pool._TestFree();
    
                return std::make_tuple(alloc_elapsed, find_elapsed, free_elapsed);
            });
        }
        for (unsigned int i = s; i < s + sample_concurrency && i < samples; i++)
        {
            auto [alloc, find, free] = futures[i].get();
            allocations[i] = alloc;
            finds[i] = find;
            frees[i] = free;
        }
    }

    std::sort(allocations.begin(), allocations.end());
    std::sort(finds.begin(), finds.end());
    std::sort(frees.begin(), frees.end());

    std::cout << "Allocate:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[allocations.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[allocations.size() / 2]).count() << "ms\n";
    std::cout << "FindClientByLocal:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[finds.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[finds.size() / 2]).count() << "ms\n";
    std::cout << "Free:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[frees.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[frees.size() / 2]).count() << "ms\n";
}

TEST(LocalPool2Test, Benchmark)
{
    common::ipv4_prefix_t prefix("192.168.0.0/24");

    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    const int samples = 64;
    const int iterations = 8'000'000;
    std::array<std::chrono::duration<double>, samples> allocations;
    std::array<std::chrono::duration<double>, samples> finds;
    std::array<std::chrono::duration<double>, samples> frees;
    std::array<std::future<std::tuple<std::chrono::duration<double>, 
                                      std::chrono::duration<double>,
                                      std::chrono::duration<double>>>, samples> futures;
    for (int s = 0; s < samples; s += concurrency)
    {
        for (unsigned int j = s; j < s + concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::tuple<std::chrono::duration<double>, 
                                                                            std::chrono::duration<double>,
                                                                            std::chrono::duration<double>> {
                dataplane::proxy::LocalPool2 pool;
                pool._TestInit(ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()});
            
                std::vector<uint64_t> addresses(iterations);
                
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    addresses[i] = pool.Allocate(0, 1, 1);
                }
                auto alloc_elapsed = std::chrono::steady_clock::now() - start;
            
                start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    if (addresses[i])
                    {
                        uint32_t addr;
                        uint16_t port;
                        dataplane::proxy::LocalPool2::UnpackTuple(addresses[i], addr, port);
                        pool.FindClientByLocal(addr, port);
                    }
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;

                start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    if (addresses[i])
                    {
                        pool.Free(0, addresses[i]);
                    }
                }
                auto free_elapsed = std::chrono::steady_clock::now() - start;
            
                pool._TestFree();
    
                return std::make_tuple(alloc_elapsed, find_elapsed, free_elapsed);
            });
        }
        for (unsigned int i = s; i < s + concurrency && i < samples; i++)
        {
            auto [alloc, find, free] = futures[i].get();
            allocations[i] = alloc;
            finds[i] = find;
            frees[i] = free;
        }
    }

    std::sort(allocations.begin(), allocations.end());
    std::sort(frees.begin(), frees.end());

    std::cout << "Samples: " << samples << " (Concurrent: " << concurrency << ")\nIterations: " << iterations << "\n";
    std::cout << "Allocate:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[allocations.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[allocations.size() / 2]).count() << "ms\n";
    std::cout << "FindClientByLocal:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[finds.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[finds.size() / 2]).count() << "ms\n";
    std::cout << "Free:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[frees.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[frees.size() / 2]).count() << "ms\n";
}

TEST(LocalPool2Test, BenchmarkConcurrent)
{
    common::ipv4_prefix_t prefix("192.168.0.0/24");

    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    unsigned int sample_concurrency = std::sqrt(concurrency);
    unsigned int access_concurrency = sample_concurrency;
    
    const unsigned int samples = 64;
    const unsigned int iterations = 8'000'000;
    unsigned int iter_per_future = iterations / access_concurrency;
    std::array<std::chrono::duration<double>, samples> allocations;
    std::array<std::chrono::duration<double>, samples> finds;
    std::array<std::chrono::duration<double>, samples> frees;
    std::array<std::future<std::tuple<std::chrono::duration<double>, 
                                      std::chrono::duration<double>,
                                      std::chrono::duration<double>>>, samples> futures;
    std::cout << "Samples: " << samples << " (Concurrent: " << sample_concurrency 
              << ")\nIterations: " << iterations << " (Concurrent: " << access_concurrency << ")\n";
    for (unsigned int s = 0; s < samples; s += sample_concurrency)
    {
        for (unsigned int j = s; j < s + sample_concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::tuple<std::chrono::duration<double>, 
                                                                            std::chrono::duration<double>,
                                                                            std::chrono::duration<double>> {
                dataplane::proxy::LocalPool2 pool;
                pool._TestInit(ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()});
            
                std::vector<uint64_t> addresses(iterations);
                
                std::vector<std::future<void>> fs(access_concurrency);
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &addresses, &pool]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            addresses[k] = pool.Allocate(i, 1, 1);
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto alloc_elapsed = std::chrono::steady_clock::now() - start;

                start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &addresses, &pool]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            if (addresses[k])
                            {
                                uint32_t addr;
                                uint16_t port;
                                dataplane::proxy::LocalPool2::UnpackTuple(addresses[k], addr, port);
                                pool.FindClientByLocal(addr, port);
                            }
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;

                start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &addresses, &pool]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            if (addresses[k])
                            {
                                pool.Free(i, addresses[k]);
                            }
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto free_elapsed = std::chrono::steady_clock::now() - start;
            
                pool._TestFree();
    
                return std::make_tuple(alloc_elapsed, find_elapsed, free_elapsed);
            });
        }
        for (unsigned int i = s; i < s + sample_concurrency && i < samples; i++)
        {
            auto [alloc, find, free] = futures[i].get();
            allocations[i] = alloc;
            finds[i] = find;
            frees[i] = free;
        }
    }

    std::sort(allocations.begin(), allocations.end());
    std::sort(finds.begin(), finds.end());
    std::sort(frees.begin(), frees.end());

    std::cout << "Allocate:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[allocations.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(allocations[allocations.size() / 2]).count() << "ms\n";
    std::cout << "FindClientByLocal:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[finds.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(finds[finds.size() / 2]).count() << "ms\n";
    std::cout << "Free:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[frees.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(frees[frees.size() / 2]).count() << "ms\n";
}

}