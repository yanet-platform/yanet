#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <future>
#include <thread>

#include "../local_pool.h"

namespace {
class LocalPoolTest
{
public:
    LocalPoolTest()
    : initialized_(false)
    {}

    ~LocalPoolTest()
    {
        if (initialized_) destroy();
        connection_queue_ = nullptr;
        initialized_ = false;
    }
    bool Init(proxy_service_id_t service_id, const ipv4_prefix_t& prefix, dataplane::memory_manager* memory_manager)
    {
        if (initialized_)
        {
            return true;
        }
        if (prefix.mask == 0)
        {
            return false;
        }
        prefix_ = prefix;

        num_connections_ = ((1u << (32u - prefix_.mask)) - 2) * num_ports;

        if (memory_manager != nullptr)
        {
            tSocketId socket_id = 0; // todo !!!
            std::string name = "tcp_proxy.local_pools." + std::to_string(service_id);
            connection_queue_ = memory_manager->create_static_array<ConnectionInfo>(name.data(), num_connections_, socket_id);
            destroy = [this, memory_manager](){
                memory_manager->destroy(connection_queue_);
            };
        }
        else
        {
            connection_queue_ = new ConnectionInfo[num_connections_];
            destroy = [this](){
                delete[] connection_queue_;
            };
        }
        if (connection_queue_ == nullptr)
        {
            num_connections_ = 0;
            return false;
        }

        for(uint32_t i = 0; i < (1u << (32u - prefix_.mask)) - 2; i++)
        {
            for(uint16_t j = 0; j < num_ports; j++)
            {
                connection_queue_[i*num_ports + j] = ConnectionInfo{
                    .is_used = 0,
                    .next_idx = i * num_ports + j + 1
                };
            }
        }
        connection_queue_[num_connections_ - 1].next_idx = 0xffffffff;

        first_ = 0;
        last_ = num_connections_ - 1;
        free_addresses_ = num_connections_;
        used_addresses_ = 0;

        initialized_ = true;

        return true;
    }

    uint64_t Allocate(uint32_t worker_id, uint32_t client_addr, tPortId client_port)
    {
        while(!mutex_.try_lock());
        if (unlikely(!initialized_) || first_ == 0xffffffff)
        {
            mutex_.unlock();
            return 0;
        }

        uint64_t res = index_to_tuple(first_);
        
        ConnectionInfo& info = connection_queue_[first_];
        first_ = info.next_idx;
        if (first_ == 0xffffffff)
            last_ = 0xffffffff;

        info.is_used = 1;
        info.address = client_addr;
        info.port = client_port;

        free_addresses_--;
        used_addresses_++;

        mutex_.unlock();
        return res;
    }

    uint64_t FindClientByLocal(uint32_t local_addr, tPortId local_port) const
    {
        if (unlikely(!initialized_))
        {
            return 0;
        }
        while(!mutex_.try_lock_shared());

        uint32_t idx = tuple_to_index(PackTuple(local_addr, local_port));
        local_addr = rte_be_to_cpu_32(local_addr);
        local_port = rte_be_to_cpu_16(local_port);
        if (unlikely(idx > num_connections_ - 1))
        {
            mutex_.unlock();
            // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: out of range, local_addr=%s local_port=%d idx=%d num_connections_=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx, num_connections_);
            return 0;
        }

        const ConnectionInfo& info = connection_queue_[idx];
        if (info.is_used == 0)
        {
            mutex_.unlock();
            // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: not used, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
            return 0;
        }

        mutex_.unlock();
        // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: found, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
        return PackTuple(info.address, info.port);
    }

    void Free(uint32_t worker_id, uint64_t tuple)
    {
        if (unlikely(!initialized_))
        {
            return;
        }
        while(!mutex_.try_lock());

        uint32_t idx = tuple_to_index(tuple);
        if (unlikely(idx > num_connections_ - 1))
        {
            mutex_.unlock();
            return;
        }

        if (last_ != 0xffffffff)
            connection_queue_[last_].next_idx = idx;
        last_ = idx;
        if (first_ == 0xffffffff)
            first_ = idx;

        ConnectionInfo& info = connection_queue_[last_];
        info.is_used = 0;
        info.next_idx = 0xffffffff;

        free_addresses_++;
        used_addresses_--;

        mutex_.unlock();
    }

    constexpr static size_t max_workers = 128;
    constexpr static uint16_t min_port = 32768;
    constexpr static uint16_t max_port = 65535;
    constexpr static uint16_t num_ports = max_port - min_port + 1;

private:
    bool initialized_;
    mutable std::shared_mutex mutex_;
    ipv4_prefix_t prefix_;
    std::function<void()> destroy;

    struct ConnectionInfo
    {
        uint16_t is_used;
        union {
            struct {
                uint32_t address;
                tPortId port;
            };
            uint32_t next_idx;
        };
    };
    ConnectionInfo* connection_queue_;
    uint32_t num_connections_;
    uint32_t first_;
    uint32_t last_;

    uint32_t free_addresses_;
    uint32_t used_addresses_;

    inline uint64_t index_to_tuple(uint32_t index) const
    {
        return PackTuple(rte_cpu_to_be_32(prefix_.address.address + 1 + index / num_ports),
                        rte_cpu_to_be_16(index % num_ports + min_port));
    }

    inline uint32_t tuple_to_index(uint64_t tuple) const
    {
        return (rte_be_to_cpu_16((uint16_t)(tuple & 0xffff)) - min_port) + 
            (rte_be_to_cpu_32((uint32_t)(tuple >> 16)) - prefix_.address.address - 1) * num_ports;
    }

public:
    inline static uint64_t PackTuple(uint32_t addr, uint16_t port) {
        return ((uint64_t)addr << 16) | (uint64_t)port;
    }

    inline static void UnpackTuple(uint64_t tuple, uint32_t& addr, tPortId& port) {
        addr = tuple >> 16;
        port = tuple & 0xffff;
    }

    inline static void UnpackTupleSrc(uint64_t tuple, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header) {
        ipv4_header->src_addr = tuple >> 16;
        tcp_header->src_port = tuple & 0xffff;
    }

    inline static void UnpackTupleDst(uint64_t tuple, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header) {
        ipv4_header->dst_addr = tuple >> 16;
        tcp_header->dst_port = tuple & 0xffff;
    }
};

TEST(LocalPoolTestTest, Allocate)
{
    common::ipv4_prefix_t prefix("192.168.0.0/30");
    LocalPoolTest pool;
    pool.Init(0, ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()}, nullptr);

    uint32_t client_addr = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.1")).address;
    tPortId client_port = 12345;

    uint32_t ip = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.1")).address;
    uint64_t expect = LocalPoolTest::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32768));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = LocalPoolTest::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32769));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = LocalPoolTest::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32770));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    EXPECT_EQ(pool.FindClientByLocal(ip, rte_cpu_to_be_16(32768)),
              LocalPoolTest::PackTuple(client_addr, client_port));

    uint32_t ip2 = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.2")).address;
    for(uint32_t i = LocalPoolTest::min_port+3; i <= UINT16_MAX; i++) {pool.Allocate(0, client_addr, client_port);}
    expect = LocalPoolTest::PackTuple(ip2, rte_cpu_to_be_16((uint16_t)32768));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = LocalPoolTest::PackTuple(ip2, rte_cpu_to_be_16((uint16_t)32769));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = LocalPoolTest::PackTuple(ip2, rte_cpu_to_be_16((uint16_t)32770));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);

    for(uint32_t i = LocalPoolTest::min_port+3; i <= UINT16_MAX; i++) {pool.Allocate(0, client_addr, client_port);}
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), 0);

    pool.Free(0, LocalPoolTest::PackTuple(ip, rte_cpu_to_be_16(33333)));
    EXPECT_EQ(pool.FindClientByLocal(ip, rte_cpu_to_be_16(33333)), 0);
    expect = LocalPoolTest::PackTuple(ip, rte_cpu_to_be_16((uint16_t)33333));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
};

TEST(LocalPoolTest, Allocate)
{
    common::ipv4_prefix_t prefix("192.168.0.0/30");
    dataplane::proxy::LocalPool pool;
    pool.Init(0, ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()}, nullptr, 0, false);

    uint32_t client_addr = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.1")).address;
    tPortId client_port = 12345;

    uint32_t ip = ipv4_address_t::convert(common::ipv4_address_t("192.168.0.1")).address;
    uint64_t expect = dataplane::proxy::LocalPool::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32768));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = dataplane::proxy::LocalPool::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32769));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
    expect = dataplane::proxy::LocalPool::PackTuple(ip, rte_cpu_to_be_16((uint16_t)32770));
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
    for(uint32_t i = 1; i < dataplane::proxy::LocalPool::chunk_size; i++)
        pool.Free(0, dataplane::proxy::LocalPool::PackTuple(ip, rte_cpu_to_be_16(33333+i)));
    expect = dataplane::proxy::LocalPool::PackTuple(ip, rte_cpu_to_be_16(33333));
    EXPECT_EQ(pool.Allocate(0, client_addr, client_port), expect);
};

TEST(LocalPoolTestTest, Benchmark)
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
                LocalPoolTest pool;
                pool.Init(0, ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()}, nullptr);
            
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
                        LocalPoolTest::UnpackTuple(addresses[i], addr, port);
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

TEST(LocalPoolTestTest, BenchmarkConcurrent)
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
                LocalPoolTest pool;
                pool.Init(0, ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()}, nullptr);
            
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
                                LocalPoolTest::UnpackTuple(addresses[k], addr, port);
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
                pool.Init(0, ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()}, nullptr, 0, false);
            
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
                        dataplane::proxy::LocalPool::UnpackTuple(addresses[i], addr, port);
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
                pool.Init(0, ipv4_prefix_t{ipv4_address_t{prefix.address()}, prefix.mask()}, nullptr, 0, false);
            
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