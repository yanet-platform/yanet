#include <gtest/gtest.h>

#include <array>
#include <future>
#include <chrono>

#include "dataplane/proxy_limiter.h"

using namespace dataplane::proxy;

namespace {

TEST(ConnectionLimitTableTest, ConnLimit)
{
    const uint32_t num_connections = 1024;
    const uint64_t timeout = 1000;

    ConnectionLimitTable connlimit;
    ASSERT_TRUE(connlimit.Init(num_connections, nullptr, 0, ""));

    uint64_t current_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    ASSERT_FALSE(connlimit.Exists(1, current_time));
    current_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    ASSERT_TRUE(connlimit.Add(1, current_time, timeout));
    ASSERT_TRUE(connlimit.Exists(1, current_time));

    current_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    ASSERT_TRUE(connlimit.Add(2, current_time, timeout));
    ASSERT_TRUE(connlimit.Exists(2, current_time));
    connlimit.Remove(2);
    ASSERT_FALSE(connlimit.Exists(2, current_time));

    sleep(4);
    current_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    ASSERT_FALSE(connlimit.Exists(1, current_time));
}

TEST(ConnectionLimitTableTest, Benchmark)
{
    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    const int samples = 64;
    const int iterations = 1 << 23;
    std::array<std::chrono::duration<double>, samples> adds;
    std::array<std::chrono::duration<double>, samples> exists;
    std::array<std::chrono::duration<double>, samples> removes;
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
                ConnectionLimitTable connlimit;
                connlimit.Init(iterations, nullptr, 0, "");
            
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    connlimit.Add(i, 0, 1000);
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;

                start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    connlimit.Exists(i, 0);
                }
                auto exists_elapsed = std::chrono::steady_clock::now() - start;

                start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    connlimit.Remove(i);
                }
                auto remove_elapsed = std::chrono::steady_clock::now() - start;
    
                return {find_elapsed, exists_elapsed, remove_elapsed};
            });
        }
        for (unsigned int i = s; i < s + concurrency && i < samples; i++)
        {
            auto [add, exist, remove] = futures[i].get();
            adds[i] = add;
            exists[i] = exist;
            removes[i] = remove;
        }
    }

    std::sort(adds.begin(), adds.end());
    std::sort(exists.begin(), exists.end());
    std::sort(removes.begin(), removes.end());

    std::cout << "Samples: " << samples << " (Concurrent: " << concurrency << ")\nIterations: " << iterations << "\n";
    std::cout << "Add:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[adds.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[adds.size() / 2]).count() << "ms\n";
    std::cout << "Exists:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(exists[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(exists[exists.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(exists[exists.size() / 2]).count() << "ms\n";
    std::cout << "Remove:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(removes[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(removes[removes.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(removes[removes.size() / 2]).count() << "ms\n";
}

TEST(ConnectionLimitTableTest, BenchmarkConcurrent)
{
    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    unsigned int sample_concurrency = std::sqrt(concurrency);
    unsigned int access_concurrency = sample_concurrency;
    
    const unsigned int samples = 64;
    const unsigned int iterations = 1 << 23;
    unsigned int iter_per_future = iterations / access_concurrency;

    std::array<std::chrono::duration<double>, samples> adds;
    std::array<std::chrono::duration<double>, samples> exists;
    std::array<std::chrono::duration<double>, samples> removes;

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
                ConnectionLimitTable connlimit;
                connlimit.Init(iterations, nullptr, 0, "");
            
                std::vector<std::future<void>> fs(access_concurrency);
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &connlimit]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            connlimit.Add(k, 0, 1000);
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
                    fs[i] = std::async(std::launch::async, [=, &connlimit]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            connlimit.Exists(k, 0);
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto exists_elapsed = std::chrono::steady_clock::now() - start;

                start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &connlimit]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            connlimit.Remove(k);
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto remove_elapsed = std::chrono::steady_clock::now() - start;
    
                return {find_elapsed, exists_elapsed, remove_elapsed};
            });
        }
        for (unsigned int i = s; i < s + sample_concurrency && i < samples; i++)
        {
            auto [add, exist, remove] = futures[i].get();
            adds[i] = add;
            exists[i] = exist;
            removes[i] = remove;
        }
    }

    std::sort(adds.begin(), adds.end());
    std::sort(exists.begin(), exists.end());
    std::sort(removes.begin(), removes.end());

    std::cout << "Add:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[adds.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[adds.size() / 2]).count() << "ms\n";
    std::cout << "Exists:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(exists[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(exists[exists.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(exists[exists.size() / 2]).count() << "ms\n";
    std::cout << "Remove:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(removes[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(removes[removes.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(removes[removes.size() / 2]).count() << "ms\n";
}

}