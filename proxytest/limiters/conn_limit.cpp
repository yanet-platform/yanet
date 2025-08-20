#include <gtest/gtest.h>

#include <array>
#include <future>

#include "dataplane/proxy_limiter.h"

using namespace dataplane::proxy;

namespace {

TEST(ConnectionLimitTableTest, ConnLimit)
{
    const uint64_t max_conns = 10;

    ConnectionLimitTable connlimit;
    connlimit.Init(1024, max_conns, nullptr, 0, "");

    for (uint32_t i = 0; i < max_conns; i++)
    {
        ASSERT_TRUE(connlimit.Add(0));
    }
    ASSERT_FALSE(connlimit.Add(0));
    connlimit.Remove(0, 10);
    for (uint32_t i = 0; i < max_conns; i++)
    {
        ASSERT_TRUE(connlimit.Add(0));
    }
    ASSERT_FALSE(connlimit.Add(0));
}

TEST(ConnectionLimitTableTest, ConnLimitConcurrent)
{
    const uint64_t max_conns = 10;

    ConnectionLimitTable connlimit;
    connlimit.Init(1024, max_conns, nullptr, 0, "");

    std::array<std::future<bool>, 8> futures;

    for (uint32_t f = 0; f < futures.size(); f++)
    {
        futures[f] = std::async([=, &connlimit]() -> bool {
            for (uint32_t i = 0; i < max_conns; i++)
            {
                if (connlimit.Add(f) != true) return false;
            }
            if (connlimit.Add(f) != false) return false;
            connlimit.Remove(f, 10);
            for (uint32_t i = 0; i < max_conns; i++)
            {
                if (connlimit.Add(f) != true) return false;
            }
            if (connlimit.Add(f) != false) return false;

            return true;
        });
    }

    for (auto& f : futures)
    {
        ASSERT_TRUE(f.get());
    }
}

TEST(ConnectionLimitTableTest, Benchmark)
{
    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    const int samples = 64;
    const int iterations = 8'000'000;
    std::array<std::chrono::duration<double>, samples> adds;
    std::array<std::future<std::chrono::duration<double>>, samples> futures;
    for (int s = 0; s < samples; s += concurrency)
    {
        for (unsigned int j = s; j < s + concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::chrono::duration<double> {
                ConnectionLimitTable connlimit;
                connlimit.Init(iterations, 10, nullptr, 0, "");
            
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    connlimit.Add(i);
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;
    
                return find_elapsed;
            });
        }
        for (unsigned int i = s; i < s + concurrency && i < samples; i++)
        {
            adds[i] = futures[i].get();
        }
    }

    std::sort(adds.begin(), adds.end());

    std::cout << "Samples: " << samples << " (Concurrent: " << concurrency << ")\nIterations: " << iterations << "\n";
    std::cout << "Add:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[adds.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[adds.size() / 2]).count() << "ms\n";
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
    const unsigned int iterations = 8'000'000;
    unsigned int iter_per_future = iterations / access_concurrency;
    std::array<std::chrono::duration<double>, samples> adds;
    std::array<std::future<std::chrono::duration<double>>, samples> futures;
    std::cout << "Samples: " << samples << " (Concurrent: " << sample_concurrency 
              << ")\nIterations: " << iterations << " (Concurrent: " << access_concurrency << ")\n";
    for (unsigned int s = 0; s < samples; s += sample_concurrency)
    {
        for (unsigned int j = s; j < s + sample_concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::chrono::duration<double> {
                ConnectionLimitTable connlimit;
                connlimit.Init(iterations, 10, nullptr, 0, "");
            
                std::vector<std::future<void>> fs(access_concurrency);
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &connlimit]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            connlimit.Add(k);
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;
    
                return find_elapsed;
            });
        }
        for (unsigned int i = s; i < s + sample_concurrency && i < samples; i++)
        {
            adds[i] = futures[i].get();
        }
    }

    std::sort(adds.begin(), adds.end());

    std::cout << "Check:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[adds.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(adds[adds.size() / 2]).count() << "ms\n";
}

}