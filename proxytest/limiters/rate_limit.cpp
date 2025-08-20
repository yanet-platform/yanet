#include <gtest/gtest.h>

#include <array>
#include <future>

#include "dataplane/proxy_limiter.h"

using namespace dataplane::proxy;

namespace {

TEST(RateLimitTableTest, RateLimit)
{
    const uint64_t max_rate = 10;
    const uint64_t max_burst = 10;

    RateLimitTable ratelimit;
    ratelimit.Init(1024, max_rate, max_burst, nullptr, 0, "");

    uint64_t current_time_ms;
    for (uint32_t i = 0; i < max_burst; i++)
    {
        current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        ASSERT_TRUE(ratelimit.Check(0, current_time_ms));
    }
    current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    ASSERT_FALSE(ratelimit.Check(0, current_time_ms));
    sleep(1);
    for (uint32_t i = 0; i < max_burst; i++)
    {
        current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        ASSERT_TRUE(ratelimit.Check(0, current_time_ms));
    }
    current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    ASSERT_FALSE(ratelimit.Check(0, current_time_ms));
}

TEST(RateLimitTableTest, RateLimitConcurrent)
{
    const uint64_t max_rate = 10;
    const uint64_t max_burst = 10;

    RateLimitTable ratelimit;
    ratelimit.Init(1024, max_rate, max_burst, nullptr, 0, "");

    std::array<std::future<bool>, 8> futures;

    for (uint32_t f = 0; f < futures.size(); f++)
    {
        futures[f] = std::async([=, &ratelimit]() -> bool {
            uint64_t current_time_ms;
            for (uint32_t i = 0; i < max_burst; i++)
            {
                current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                if (ratelimit.Check(f, current_time_ms) != true) return false;
            }
            current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            if (ratelimit.Check(f, current_time_ms) != false) return false;
            sleep(1);
            for (uint32_t i = 0; i < max_burst; i++)
            {
                current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                if (ratelimit.Check(f, current_time_ms) != true) return false;
            }
            current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            if (ratelimit.Check(f, current_time_ms) != false) return false;

            return true;
        });
    }

    for (auto& f : futures)
    {
        ASSERT_TRUE(f.get());
    }
}

TEST(RateLimitTableTest, Benchmark)
{
    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    const int samples = 64;
    const int iterations = 8'000'000;
    std::array<std::chrono::duration<double>, samples> checks;
    std::array<std::future<std::chrono::duration<double>>, samples> futures;
    for (int s = 0; s < samples; s += concurrency)
    {
        for (unsigned int j = s; j < s + concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::chrono::duration<double> {
                RateLimitTable ratelimit;
                ratelimit.Init(iterations, 10, 10, nullptr, 0, "");
            
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    ratelimit.Check(i, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;
    
                return find_elapsed;
            });
        }
        for (unsigned int i = s; i < s + concurrency && i < samples; i++)
        {
            checks[i] = futures[i].get();
        }
    }

    std::sort(checks.begin(), checks.end());

    std::cout << "Samples: " << samples << " (Concurrent: " << concurrency << ")\nIterations: " << iterations << "\n";
    std::cout << "Check:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[checks.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[checks.size() / 2]).count() << "ms\n";
}

TEST(RateLimitTableTest, BenchmarkConcurrent)
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
    std::array<std::chrono::duration<double>, samples> checks;
    std::array<std::future<std::chrono::duration<double>>, samples> futures;
    std::cout << "Samples: " << samples << " (Concurrent: " << sample_concurrency 
              << ")\nIterations: " << iterations << " (Concurrent: " << access_concurrency << ")\n";
    for (unsigned int s = 0; s < samples; s += sample_concurrency)
    {
        for (unsigned int j = s; j < s + sample_concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::chrono::duration<double> {
                RateLimitTable ratelimit;
                ratelimit.Init(iterations, 10, 10, nullptr, 0, "");
            
                std::vector<std::future<void>> fs(access_concurrency);
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &ratelimit]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            ratelimit.Check(k, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
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
            checks[i] = futures[i].get();
        }
    }

    std::sort(checks.begin(), checks.end());

    std::cout << "Check:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[checks.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[checks.size() / 2]).count() << "ms\n";
}

}