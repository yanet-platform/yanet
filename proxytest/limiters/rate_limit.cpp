#include <gtest/gtest.h>

#include <array>
#include <condition_variable>
#include <future>
#include <shared_mutex>

#include "dataplane/proxy_limiter.h"

using namespace dataplane::proxy;

namespace {

const std::array<uint32_t, 17> ips = {
    2,
    39,
    72,
    109,
    384,
    421,
    458,
    495,
    644,
    673,
    718,
    747,
    774,
    803,
    844,
    873,
    1048
};

TEST(RateLimitTableTest, RateLimit)
{
    const uint32_t num_connections = 1024;
    const uint32_t max_rate = 10;
    const uint32_t max_burst = 10;

    RateLimitTable ratelimit;
    ratelimit.Init(num_connections, max_rate, max_burst, nullptr, 0, "");

    uint64_t current_time_ms;
    for (uint32_t i = 0; i < max_burst; i++)
    {
        current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        ASSERT_TRUE(ratelimit.CheckAndConsume(ips[0], current_time_ms));
    }
    current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    ASSERT_FALSE(ratelimit.CheckAndConsume(ips[0], current_time_ms));
    sleep(1);
    for (uint32_t i = 0; i < max_burst; i++)
    {
        current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        ASSERT_TRUE(ratelimit.CheckAndConsume(ips[0], current_time_ms));
    }
    current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    ASSERT_FALSE(ratelimit.CheckAndConsume(ips[0], current_time_ms));

    for(uint32_t i = 1; i < RateLimitBucket::bucket_size; i++)
    {
        current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        ASSERT_TRUE(ratelimit.CheckAndConsume(ips[i], current_time_ms));
    }
    current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    ASSERT_FALSE(ratelimit.CheckAndConsume(ips[RateLimitBucket::bucket_size], current_time_ms));
    sleep(2);
    current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    ASSERT_TRUE(ratelimit.CheckAndConsume(ips[RateLimitBucket::bucket_size], current_time_ms));
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
    std::array<std::chrono::duration<double>, samples> check_and_consume;
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
                    ratelimit.CheckAndConsume(i, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;
    
                return find_elapsed;
            });
        }
        for (unsigned int i = s; i < s + concurrency && i < samples; i++)
        {
            check_and_consume[i] = futures[i].get();
        }
    }

    std::sort(check_and_consume.begin(), check_and_consume.end());

    std::cout << "Samples: " << samples << " (Concurrent: " << concurrency << ")\nIterations: " << iterations << "\n";
    std::cout << "CheckAndConsume:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(check_and_consume[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(check_and_consume[check_and_consume.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(check_and_consume[check_and_consume.size() / 2]).count() << "ms\n";
}

TEST(RateLimitTableTest, BenchmarkConcurrent)
{
    // unsigned int concurrency = std::thread::hardware_concurrency();
    // if (concurrency == 0)
    // {
    //     concurrency = 8;
    // }
    unsigned int concurrency = 8;

    const unsigned int iterations = 8'000'000;
    unsigned int iters_by_thread = iterations / concurrency;

    RateLimitTable ratelimit;
    ratelimit.Init(iterations, 10, 10, nullptr, 0, "");
    
    std::vector<std::thread> threads;
    std::cout << "Iterations: " << iterations << " (Concurrent: " << concurrency << ")\n";

    std::shared_mutex thread_sync_mutex;
    std::condition_variable_any thread_sync_cv;
    bool thread_sync_ready = false;

    for (unsigned int t = 0; t < concurrency; t++)
    {
        threads.emplace_back([&]() {
            std::shared_lock lock(thread_sync_mutex);
            thread_sync_cv.wait(lock, [&] { return thread_sync_ready; });

            for (unsigned int i = t * iters_by_thread; i < t * iters_by_thread + iters_by_thread ; i++)
            {
                ratelimit.CheckAndConsume(i, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
            }
        });
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(t, &cpuset);
        int rc = pthread_setaffinity_np(threads[t].native_handle(), sizeof(cpu_set_t), &cpuset);
        if (rc != 0) {
            YANET_LOG_ERROR("Failed to set affinity for syn thread %d: %s\n", t, strerror(rc));
        }
    }

    {
        std::lock_guard lock(thread_sync_mutex);
        thread_sync_ready = true;
    }
    thread_sync_cv.notify_all();
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    for (unsigned int t = 0; t < concurrency; t++)
    {
        threads[t].join();
    }
    auto elapsed = std::chrono::steady_clock::now() - start;

    std::cout << "CheckAndConsume: " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << "ms\n";
}

}