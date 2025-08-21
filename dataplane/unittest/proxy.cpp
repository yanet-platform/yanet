#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <future>
#include <thread>

#include "../proxy_connections.h"

TEST(ServiceConnectionsTest, Benchmark)
{
    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    const int samples = 64;
    const int iterations = 8'000'000;
    std::array<std::chrono::duration<double>, samples> find;
    std::array<std::future<std::chrono::duration<double>>, samples> futures;
    for (int s = 0; s < samples; s += concurrency)
    {
        for (unsigned int j = s; j < s + concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::chrono::duration<double> {
                dataplane::proxy::ServiceConnections conn;
                conn.Init(1, iterations, nullptr, 0, "");
            
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    dataplane::proxy::ConnectionData<dataplane::proxy::Connection> data;
                    conn.FindAndLock(i, 2, 7, data, false);
                    data.Unlock();
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;
    
                return find_elapsed;
            });
        }
        for (unsigned int i = s; i < s + concurrency && i < samples; i++)
        {
            find[i] = futures[i].get();
        }
    }

    std::sort(find.begin(), find.end());

    std::cout << "Samples: " << samples << " (Concurrent: " << concurrency << ")\nIterations: " << iterations << "\n";
    std::cout << "FindAndLock:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() / 2]).count() << "ms\n";
}

TEST(ServiceConnectionsTest, BenchmarkConcurrent)
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
    std::array<std::chrono::duration<double>, samples> find;
    std::array<std::future<std::chrono::duration<double>>, samples> futures;
    std::cout << "Samples: " << samples << " (Concurrent: " << sample_concurrency 
              << ")\nIterations: " << iterations << " (Concurrent: " << access_concurrency << ")\n";
    for (unsigned int s = 0; s < samples; s += sample_concurrency)
    {
        for (unsigned int j = s; j < s + sample_concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::chrono::duration<double> {
                dataplane::proxy::ServiceConnections conn;
                conn.Init(1, iterations, nullptr, 0, "");
            
                std::vector<std::future<void>> fs(access_concurrency);
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &conn]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            dataplane::proxy::ConnectionData<dataplane::proxy::Connection> data;
                            conn.FindAndLock(k, 2, 7, data, false);
                            data.Unlock();
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
            find[i] = futures[i].get();
        }
    }

    std::sort(find.begin(), find.end());

    std::cout << "FindAndLock:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() / 2]).count() << "ms\n";
}