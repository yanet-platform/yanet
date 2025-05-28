#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <future>
#include <thread>

#include "../proxy.h"

TEST(ServiceConnectionsTest, Benchmark)
{
    unsigned int concurrent = std::thread::hardware_concurrency();
    if (concurrent == 0)
    {
        concurrent = 8;
    }
    const int samples = 64;
    const int iterations = 8'000'000;
    std::array<std::chrono::duration<double>, samples> insert;
    std::array<std::chrono::duration<double>, samples> find;
    std::array<std::future<std::pair<std::chrono::duration<double>, std::chrono::duration<double>>>, 100> futures;
    for (int s = 0; s < samples; s += concurrent)
    {
        for (unsigned int j = s; j < s + concurrent && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::pair<std::chrono::duration<double>, std::chrono::duration<double>> {
                dataplane::proxy::ServiceConnections conn;
                conn._TestInit(1, iterations);
            
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    conn.TryInsert(i, 2, i, 4, dataplane::proxy::ConnectionState::ESTABLISHED, 6, 7, 8);
                }
                auto insert_elapsed = std::chrono::steady_clock::now() - start;
            
                start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    conn.FindAndLock(i, 2, 7);
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;

                conn._TestFree();
    
                return std::make_pair(insert_elapsed, find_elapsed);
            });
        }
        for (unsigned int i = s; i < s + concurrent && i < samples; i++)
        {
            auto [ie, fe] = futures[i].get();
            insert[i] = ie;
            find[i] = fe;
        }
    }

    std::sort(insert.begin(), insert.end());

    std::cout << "Samples: " << samples << " Concurrent: " << concurrent << "\nIterations: " << iterations << "\n";
    std::cout << "TryInsert:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(insert[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(insert[insert.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(insert[insert.size() / 2]).count() << "ms\n";
    std::cout << "FindAndLock:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() / 2]).count() << "ms\n";
}