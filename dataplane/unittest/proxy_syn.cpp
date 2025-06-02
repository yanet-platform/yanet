#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <future>
#include <thread>

#include "../proxy_syn.h"

TEST(ServiceSynConnectionsTest, Benchmark)
{
    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    const int samples = 64;
    const int iterations = 8'000'000;
    std::array<std::chrono::duration<double>, samples> insert;
    std::array<std::chrono::duration<double>, samples> find;
    std::array<std::future<std::pair<std::chrono::duration<double>, std::chrono::duration<double>>>, samples> futures;
    for (int s = 0; s < samples; s += concurrency)
    {
        for (unsigned int j = s; j < s + concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::pair<std::chrono::duration<double>, std::chrono::duration<double>> {
                dataplane::proxy::ServiceSynConnections syn;
                syn._TestInit(1, iterations);
            
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    syn.TryInsert(i, 2, i, 4, 5, 6);
                }
                auto insert_elapsed = std::chrono::steady_clock::now() - start;

                start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    syn.FindAndLock(i, 2, 6);
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;
            
                syn._TestFree();
    
                return std::make_pair(insert_elapsed, find_elapsed);
            });
        }
        for (unsigned int i = s; i < s + concurrency && i < samples; i++)
        {
            auto [ie, fe] = futures[i].get();
            insert[i] = ie;
            find[i] = fe;
        }
    }

    std::sort(insert.begin(), insert.end());
    std::sort(find.begin(), find.end());

    std::cout << "Samples: " << samples << " (Concurrent: " << concurrency << ")\nIterations: " << iterations << "\n";
    std::cout << "TryInsert:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(insert[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(insert[insert.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(insert[insert.size() / 2]).count() << "ms\n";
    std::cout << "FindAndLock:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() / 2]).count() << "ms\n";
}

TEST(ServiceSynConnectionsTest, BenchmarkConcurrent)
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
    std::array<std::chrono::duration<double>, samples> insert;
    std::array<std::chrono::duration<double>, samples> find;
    std::array<std::future<std::pair<std::chrono::duration<double>, std::chrono::duration<double>>>, samples> futures;
    std::cout << "Samples: " << samples << " (Concurrent: " << sample_concurrency 
              << ")\nIterations: " << iterations << " (Concurrent: " << access_concurrency << ")\n";
    for (unsigned int s = 0; s < samples; s += sample_concurrency)
    {
        for (unsigned int j = s; j < s + sample_concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::pair<std::chrono::duration<double>, std::chrono::duration<double>> {
                dataplane::proxy::ServiceSynConnections syn;
                syn._TestInit(1, iterations);
            
                std::vector<std::future<void>> fs(access_concurrency);
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &syn]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            syn.TryInsert(k, 2, k, 4, 5, 6);
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto insert_elapsed = std::chrono::steady_clock::now() - start;

                start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &syn]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            syn.FindAndLock(k, 2, 6);
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;
            
                syn._TestFree();
    
                return std::make_pair(insert_elapsed, find_elapsed);
            });
        }
        for (unsigned int i = s; i < s + sample_concurrency && i < samples; i++)
        {
            auto [ie, fe] = futures[i].get();
            insert[i] = ie;
            find[i] = fe;
        }
    }

    std::sort(insert.begin(), insert.end());
    std::sort(find.begin(), find.end());

    std::cout << "TryInsert:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(insert[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(insert[insert.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(insert[insert.size() / 2]).count() << "ms\n";
    std::cout << "FindAndLock:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() / 2]).count() << "ms\n";
}