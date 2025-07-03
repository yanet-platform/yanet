#include <gtest/gtest.h>

#include "../syncookies.h"
#include "../proxy.h"
#include "../type.h"

#include <array>
#include <random>
#include <future>

namespace {

using namespace dataplane::proxy;

TEST(SynCookiesTest, PackData) {
    TcpOptions options{};
    options.mss = 1440;
    options.sack_permitted = 1;
    options.window_scaling = 14;
    uint32_t packed = SynCookies::PackData(options);
    EXPECT_EQ(SynCookies::UnpackData(packed), options);
}

TEST(SynCookiesTest, Cookies) {
    SynCookies cookies;

    common::ipv4_address_t saddr("192.168.0.1");
    uint16_t sport = 1000;
    uint32_t seq = 1;
    TcpOptions options{};
    options.mss = 1440;
    options.sack_permitted = 1;
    options.window_scaling = 7;
    uint32_t data = SynCookies::PackData(options);

    constexpr int N = 1000000;
    std::array<uint32_t, N> cookies_array;
    for(int i = 0; i < N; ++i) {
        uint32_t cookie = cookies.GetCookie(saddr, sport, i, data);
        EXPECT_EQ(cookies.CheckCookie(cookie, saddr, sport, i), data);
        cookies_array[i] = cookie;
    }
    cookies.UpdateKeys();
    for(int i = 0; i < N; ++i) {
        EXPECT_EQ(cookies.CheckCookie(cookies_array[i], saddr, sport, i), data);
    }
    cookies.UpdateKeys();
    for(int i = 0; i < N; ++i) {
        EXPECT_NE(cookies.CheckCookie(cookies_array[i], saddr, sport, i), data);
    }

    uint32_t cookie = cookies.GetCookie(saddr, sport, seq, data);
    
    EXPECT_NE(cookies.CheckCookie(cookie, saddr, sport, seq + 1), data);
    

    EXPECT_EQ(cookies.CheckCookie(12345678, saddr, 345, 321), 0);
}

TEST(SynCookiesTest, RandomCookies) {
    SynCookies cookies;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist32(0, std::numeric_limits<uint32_t>::max());
    std::uniform_int_distribution<uint16_t> dist16(0, std::numeric_limits<uint16_t>::max());
    TcpOptions options{};
    options.mss = 1440;
    options.sack_permitted = true;
    options.window_scaling = 14;
    uint32_t data = SynCookies::PackData(options);

    for(uint32_t i = 0; i < 100'000'000; ++i) {
        uint32_t sa = dist32(gen), s = dist32(gen);
        uint16_t sp = dist16(gen);
        // std::string get, check;
        uint32_t cookie = cookies.GetCookie(sa, sp, s, data);
        EXPECT_EQ(cookies.CheckCookie(cookie, sa, sp, s), data);
        // if (cookies.CheckCookie(cookie, sa, sp, s, check) != data)
        // {
        //     YANET_LOG_WARNING("%s", get.c_str());
        //     YANET_LOG_WARNING("%s", check.c_str());
        //     break;
        // }
    }
}

TEST(SynCookiesTest, RandomValidation) {
    SynCookies cookies;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist32(0, std::numeric_limits<uint32_t>::max());
    std::uniform_int_distribution<uint16_t> dist16(0, std::numeric_limits<uint16_t>::max());

    uint32_t total = 1'000'000'000, positive = 0;
    for(uint32_t i = 0; i < total; ++i) {
        uint32_t c = dist32(gen), s = dist32(gen);
        uint32_t sa = dist32(gen);
        uint16_t sp = dist16(gen);
        if (cookies.CheckCookie(c, sa, sp, s) != 0) {
            ++positive;
        }
    }

    //          positive / total ~= 1/(2^23)
    // positive / total * (2^23) ~= 1
    double res = (double)positive / total * (1 << 23);
    EXPECT_GT(res, 0.75);
    EXPECT_LT(res, 1.25);
}

TEST(SynCookiesTest, Benchmark)
{
    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    const int samples = 64;
    const int iterations = 8'000'000;
    TcpOptions options{};
    options.mss = 1440;
    options.sack_permitted = 1;
    options.window_scaling = 7;

    std::array<std::chrono::duration<double>, samples> gets;
    std::array<std::chrono::duration<double>, samples> checks;
    std::array<std::future<std::tuple<std::chrono::duration<double>, 
                                      std::chrono::duration<double>>>, samples> futures;
    for (int s = 0; s < samples; s += concurrency)
    {
        for (unsigned int j = s; j < s + concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::tuple<std::chrono::duration<double>, 
                                                                            std::chrono::duration<double>> {
                SynCookies syn_cookies;
            
                std::vector<uint64_t> cookies(iterations);
                
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    cookies[i] = syn_cookies.GetCookie(i, 0, -i, SynCookies::PackData(options));
                }
                auto get_elapsed = std::chrono::steady_clock::now() - start;
            
                start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    syn_cookies.CheckCookie(cookies[i], i, 0, -i);
                }
                auto check_elapsed = std::chrono::steady_clock::now() - start;

                return std::make_tuple(get_elapsed, check_elapsed);
            });
        }
        for (unsigned int i = s; i < s + concurrency && i < samples; i++)
        {
            auto [get, check] = futures[i].get();
            gets[i] = get;
            checks[i] = check;
        }
    }

    std::sort(gets.begin(), gets.end());
    std::sort(checks.begin(), checks.end());

    std::cout << "Samples: " << samples << " (Concurrent: " << concurrency << ")\nIterations: " << iterations << "\n";
    std::cout << "GetCookie:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(gets[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(gets[gets.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(gets[gets.size() / 2]).count() << "ms\n";
    std::cout << "CheckCookie:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[checks.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[checks.size() / 2]).count() << "ms\n";
}

TEST(SynCookiesTest, BenchmarkConcurrent)
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
    TcpOptions options{};
    options.mss = 1440;
    options.sack_permitted = 1;
    options.window_scaling = 7;

    std::array<std::chrono::duration<double>, samples> gets;
    std::array<std::chrono::duration<double>, samples> checks;
    std::array<std::future<std::tuple<std::chrono::duration<double>, 
                                      std::chrono::duration<double>>>, samples> futures;
    std::cout << "Samples: " << samples << " (Concurrent: " << sample_concurrency 
              << ")\nIterations: " << iterations << " (Concurrent: " << access_concurrency << ")\n";
    for (unsigned int s = 0; s < samples; s += concurrency)
    {
        for (unsigned int j = s; j < s + concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::tuple<std::chrono::duration<double>, 
                                                                            std::chrono::duration<double>> {
                SynCookies syn_cookies;
            
                std::vector<uint64_t> cookies(iterations);
                
                std::vector<std::future<void>> fs(access_concurrency);
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &cookies, &syn_cookies]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            cookies[i] = syn_cookies.GetCookie(k, 0, -k, SynCookies::PackData(options));
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto get_elapsed = std::chrono::steady_clock::now() - start;
            
                start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &cookies, &syn_cookies]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            syn_cookies.CheckCookie(cookies[i], k, 0, -k);
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto check_elapsed = std::chrono::steady_clock::now() - start;

                return std::make_tuple(get_elapsed, check_elapsed);
            });
        }
        for (unsigned int i = s; i < s + concurrency && i < samples; i++)
        {
            auto [get, check] = futures[i].get();
            gets[i] = get;
            checks[i] = check;
        }
    }

    std::sort(gets.begin(), gets.end());
    std::sort(checks.begin(), checks.end());

    std::cout << "GetCookie:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(gets[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(gets[gets.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(gets[gets.size() / 2]).count() << "ms\n";
    std::cout << "CheckCookie:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[checks.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(checks[checks.size() / 2]).count() << "ms\n";
}

}