#include <gtest/gtest.h>

#include "../syncookies.h"
#include "../type.h"

#include <array>
#include <random>

namespace {

using namespace dataplane::proxy;

TEST(SynCookiesTest, PackData) {
    SynCookies::TCPOptions options{
        .mss = 2,
        .sack = 1,
        .wscale = 14,
        .ecn = 1,
    };
    uint32_t packed = SynCookies::PackData(options);
    EXPECT_EQ(SynCookies::UnpackData(packed), options);
}

TEST(SynCookiesTest, Cookies) {
    SynCookies cookies;

    common::ipv4_address_t saddr("192.168.0.1");
    common::ipv4_address_t daddr("192.168.0.2");
    uint16_t sport = 1000;
    uint16_t dport = 2000;
    uint32_t seq = 1;
    uint32_t data = SynCookies::PackData(SynCookies::TCPOptions{
        .mss = 3,
        .sack = 1,
        .wscale = 7,
        .ecn = 1,
    });

    constexpr int N = 1000000;
    std::array<uint32_t, N> cookies_array;
    for(int i = 0; i < N; ++i) {
        uint32_t cookie = cookies.GetCookie(saddr, daddr, sport, dport, i, data);
        EXPECT_EQ(cookies.CheckCookie(cookie, saddr, daddr, sport, dport, i), data);
        cookies_array[i] = cookie;
    }
    cookies.UpdateKeys();
    for(int i = 0; i < N; ++i) {
        EXPECT_EQ(cookies.CheckCookie(cookies_array[i], saddr, daddr, sport, dport, i), data);
    }
    cookies.UpdateKeys();
    for(int i = 0; i < N; ++i) {
        EXPECT_NE(cookies.CheckCookie(cookies_array[i], saddr, daddr, sport, dport, i), data);
    }

    uint32_t cookie = cookies.GetCookie(saddr, daddr, sport, dport, seq, data);
    
    EXPECT_NE(cookies.CheckCookie(cookie, saddr, daddr, sport, dport, seq + 1), data);
    

    EXPECT_EQ(cookies.CheckCookie(12345678, saddr, daddr, 345, 432, 321), 0);
}

TEST(SynCookiesTest, RandomCookies) {
    SynCookies cookies;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist32(0, std::numeric_limits<uint32_t>::max());
    std::uniform_int_distribution<uint16_t> dist16(0, std::numeric_limits<uint16_t>::max());
    std::uniform_int_distribution<uint8_t> dist8(0, 255);

    for(uint32_t i = 0; i < 100'000'000; ++i) {
        uint32_t sa = dist32(gen), da = dist32(gen), s = dist32(gen);
        uint16_t sp = dist16(gen), dp = dist16(gen);
        uint32_t data = dist8(gen);
        uint32_t cookie = cookies.GetCookie(sa, da, sp, dp, s, data);
        EXPECT_EQ(cookies.CheckCookie(cookie, sa, da, sp, dp, s), data);
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
        uint32_t c = dist32(gen);
        uint32_t sa = dist32(gen), da = dist32(gen), s = dist32(gen);
        uint16_t sp = dist16(gen), dp = dist16(gen);
        if (cookies.CheckCookie(c, sa, da, sp, dp, s) != 0) {
            ++positive;
        }
    }

    //          positive / total ~= 1/(2^23)
    // positive / total * (2^23) ~= 1
    double res = (double)positive / total * (1 << 23);
    EXPECT_GT(res, 0.8);
    EXPECT_LT(res, 1.2);
}

}