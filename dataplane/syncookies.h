#pragma once

#include "type.h"

#include <random>

namespace dataplane::proxy
{

struct TcpOptions;

class SynCookies
{
public:
    SynCookies();

    uint32_t GetCookie(uint32_t saddr, uint16_t sport, 
                        uint32_t sseq, uint32_t data);
    uint32_t CheckCookie(uint32_t cookie, uint32_t saddr, uint16_t sport);

    void UpdateKeys();

    static uint32_t PackData(TcpOptions options);

    static TcpOptions UnpackData(uint32_t data);

    static uint32_t MssToTable(uint32_t mss);

    static uint32_t MssFromTable(uint32_t table_value);

private:
    using key128_t = uint64_t[2];
    key128_t keys_[3];
    uint32_t current_key_ = 0;
    
    std::random_device rd_;
    std::mt19937 gen_;
    std::uniform_int_distribution<uint32_t> dist_;

    static constexpr uint32_t COOKIE_BITS = 24;
    static constexpr uint32_t COOKIE_MASK = (1 << COOKIE_BITS) - 1;

    static constexpr uint32_t EVEN_BITS    = 1;
    static constexpr uint32_t MSS_BITS     = 2;
    static constexpr uint32_t SACK_BITS    = 1;
    static constexpr uint32_t WSCALE_BITS  = 4;

    static constexpr uint32_t EVEN_OFFSET   = 0;
    static constexpr uint32_t MSS_OFFSET    = EVEN_OFFSET + EVEN_BITS;
    static constexpr uint32_t SACK_OFFSET   = MSS_OFFSET + MSS_BITS;
    static constexpr uint32_t WSCALE_OFFSET = SACK_OFFSET + SACK_BITS;

    static constexpr uint32_t EVEN_MASK    = ((1 << EVEN_BITS) - 1) << EVEN_OFFSET;
    static constexpr uint32_t MSS_MASK     = ((1 << MSS_BITS) - 1) << MSS_OFFSET;
    static constexpr uint32_t SACK_MASK    = ((1 << SACK_BITS) - 1) << SACK_OFFSET;
    static constexpr uint32_t WSCALE_MASK  = ((1 << WSCALE_BITS) - 1) << WSCALE_OFFSET;
    
    static constexpr uint32_t DATA_MASK = WSCALE_MASK | SACK_MASK | MSS_MASK | EVEN_MASK;

    uint32_t cookie_hash(uint32_t saddr, uint16_t sport, uint32_t keyidx);
};

}