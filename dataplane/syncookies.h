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

    template<typename addr_type>
    uint32_t GetCookie(addr_type saddr, uint16_t sport,  uint32_t sseq, uint32_t data) const
    {
        uint32_t cookie = ((cookie_hash(saddr, sport, 0) + sseq) << 1)
                    + ((current_key_ - 1) << COOKIE_BITS)
                    + ((cookie_hash(saddr, sport, current_key_) + data) << 1 & COOKIE_MASK);
        cookie |= (rte_be_to_cpu_32(sseq) & 1);

        return cookie;
    }

    template<typename addr_type>
    uint32_t CheckCookie(uint32_t cookie, addr_type saddr, uint16_t sport, uint32_t sseq) const
    {
        cookie -= (cookie_hash(saddr, sport, 0) + sseq) << 1;
        uint32_t keyidx = (cookie >> COOKIE_BITS) + 1;
        if (1 > keyidx || keyidx > 2) {
            return 0;
        }
        cookie = ((cookie & COOKIE_MASK) - (cookie_hash(saddr, sport, keyidx) << 1 & COOKIE_MASK)) & COOKIE_MASK;
        
        uint32_t data = cookie >> 1;
        if (data & ~DATA_MASK) {
            return 0;
        }

        return data;
    }

    void UpdateKeys();
    void CopyKeysFrom(const SynCookies& other);

    static uint32_t PackData(TcpOptions options);
    static TcpOptions UnpackData(uint32_t data);
    static uint32_t MssToTable(uint32_t mss);
    static uint32_t MssFromTable(uint32_t table_value);

private:
    using key128_t = uint64_t[2];
    key128_t keys_[3];
    uint32_t current_key_ = 0;
    
    static constexpr uint32_t COOKIE_BITS = 24;
    static constexpr uint32_t COOKIE_MASK = (1 << COOKIE_BITS) - 1;

    static constexpr uint32_t MSS_BITS     = 2;
    static constexpr uint32_t SACK_BITS    = 1;
    static constexpr uint32_t WSCALE_BITS  = 4;

    static constexpr uint32_t MSS_OFFSET    = 0;
    static constexpr uint32_t SACK_OFFSET   = MSS_OFFSET + MSS_BITS;
    static constexpr uint32_t WSCALE_OFFSET = SACK_OFFSET + SACK_BITS;

    static constexpr uint32_t MSS_MASK     = ((1 << MSS_BITS) - 1) << MSS_OFFSET;
    static constexpr uint32_t SACK_MASK    = ((1 << SACK_BITS) - 1) << SACK_OFFSET;
    static constexpr uint32_t WSCALE_MASK  = ((1 << WSCALE_BITS) - 1) << WSCALE_OFFSET;
    
    static constexpr uint32_t DATA_MASK = WSCALE_MASK | SACK_MASK | MSS_MASK;

    uint32_t cookie_hash(uint32_t saddr, uint16_t sport, uint32_t keyidx) const;
    uint32_t cookie_hash(common::uint128_t saddr, uint16_t sport, uint32_t keyidx) const;
} __rte_cache_aligned;

}