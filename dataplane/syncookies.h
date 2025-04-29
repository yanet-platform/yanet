#pragma once

#include "type.h"

#include <random>

namespace dataplane::proxy
{

class SynCookies
{
public:
    SynCookies();

    uint32_t GetCookie(uint32_t saddr, uint32_t daddr,
                        uint16_t sport, uint16_t dport, 
                        uint32_t sseq, uint32_t data);
    uint32_t CheckCookie(uint32_t cookie,
                        uint32_t saddr, uint32_t daddr,
                        uint16_t sport, uint16_t dport,
                        uint32_t sseq);

    void UpdateKeys();

    struct TCPOptions {
        uint32_t mss;
        uint32_t sack;
        uint32_t wscale;

        constexpr bool operator==(const TCPOptions& other) const {
            return mss == other.mss && sack == other.sack && wscale == other.wscale;
        }

        constexpr bool operator!=(const TCPOptions& other) const {
            return !(*this == other);
        }
    };

    static uint32_t PackData(TCPOptions options) {
        return ((options.mss << MSS_OFFSET) & MSS_MASK) |
            ((options.sack << SACK_OFFSET) & SACK_MASK) | 
            ((options.wscale << WSCALE_OFFSET) & WSCALE_MASK);
    }

    static TCPOptions UnpackData(uint32_t data) {
        return {
            .mss = (data & MSS_MASK) >> MSS_OFFSET,
            .sack = (data & SACK_MASK) >> SACK_OFFSET,
            .wscale = (data & WSCALE_MASK) >> WSCALE_OFFSET
        };
    }

private:
    uint32_t keys_[3];
    uint32_t current_key_ = 0;
    
    std::random_device rd_;
    std::mt19937 gen_;
    std::uniform_int_distribution<uint32_t> dist_;

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

    uint32_t cookie_hash(uint32_t saddr, uint32_t daddr,
                        uint16_t sport, uint16_t dport,
                        uint32_t keyidx);
};

}