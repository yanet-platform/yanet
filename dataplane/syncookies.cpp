#include "syncookies.h"

#include "rte_hash_crc.h"

#include <random>

namespace dataplane::proxy
{

SynCookies::SynCookies() 
    : keys_{}, current_key_(1),
    rd_(), gen_(rd_()), dist_(0, std::numeric_limits<uint32_t>::max()) 
{
    UpdateKeys();
}

uint32_t SynCookies::GetCookie(uint32_t saddr, uint32_t daddr,
                                                    uint16_t sport, uint16_t dport,
                                                    uint32_t sseq, uint32_t data)
{
    uint32_t cookie = cookie_hash(saddr, daddr, sport, dport, 0) + sseq +
                    (current_key_ << COOKIE_BITS) +
                    ((cookie_hash(saddr, daddr, sport, dport, current_key_) + data) & COOKIE_MASK);

    return cookie;
}
 
uint32_t SynCookies::CheckCookie(uint32_t cookie,
                                uint32_t saddr, uint32_t daddr,
                                uint16_t sport, uint16_t dport,
                                uint32_t sseq)
{
    cookie -= cookie_hash(saddr, daddr, sport, dport, 0) + sseq;
    uint32_t keyidx = (cookie >> COOKIE_BITS);
    if (1 > keyidx || keyidx > 2) {
        return 0;
    }

    uint32_t data = (cookie - cookie_hash(saddr, daddr, sport, dport, keyidx)) & COOKIE_MASK;
    if (data & ~DATA_MASK) {
        return 0;
    }

    return data;
}

void SynCookies::UpdateKeys()
{
    current_key_ = 3 - current_key_; // switch between 1 and 2
    keys_[current_key_] = dist_(gen_);
}

uint32_t SynCookies::cookie_hash(uint32_t saddr, uint32_t daddr,
                                uint16_t sport, uint16_t dport, 
                                uint32_t keyidx)
{
    const uint32_t data[3] = {saddr, daddr, (uint32_t)sport << 16 | (uint32_t)dport};
	return rte_hash_crc(data, sizeof(data), keys_[keyidx]);
}

}