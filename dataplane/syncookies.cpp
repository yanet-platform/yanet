#include "common/config.h"
#include "syncookies.h"

#include "rte_hash_crc.h"
#include "proxy.h"

#include <random>

namespace dataplane::proxy
{

static uint32_t const mss_tab_values_[] = { 536, 1300, 1440, 1460 };

uint32_t SynCookies::MssToTable(uint32_t mss)
{
    uint32_t index;
    for (index = 3; index; index--)
    {
        if (mss >= mss_tab_values_[index])
        {
            break;
        }
    }
    return index;
}

uint32_t SynCookies::MssFromTable(uint32_t table_value)
{
    return mss_tab_values_[table_value];
}

uint32_t SynCookies::PackData(TcpOptions options) {
    return ((MssToTable(options.mss) << MSS_OFFSET) & MSS_MASK) |
        (((uint32_t)options.sack_permitted << SACK_OFFSET) & SACK_MASK) | 
        (((uint32_t)options.window_scaling << WSCALE_OFFSET) & WSCALE_MASK);
}

TcpOptions SynCookies::UnpackData(uint32_t data) {
    return {
        .timestamp_value = 0,
        .timestamp_echo = 0,
        .mss = (uint16_t)MssFromTable((data & MSS_MASK) >> MSS_OFFSET),
        .sack_permitted = (uint8_t)((data & SACK_MASK) >> SACK_OFFSET),
        .window_scaling = (uint8_t)((data & WSCALE_MASK) >> WSCALE_OFFSET),
        .sack_count = 0,
        .sack_start = {0, 0, 0, 0},
        .sack_finish = {0, 0, 0, 0}
    };
}

SynCookies::SynCookies() 
    : keys_{}, current_key_(1)
{
    #ifdef CONFIG_YADECAP_AUTOTEST
    keys_[0][0] = 0;
    keys_[0][1] = 0;
    #else
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());
    keys_[0][0] = dist(gen);
    keys_[0][1] = dist(gen);
    #endif
    UpdateKeys();
}
 
void SynCookies::UpdateKeys()
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());
    current_key_ = 3 - current_key_; // switch between 1 and 2
    keys_[current_key_][0] = dist(gen);
    keys_[current_key_][1] = dist(gen);
    
#ifdef CONFIG_YADECAP_AUTOTEST
    current_key_ = 1;
    keys_[current_key_][0] = 0;
    keys_[current_key_][1] = 0;
#endif
}

void SynCookies::CopyKeysFrom(const SynCookies& other)
{
    for (int i1 = 0; i1 < 3; i1++)
    {
        for (int i2 = 0; i2 < 2; i2++)
        {
            keys_[i1][i2] = other.keys_[i1][i2];
        }
    }
    current_key_ = other.current_key_;
}

uint32_t SynCookies::cookie_hash(uint32_t saddr, uint16_t sport, uint32_t keyidx) const
{
    const uint64_t data[] = {(uint64_t)saddr << 32 | (uint64_t)sport,
                                keys_[keyidx][0], keys_[keyidx][1]};
	return rte_hash_crc(data, sizeof(data), 0);
}

uint32_t SynCookies::cookie_hash(common::uint128_t saddr, uint16_t sport, uint32_t keyidx) const
{
    const uint64_t data[] = {(uint64_t)(saddr >> 64), (uint64_t)saddr, (uint64_t)sport,
                             keys_[keyidx][0], keys_[keyidx][1]};
	return rte_hash_crc(data, sizeof(data), 0);
}

}