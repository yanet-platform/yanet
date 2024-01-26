#pragma once

#include <arpa/inet.h>
#include <stdio.h>

#include <rte_ether.h>
#include <rte_hash_crc.h>

#include "common/config.h"
#include "common/define.h"

#define YADECAP_UNUSED [[maybe_unused]]

#define YADECAP_LOG_PRINT(msg, args...) fprintf(stdout, msg, ##args)

#define YADECAP_LOG_DEBUG YANET_LOG_DEBUG

#define YADECAP_LOG_INFO YANET_LOG_INFO

#define YADECAP_LOG_WARNING YANET_LOG_WARNING

#define YADECAP_LOG_ERROR YANET_LOG_ERROR

#define YADECAP_CACHE_ALIGNED(name) void* name[0] __rte_aligned(RTE_CACHE_LINE_SIZE)

#define YANET_INLINE_ALWAYS __attribute__((always_inline))
#define YANET_INLINE_NEVER __attribute__((noinline))

#define YADECAP_MEMORY_BARRIER_COMPILE __asm__ __volatile__("" :: \
	                                                            : "memory")
#define YANET_MEMORY_BARRIER_COMPILE __asm__ __volatile__("" :: \
	                                                          : "memory")

#define YADECAP_METADATA(mbuf) ((dataplane::metadata*)((char*)(mbuf)->buf_addr))

#define YADECAP_ETHER_TYPE_MPLS (0x8847)
#define YADECAP_MPLS_HEADER_SIZE 4

#define YANET_PHYSICALPORT_FLAG_IN_DUMP ((uint8_t)(1u << 0))
#define YANET_PHYSICALPORT_FLAG_OUT_DUMP ((uint8_t)(1u << 1))
#define YANET_PHYSICALPORT_FLAG_DROP_DUMP ((uint8_t)(1u << 2))

#define YANET_LOGICALPORT_FLAG_PROMISCUOUSMODE ((uint8_t)(1u << 0))

#define YANET_TRANSLATION_FLAG_RANGE ((uint8_t)(1u << 0))

#define YANET_DREGRESS_FLAG_FIN ((uint8_t)(1u << 0))
#define YANET_DREGRESS_FLAG_IS_BEST ((uint8_t)(1u << 1))
#define YANET_DREGRESS_FLAG_NH_IS_IPV4 ((uint8_t)(1u << 2))

#define YANET_BALANCER_FLAG_ENABLED ((uint8_t)(1u << 0))
#define YANET_BALANCER_FLAG_DST_IPV6 ((uint8_t)(1u << 1))

#define YANET_BALANCER_ID_INVALID (0)

#define IPv4_OUTER_SOURCE_NETWORK_FLAG ((uint8_t)(1u << 0))
#define IPv6_OUTER_SOURCE_NETWORK_FLAG ((uint8_t)(1u << 1))

template<typename TMap,
         typename TValue>
inline bool existValue(const TMap& map, const TValue& value)
{
	for (const auto& iter : map)
	{
		if (iter.second == value)
		{
			return true;
		}
	}

	return false;
}

inline bool equal(const rte_ether_addr& first, const rte_ether_addr& second)
{
	return !memcmp(first.addr_bytes, second.addr_bytes, RTE_ETHER_ADDR_LEN);
}

inline bool equal(const uint8_t* first, const in6_addr& second)
{
	return !memcmp(first, second.__in6_u.__u6_addr8, 16);
}

template<uint32_t size>
inline uint32_t yanet_hash_crc(const void* data, uint32_t init)
{
	return rte_hash_crc(data, size, init);
}

//

static_assert(CONFIG_YADECAP_PORTS_SIZE <= 0xFF, "invalid CONFIG_YADECAP_PORTS_SIZE");

//

namespace dataplane
{

class memory_pointer;
class memory_manager;

}
