#pragma once


#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "type.h"

inline uint16_t csum_calc(uint32_t const* buf,
                          unsigned int len)
{
	uint64_t sum = 0;

	while (len--)
	{
		sum += *(buf++);
	}

	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

inline uint16_t csum_plus(uint16_t val0,
                          uint16_t val1)
{
	uint16_t sum = val0 + val1;

	if (sum < val0)
	{
		++sum;
	}

	return sum;
}

inline uint16_t csum_plus(uint16_t val0,
                          uint16_t val1,
                          uint16_t val2,
                          uint16_t val3,
                          uint16_t val4)
{
	uint32_t sum = (uint32_t)val0 + val1 + val2 + val3 + val4;

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

inline uint16_t csum_minus(uint16_t val0,
                           uint16_t val1)
{
	uint16_t sum = val0 - val1;

	if (sum > val0)
	{
		--sum;
	}

	return sum;
}

inline uint16_t csum_minus(uint16_t val0,
                           uint16_t val1,
                           uint16_t val2,
                           uint16_t val3,
                           uint16_t val4)
{
	uint32_t sum = (uint32_t)val1 + val2 + val3 + val4;

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return csum_minus(val0, sum);
}

inline uint16_t yanet_checksum(void const* pointer,
                               unsigned int len)
{
	return csum_calc((uint32_t const*)pointer, len / 4);
}

inline void yanet_ipv4_checksum(rte_ipv4_hdr* ipv4Header)
{
	ipv4Header->hdr_checksum = 0;
	ipv4Header->hdr_checksum = rte_ipv4_cksum(ipv4Header); ///< @todo
}

inline void yanet_icmpv4_checksum(icmp_header_t* icmpHeader,
                                  unsigned int len)
{
	icmpHeader->checksum = 0;
	icmpHeader->checksum = ~rte_raw_cksum(icmpHeader, len);
}

inline void yanet_icmpv6_checksum(icmp_header_t* icmpHeader,
                                  unsigned int len,
                                  const uint8_t* source,
                                  const uint8_t* destination)
{
	icmpHeader->checksum = 0;

	uint32_t sum = __rte_raw_cksum(source, 16, 0);
	sum = __rte_raw_cksum(destination, 16, sum);

	uint32_t blen = rte_cpu_to_be_32(len);
	sum = __rte_raw_cksum(&blen, 4, sum);

	uint32_t nextHeader = rte_cpu_to_be_32(IPPROTO_ICMPV6);
	sum = __rte_raw_cksum(&nextHeader, 4, sum);

	sum = __rte_raw_cksum(icmpHeader, len, sum);

	icmpHeader->checksum = ~__rte_raw_cksum_reduce(sum);
}

inline void yanet_tcp_checksum_v6_to_v4(rte_tcp_hdr* tcpHeader,
                                        uint16_t checksum6,
                                        uint16_t checksum4)
{
	uint16_t csum = ~tcpHeader->cksum;
	csum = csum_minus(csum, checksum6);
	csum = csum_plus(csum, checksum4);
	tcpHeader->cksum = ~csum;
}

inline void yanet_udp_checksum_v6_to_v4(rte_udp_hdr* udpHeader,
                                        uint16_t checksum6,
                                        uint16_t checksum4)
{
	if (udpHeader->dgram_cksum)
	{
		uint16_t csum = ~udpHeader->dgram_cksum;
		csum = csum_minus(csum, checksum6);
		csum = csum_plus(csum, checksum4);
		csum = ~csum;
		udpHeader->dgram_cksum = csum ?: 0xffff;
	}
}

inline void yanet_icmp_checksum_v6_to_v4(icmpv6_header_t* icmpHeader,
                                         uint16_t checksum6,
                                         uint16_t checksum4)
{
	uint16_t csum = ~icmpHeader->checksum;
	csum = csum_minus(csum, checksum6);
	csum = csum_plus(csum, checksum4);
	icmpHeader->checksum = ~csum;
}

inline void yanet_tcp_checksum_v4_to_v6(rte_tcp_hdr* tcpHeader,
                                        uint16_t checksum4,
                                        uint16_t checksum6)
{
	uint16_t csum = ~tcpHeader->cksum;
	csum = csum_minus(csum, checksum4);
	csum = csum_plus(csum, checksum6);
	tcpHeader->cksum = ~csum;
}

inline void yanet_udp_checksum_v4_to_v6(rte_udp_hdr* udpHeader,
                                        uint16_t checksum4,
                                        uint16_t checksum6)
{
	if (udpHeader->dgram_cksum)
	{
		uint16_t csum = ~udpHeader->dgram_cksum;
		csum = csum_minus(csum, checksum4);
		csum = csum_plus(csum, checksum6);
		csum = ~csum;
		udpHeader->dgram_cksum = csum ?: 0xffff;
	}
}

inline void yanet_icmp_checksum_v4_to_v6(icmpv4_header_t* icmpHeader,
                                         uint16_t checksum4,
                                         uint16_t checksum6)
{
	uint16_t csum = ~icmpHeader->checksum;
	csum = csum_minus(csum, checksum4);
	csum = csum_plus(csum, checksum6);
	icmpHeader->checksum = ~csum;
}
