#pragma once

#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <variant>

#include "checksum.h"
#include "type.h"
#include <rte_mbuf.h>

inline bool yanet_icmp_translate_v6_to_v4(icmp_header_t* icmpHeader,
                                          uint16_t length,
                                          uint16_t checksum6)
{
	uint8_t type = 0;

	if (icmpHeader->type == ICMP6_ECHO_REQUEST)
	{
		type = ICMP_ECHO;
	}
	else if (icmpHeader->type == ICMP6_ECHO_REPLY)
	{
		type = ICMP_ECHOREPLY;
	}
	else
	{
		return false;
	}

	uint16_t csum = ~icmpHeader->checksum;

	csum = csum_minus(csum,
	                  checksum6,
	                  rte_cpu_to_be_16(IPPROTO_ICMPV6),
	                  rte_cpu_to_be_16(length),
	                  *(uint16_t*)icmpHeader);

	icmpHeader->type = type;

	csum = csum_plus(csum, *(uint16_t*)icmpHeader);

	icmpHeader->checksum = ~csum;

	return true;
}

inline bool yanet_icmp_translate_v4_to_v6(icmp_header_t* icmpHeader,
                                          uint16_t length,
                                          uint16_t checksum6)
{
	uint8_t type = 0;

	if (icmpHeader->type == ICMP_ECHO)
	{
		type = ICMP6_ECHO_REQUEST;
	}
	else if (icmpHeader->type == ICMP_ECHOREPLY)
	{
		type = ICMP6_ECHO_REPLY;
	}
	else
	{
		return false;
	}

	uint16_t csum = ~icmpHeader->checksum;

	csum = csum_minus(csum, *(uint16_t*)icmpHeader);

	icmpHeader->type = type;

	csum = csum_plus(csum,
	                 checksum6,
	                 rte_cpu_to_be_16(IPPROTO_ICMPV6),
	                 rte_cpu_to_be_16(length),
	                 *(uint16_t*)icmpHeader);

	icmpHeader->checksum = ~csum;

	return true;
}

namespace yanet::icmp
{

enum class TypePackage
{
	TimeExceeded = 0
};

struct CreateTimeExceededPackagePayload
{
	rte_mbuf* mbuf_source;
	const dataplane::globalBase::host_config_t host_config;
};

using CreatePackagePayload = std::variant<CreateTimeExceededPackagePayload>;

uint32_t create_icmp_package(TypePackage type, rte_mbuf* mbuf_target, const CreatePackagePayload& payload);
uint32_t create_icmp_package_time_exceeded(rte_mbuf* mbuf_target, const CreateTimeExceededPackagePayload& payload);
}
