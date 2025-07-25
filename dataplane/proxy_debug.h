#pragma once

#include "common/ringlog.h"

#define TCP_PROXY_FULL_DEBUG 0

namespace dataplane::proxy
{

#if TCP_PROXY_FULL_DEBUG == 1
    #define DebugPacket(message, service_id, ipv4_header, tcp_header) \
    YANET_LOG_WARNING("%s service_id=%d, %s:%d -> %s:%d, seq=%u, ack=%u\n", message, service_id, \
        common::ipv4_address_t(rte_cpu_to_be_32(ipv4_header->src_addr)).toString().c_str(), rte_cpu_to_be_16(tcp_header->src_port), \
        common::ipv4_address_t(rte_cpu_to_be_32(ipv4_header->dst_addr)).toString().c_str(), rte_cpu_to_be_16(tcp_header->dst_port), \
        rte_cpu_to_be_32(tcp_header->sent_seq), rte_cpu_to_be_32(tcp_header->recv_ack))
#else
    #define DebugPacket(message, service_id, ipv4_header, tcp_header) {}
#endif

}
