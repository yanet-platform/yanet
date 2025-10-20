#pragma once

#include "common/ringlog.h"
#include "metadata.h"

#define TCP_PROXY_FULL_DEBUG 1

namespace dataplane::proxy
{

template<typename ip_header_t>
void PrintDebugPacket(const char* msg, proxy_service_id_t service_id, ip_header_t* ip_header, rte_tcp_hdr* tcp_header)
{
    if constexpr (std::is_same_v<ip_header_t, rte_ipv4_hdr>)
    {
        YANET_LOG_WARNING("%s service_id=%d, %s:%d -> %s:%d, seq=%u, ack=%u\n", msg, service_id,
            common::ipv4_address_t(rte_cpu_to_be_32(ip_header->src_addr)).toString().c_str(), rte_cpu_to_be_16(tcp_header->src_port),
            common::ipv4_address_t(rte_cpu_to_be_32(ip_header->dst_addr)).toString().c_str(), rte_cpu_to_be_16(tcp_header->dst_port),
            rte_cpu_to_be_32(tcp_header->sent_seq), rte_cpu_to_be_32(tcp_header->recv_ack));
    }
    else if constexpr (std::is_same_v<ip_header_t, rte_ipv6_hdr>)
    {
        YANET_LOG_WARNING("%s service_id=%d, %s:%d -> %s:%d, seq=%u, ack=%u\n", msg, service_id,
            common::ipv6_address_t(*(common::uint128_t*)&ip_header->src_addr).toString().c_str(), rte_cpu_to_be_16(tcp_header->src_port),
            common::ipv6_address_t(*(common::uint128_t*)&ip_header->dst_addr).toString().c_str(), rte_cpu_to_be_16(tcp_header->dst_port),
            rte_cpu_to_be_32(tcp_header->sent_seq), rte_cpu_to_be_32(tcp_header->recv_ack));
    }
}

#if TCP_PROXY_FULL_DEBUG == 1
    #define DebugPacket(message, service_id, ip_header, tcp_header) \
    PrintDebugPacket(message, service_id, ip_header, tcp_header);
#else
    #define DebugPacket(message, service_id, ip_header, tcp_header) {}
#endif

inline void DebugFullHeader(rte_mbuf* mbuf, const char* message)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    proxy_service_id_t service_id = metadata->flow.data.proxy_service.id;
    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);

    uint8_t* addr = (uint8_t*)ipv4_header - 18;
    char buffer[1024];
    char* str = buffer;
    for (int i = 0; i < 160; i++)
    {
        str += sprintf(str, "0x%02x ", addr[i]);
    }
    *str = 0;
    
    YANET_LOG_WARNING("%s service=%d, %s:%d -> %s:%d, data=%s\n", message, service_id,
        common::ipv4_address_t(rte_cpu_to_be_32(ipv4_header->src_addr)).toString().c_str(), rte_cpu_to_be_16(tcp_header->src_port),
        common::ipv4_address_t(rte_cpu_to_be_32(ipv4_header->dst_addr)).toString().c_str(), rte_cpu_to_be_16(tcp_header->dst_port),
        buffer);
}

}
