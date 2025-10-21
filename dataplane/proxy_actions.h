#pragma once

#include <rte_tcp.h>

#include "common/counters.h"

#include "checksum.h"
#include "globalbase.h"
#include "proxy.h"
#include "type.h"

namespace dataplane::proxy
{

struct WorkerInfo
{
    dataplane::globalBase::generation* globalBase;
    uint64_t* counters;
    uint32_t worker_id;
    common::ringlog::LogInfo* ringlog;
    uint32_t current_time_sec;
    uint64_t current_time_ms;
};

inline uint32_t add_cpu_32(uint32_t value, int32_t added)
{
    return rte_cpu_to_be_32(rte_be_to_cpu_32(value) + added);
}

inline uint32_t sub_cpu_32(uint32_t value, int32_t added)
{
    return rte_cpu_to_be_32(rte_be_to_cpu_32(value) - added);
}

inline uint16_t shift_cpu_16(uint16_t value, int32_t shift)
{
    uint32_t result = (shift > 0 ? uint32_t(rte_be_to_cpu_16(value)) >> shift : uint32_t(rte_be_to_cpu_16(value)) << (-shift));
    return rte_cpu_to_be_16(std::min(result, 0xffffu));
}

inline void SwapAddresses(rte_ipv4_hdr* ipv4_header)
{
    rte_be32_t tmp = ipv4_header->src_addr;
    ipv4_header->src_addr = ipv4_header->dst_addr;
    ipv4_header->dst_addr = tmp;
}

inline void SwapAddresses(rte_ipv6_hdr* ipv6_header)
{
    uint8_t tmp_for_swap[sizeof(ipv6_header->src_addr)];
    rte_memcpy(tmp_for_swap, ipv6_header->src_addr, sizeof(tmp_for_swap));
    rte_memcpy(ipv6_header->src_addr, ipv6_header->dst_addr, sizeof(ipv6_header->src_addr));
    rte_memcpy(ipv6_header->dst_addr, tmp_for_swap, sizeof(ipv6_header->dst_addr));
}

inline void SwapPorts(rte_tcp_hdr* tcp_header)
{
    rte_be16_t tmp = tcp_header->src_port;
    tcp_header->src_port = tcp_header->dst_port;
    tcp_header->dst_port = tmp;
}

inline void UpdateCheckSums(rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    ipv4_header->hdr_checksum = 0;
    ipv4_header->hdr_checksum = rte_ipv4_cksum(ipv4_header);
    tcp_header->cksum = 0;
    tcp_header->cksum = rte_ipv4_udptcp_cksum(ipv4_header, tcp_header);
}

inline void UpdateCheckSums(rte_ipv6_hdr* ipv6_header, rte_tcp_hdr* tcp_header)
{
    tcp_header->cksum = 0;
    tcp_header->cksum = rte_ipv6_udptcp_cksum(ipv6_header, tcp_header);
}

inline bool NonEmptyTcpData(rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
    return (rte_be_to_cpu_16(ipv4_header->total_length) != sizeof(rte_ipv4_hdr) + tcp_header_len);
}

inline uint16_t ip_phdr_cksum(rte_ipv4_hdr* ipv4_header)
{
    return rte_ipv4_phdr_cksum(ipv4_header, 0);
}

inline uint16_t ip_phdr_cksum(rte_ipv6_hdr* ipv6_header)
{
    return rte_ipv6_phdr_cksum(ipv6_header, 0);
}

template<typename ip_header_t>
uint32_t CheckSumBeforeUpdate(ip_header_t* ip_header, rte_tcp_hdr* tcp_header)
{
    uint32_t chksum_work = tcp_header->cksum + ip_phdr_cksum(ip_header);
    tcp_header->cksum = 0;
    chksum_work += rte_raw_cksum(tcp_header, (tcp_header->data_off >> 4) << 2);
    return chksum_work;
}

template<typename ip_header_t>
void CheckSumAfterUpdate(const dataplane::proxy::proxy_service_t& service, ip_header_t* ip_header, rte_tcp_hdr* tcp_header, uint32_t chksum_work, uint32_t size_data)
{
    if ((service.config.debug_flags & proxy_service_config_t::flag_ignore_optimize_checksum) != 0)
    {
        UpdateCheckSums(ip_header, tcp_header);
        return;
    }

    if constexpr (std::is_same_v<ip_header_t, rte_ipv4_hdr>)
    {
        ip_header->hdr_checksum = 0;
        ip_header->hdr_checksum = rte_ipv4_cksum(ip_header);
    }

    uint32_t chksum_plus = ip_phdr_cksum(ip_header) + rte_raw_cksum(tcp_header, ((tcp_header->data_off >> 4) << 2) + size_data);

    chksum_work = __rte_raw_cksum_reduce(chksum_work);
    chksum_plus = __rte_raw_cksum_reduce(chksum_plus);
    uint16_t chksum = chksum_work - chksum_plus;
    if (chksum_work < chksum_plus)
    {
        chksum--;
    }

    tcp_header->cksum = chksum;
}

#define addr_t(addr) (*(addr_type<ip_header_t>*)&addr)

template<typename ip_header_t>
void PrepareSynAckToClient(const proxy_service_t& service, rte_mbuf* mbuf,
                           ip_header_t* ip_header, rte_tcp_hdr* tcp_header,
                           uint64_t* counters, uint32_t current_time_sec)
{
    TcpOptions tcp_options;
    memset(&tcp_options, 0, sizeof(tcp_options));
    if (!tcp_options.Read(tcp_header)) {
        counters[service.config.counter_id + (tCounterId)::proxy::service_counter::pkts_with_corrupted_tcp_opts_client]++;
        // DebugFullHeader(mbuf, "PrepareSynAckToClient");
    }
    tcp_options.sack_permitted &= service.config.tcp_options.use_sack;
    tcp_options.mss = std::min(tcp_options.mss, (uint16_t)service.config.tcp_options.mss);

    // TODO: IPv6 COOKIES
    uint32_t cookie_data = SynCookies::PackData(tcp_options);
    uint32_t addr;
    if constexpr (std::is_same_v<ip_header_t, rte_ipv6_hdr>)
        memcpy(&addr, (uint8_t*)(&ip_header->src_addr) + 12, sizeof(addr));
    else
        addr = ip_header->src_addr;
    uint32_t cookie = service.syn_cookie.GetCookie(addr_t(ip_header->src_addr), tcp_header->src_port,
                                                   tcp_header->sent_seq, cookie_data);
    // YANET_LOG_WARNING("\tcookie_data=%d, cookie=%u, seq=%u\n", cookie_data, cookie, rte_be_to_cpu_32(tcp_header->sent_seq));

    tcp_options.window_scaling = service.config.tcp_options.winscale;
    if (tcp_options.timestamp_value != 0 && service.config.tcp_options.timestamps)
    {
        tcp_options.timestamp_echo = tcp_options.timestamp_value;
        tcp_options.timestamp_value = current_time_sec;
#ifdef CONFIG_YADECAP_AUTOTEST
        tcp_options.timestamp_value = 1;
#endif
    }
    else
    {
        tcp_options.timestamp_echo = 0;
        tcp_options.timestamp_value = 0;
    }
    if (service.config.send_proxy_header)
    {
        tcp_options.mss -= int(sizeof(proxy_v2_ipv4_hdr));
    }
    tcp_options.WriteSYN(mbuf, ip_header, tcp_header);

    SwapAddresses(ip_header);
    if constexpr (std::is_same_v<ip_header_t, rte_ipv6_hdr>)
        ip_header->hop_limits = 64;
    else
        ip_header->time_to_live = 64;
    tcp_header->recv_ack = add_cpu_32(tcp_header->sent_seq, 1);
    tcp_header->sent_seq = rte_cpu_to_be_32(cookie);
    tcp_header->tcp_flags = TCP_SYN_FLAG | TCP_ACK_FLAG;
    tcp_header->rx_win = 0;
    SwapPorts(tcp_header);
}

template<typename ip_header_t>
void PrepareSynToService(const proxy_service_t& service, ip_header_t* ip_header, rte_tcp_hdr* tcp_header, uint64_t local)
{
    if constexpr (std::is_same_v<ip_header_t, rte_ipv6_hdr>)
        memcpy(&ip_header->src_addr, service.config.ipv6_pool_prefix.address().data(), sizeof(ip_header->src_addr));
    LocalPool::UnpackTupleSrc(local, ip_header, tcp_header);
    if (service.config.send_proxy_header)
    {
        // При использовании ProxyHeader уменьшаем значение SEQ полученное от клиента
        tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, sizeof(proxy_v2_ipv4_hdr));
    }

    if constexpr (std::is_same_v<ip_header_t, rte_ipv6_hdr>)
        memcpy(&ip_header->dst_addr, &service.config.upstream_addr6, sizeof(ip_header->dst_addr));
    else
        ip_header->dst_addr = service.config.upstream_addr4;
    tcp_header->dst_port = service.config.upstream_port;
}

template<typename ip_header_t>
inline bool ActionClientOnSyn(rte_mbuf* mbuf, dataplane::proxy::WorkerInfo& worker_info)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    proxy_service_id_t service_id = metadata->flow.data.proxy_service.id;
    dataplane::proxy::proxy_service_t& service = worker_info.globalBase->proxy_services[service_id];

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_packets]++;
    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_bytes] += mbuf->pkt_len;

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::syn_count]++;

    ip_header_t* ip_header = rte_pktmbuf_mtod_offset(mbuf, ip_header_t*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_client_syn", service_id, ip_header, tcp_header);
    RINGLOG_CONDITION(worker_info.globalBase->ringlog_enabled && worker_info.globalBase->ringlog_value == ip_header->src_addr);
    bool action = true;

    if constexpr (std::is_same_v<ip_header_t, rte_ipv4_hdr>)
    {
        if (service.connection_limit_table.Exists(ip_header->src_addr, worker_info.current_time_ms))
        {
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_connection_limit]++;
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_packets]++;
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_bytes] += mbuf->pkt_len;
            if (service.connection_limit_table.Mode() == common::proxy::limit_mode::on) return false;
        }
        if (!metadata->flow.data.proxy_service.whitelist
            && service.rate_limit_table.Check(ip_header->src_addr, worker_info.current_time_ms) != RateLimitResult::Pass)
        {
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_rate_limit]++;
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_packets]++;
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_bytes] += mbuf->pkt_len;
            if (service.rate_limit_table.Mode() == common::proxy::limit_mode::on) return false;
        }
    }

    bool is_syn_ack = false;
    uint32_t chksum_work = CheckSumBeforeUpdate(ip_header, tcp_header);
    SynConnectionData<ip_header_t> syn_connection_data;
    auto& syn_connections = service.tables.syn_connections<ip_header_t>();
    switch (syn_connections.FindAndLock(addr_t(ip_header->src_addr), tcp_header->src_port,
                                        worker_info.current_time_ms, syn_connection_data, !service.config.EnabledFlag(dataplane::proxy::proxy_service_config_t::flag_dont_use_bucket_optimization)))
    {
        case TableSearchResult::Overflow:
        {
            DebugPacket("\tsyn.FindAndLock=Overflow", service_id, ip_header, tcp_header);
		    RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynOverflow, tcp_header->src_port, 0));

            PrepareSynAckToClient(service, mbuf, ip_header, tcp_header, worker_info.counters, worker_info.current_time_sec);
            is_syn_ack = true;
            break;
        }
        case TableSearchResult::Found:
        {
            DebugPacket("\tsyn.FindAndLock=Found", service_id, ip_header, tcp_header);
            RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynFound, tcp_header->src_port, syn_connection_data.connection->local));
            if (++syn_connection_data.connection->retransmits_from_client > 3)
            {
                PrepareSynAckToClient(service, mbuf, ip_header, tcp_header, worker_info.counters, worker_info.current_time_sec);
                is_syn_ack = true;
            }
            else
            {
                PrepareSynToService(service, ip_header, tcp_header, syn_connection_data.connection->local);
            }
            break;
        }
        case TableSearchResult::NotFound:
        {
            DebugPacket("\tsyn.FindAndLock=NotFound", service_id, ip_header, tcp_header);
            uint64_t local = service.tables.local_pool.Allocate(worker_info.worker_id, addr_t(ip_header->src_addr), tcp_header->src_port);
            if (local == 0)
            {
                DebugPacket("failed to allocate local address", service_id, ip_header, tcp_header);
                RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynErrLocal, tcp_header->src_port, 0));
                worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::failed_local_pool_allocation]++;
                action = false;
            }
            else
            {
                RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynAdd, tcp_header->src_port, local));
                syn_connection_data.Init(addr_t(ip_header->src_addr), tcp_header->src_port, worker_info.current_time_ms);
                syn_connection_data.connection->local = local;
                syn_connection_data.connection->client_start_seq = tcp_header->sent_seq;
                
                PrepareSynToService(service, ip_header, tcp_header, local);
                worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::new_syn_connections]++;
            }
            break;
        }
    }
    syn_connection_data.Unlock();

    if (action)
    {
        CheckSumAfterUpdate(service, ip_header, tcp_header, chksum_work, 0);
        if (is_syn_ack)
        {
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::syn_cookie_count]++;
        }
        else
        {
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_client_packets]++;
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_client_bytes] += mbuf->pkt_len;
        }
    }
    else
    {
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_bytes] += mbuf->pkt_len;
    }

    return action;
}

inline bool ActionClientOnSyn4(rte_mbuf* mbuf, WorkerInfo& worker_info)
{
    return ActionClientOnSyn<rte_ipv4_hdr>(mbuf, worker_info);
}

inline bool ActionClientOnSyn6(rte_mbuf* mbuf, WorkerInfo& worker_info)
{
    return ActionClientOnSyn<rte_ipv6_hdr>(mbuf, worker_info);
}

uint32_t AddProxyHeader(const proxy_service_t& service, rte_mbuf* mbuf, dataplane::metadata* metadata,
                        rte_ipv4_hdr** ipv4_header, rte_tcp_hdr** tcp_header, uint32_t src_addr, uint16_t src_port);

uint32_t CheckSynCookie(const proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header);
bool CheckSynCookie(rte_mbuf* mbuf,
                    dataplane::proxy::WorkerInfo& worker_info,
                    dataplane::proxy::proxy_service_t& service,
                    dataplane::metadata* metadata,
                    rte_ipv4_hdr*& ipv4_header,
                    rte_tcp_hdr*& tcp_header,
                    ServiceConnectionData4& service_connection_data,
                    uint32_t flags,
                    bool reuse_connection);

inline bool ActionClientOnAck(rte_mbuf* mbuf, dataplane::proxy::WorkerInfo& worker_info)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    proxy_service_id_t service_id = metadata->flow.data.proxy_service.id;
    dataplane::proxy::proxy_service_t& service = worker_info.globalBase->proxy_services[service_id];

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_packets]++;
    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_bytes] += mbuf->pkt_len;

    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_client_ack", service_id, ipv4_header, tcp_header);
    RINGLOG_CONDITION(worker_info.globalBase->ringlog_enabled && worker_info.globalBase->ringlog_value == ipv4_header->src_addr);
    bool action = true;
    uint32_t chksum_work = CheckSumBeforeUpdate(ipv4_header, tcp_header);
    uint32_t size_proxy_header = 0;

    if (service.connection_limit_table.Exists(ipv4_header->src_addr, worker_info.current_time_ms))
    {
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_connection_limit]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_bytes] += mbuf->pkt_len;
        if (service.connection_limit_table.Mode() == common::proxy::limit_mode::on) return false;
    }

    ServiceConnectionData4 service_connection_data;
    switch (service.tables.service_connections4.FindAndLock(ipv4_header->src_addr, tcp_header->src_port, worker_info.current_time_ms, service_connection_data, false))
    {
        case TableSearchResult::Overflow:
        {
            DebugPacket("\tservice.FindAndLock=Overflow", service_id, ipv4_header, tcp_header);
            RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::AckOverflow, tcp_header->src_port, 0));
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::service_bucket_overflow]++;
            action = false;
            break;
        }
        case TableSearchResult::Found:
        {
            DebugPacket("\tservice.FindAndLock=Found", service_id, ipv4_header, tcp_header);
            RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::AckFound, tcp_header->src_port, service_connection_data.connection->local));

            if ((service_connection_data.connection->service_flags & TCP_RST_FLAG) != 0)
            {
                action = CheckSynCookie(mbuf, worker_info, service, metadata, ipv4_header, tcp_header, service_connection_data, 0, true);
            }
            else
            {
                // check non-empty tcp-data packet
                if (NonEmptyTcpData(ipv4_header, tcp_header))
                {
                    service_connection_data.connection->flags |= Connection::flag_nonempty_ack_from_client;
                }
                service_connection_data.connection->client_flags |= tcp_header->tcp_flags;

                if (tcp_header->sent_seq == service_connection_data.connection->client_start_seq)
                {
                    // todo - add check + only syn-cookie
                    if (service.config.EnabledFlag(dataplane::proxy::proxy_service_config_t::flag_ignore_size_update_detections))
                    {
                        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::ignored_size_update_detections]++;
                        action = false;
                    }
                    else
                    {
                        TcpOptions tcp_options;
                        memset(&tcp_options, 0, sizeof(tcp_options));
                        if (!tcp_options.Read(tcp_header)) {
                            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::pkts_with_corrupted_tcp_opts_client]++;
                            // DebugFullHeader(mbuf, "ActionClientOnAck 1");
                        }

                        LocalPool::UnpackTupleSrc(service_connection_data.connection->local, ipv4_header, tcp_header);
                        tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, (service.config.send_proxy_header ? sizeof(proxy_v2_ipv4_hdr) : 0));

                        // todo - need save options in ServiceConnections !!!
                        tcp_options.mss = 1300;
                        tcp_options.sack_permitted = true;
                        tcp_options.window_scaling = 5;
                        tcp_options.timestamp_echo = 0;

                        tcp_options.Write(mbuf, &ipv4_header, &tcp_header);
                        ipv4_header->time_to_live = 64;
                        tcp_header->recv_ack = 0;
                        tcp_header->tcp_flags = TCP_SYN_FLAG;
                    }
                }
                else
                {
                    uint32_t src_addr = ipv4_header->src_addr;
                    uint16_t src_port = tcp_header->src_port;
                    LocalPool::UnpackTupleSrc(service_connection_data.connection->local, ipv4_header, tcp_header);

                    bool is_first_ack = (tcp_header->sent_seq == add_cpu_32(service_connection_data.connection->client_start_seq, 1)); // todo - check time
                    
                    TcpOptions tcp_options;
                    memset(&tcp_options, 0, sizeof(tcp_options));
                    if (!tcp_options.ReadOnlyTimestampsAndSack(tcp_header)) {
                        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::pkts_with_corrupted_tcp_opts_client]++;
                        // DebugFullHeader(mbuf, "ActionClientOnAck 2");
                    }
                    // YANET_LOG_WARNING("\t\t!!!! ReadOnlyTimestampsAndSack, timestamp=(%u, %u), sack_count=%d\n", tcp_options.timestamp_value, tcp_options.timestamp_echo, tcp_options.sack_count);
                    
                    // work with SACK
                    if ((service_connection_data.connection->flags & Connection::flag_clear_sack) != 0)
                    {
                        tcp_options.sack_count = 0;
                    }
                    for (uint32_t index = 0; index < tcp_options.sack_count; index++)
                    {
                        tcp_options.sack_start[index] -= service_connection_data.connection->shift_server;
                        tcp_options.sack_finish[index] -= service_connection_data.connection->shift_server;
                    }

                    // work with timestamps
                    service_connection_data.connection->timestamp_client_last = tcp_options.timestamp_value;
                    if ((tcp_options.timestamp_value == 0) || 
                        ((service_connection_data.connection->flags & (Connection::flag_no_timestamps | Connection::flag_timestamp_fail)) != 0))
                    {
                        tcp_options.timestamp_value = 0;
                        tcp_options.timestamp_echo = 0;
                    }
                    else
                    {
                        tcp_options.timestamp_echo -= service_connection_data.connection->timestamp_shift;
                    }                    
                    tcp_options.Write(mbuf, &ipv4_header, &tcp_header);
                    

                    tcp_header->recv_ack = sub_cpu_32(tcp_header->recv_ack, service_connection_data.connection->shift_server);
                    if (is_first_ack && service.config.send_proxy_header)
                    {
                        tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, sizeof(proxy_v2_ipv4_hdr));
                        size_proxy_header = AddProxyHeader(service, mbuf, metadata, &ipv4_header, &tcp_header, src_addr, src_port);
                    }
                }
            }

            break;
        }
        case TableSearchResult::NotFound:
        {
            DebugPacket("\tservice.FindAndLock=NotFound", service_id, ipv4_header, tcp_header);
            uint32_t flags = (NonEmptyTcpData(ipv4_header, tcp_header) ? Connection::flag_nonempty_ack_from_client : 0);

            SynConnectionData4 syn_connection_data;
            if (service.tables.syn_connections4.FindAndLock(ipv4_header->src_addr, tcp_header->src_port, worker_info.current_time_ms, syn_connection_data, false) == TableSearchResult::Found)
            {
                DebugPacket("\tsyn.FindAndLock=Found", service_id, ipv4_header, tcp_header);
                if (!syn_connection_data.connection->server_answer)
                {
                    // ack, but server didn't answer
                    DebugPacket("\tno answer from server", service_id, ipv4_header, tcp_header);
                    RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::AckNoServiceAnswer, tcp_header->src_port, 0));

                    syn_connection_data.Unlock();
                    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::ack_without_service_answer]++;
                    action = false;
                }
                else if (!service.config.EnabledFlag(dataplane::proxy::proxy_service_config_t::flag_ignore_check_client_first_ack)
                    && (syn_connection_data.connection->server_seq != rte_be_to_cpu_32(tcp_header->recv_ack) - 1))
                {
                    // ack, but ack number is invalid
                    // YANET_LOG_WARNING("Invalid ACK: server_seq=%u, ack=%u\n", syn_connection_data.connection->server_seq, rte_be_to_cpu_32(tcp_header->recv_ack));
                    RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::AckBadFirstAck, tcp_header->src_port, 0));

                    DebugPacket("\tbad ack", service_id, ipv4_header, tcp_header);
                    syn_connection_data.Unlock();
                    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::ack_invalid_ack_number]++;
                    action = false;
                }
                else
                {
                    RateLimitResult result = RateLimitResult::Pass;
                    if (!metadata->flow.data.proxy_service.whitelist)
                        result = service.rate_limit_table.CheckAndConsume(ipv4_header->src_addr, worker_info.current_time_ms);
                    if (result != RateLimitResult::Pass)
                    {
                        if (result == RateLimitResult::Overflow)
                            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::rate_limiter_overflow]++;
                        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_rate_limit]++;
                    }
                    if (result == RateLimitResult::Pass || service.rate_limit_table.Mode() != common::proxy::limit_mode::on)
                    {
                        DebugPacket("\tadd to service", service_id, ipv4_header, tcp_header);
                        RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::AckNew, tcp_header->src_port, syn_connection_data.connection->local));
    
                        uint32_t src_addr = ipv4_header->src_addr;
                        uint16_t src_port = tcp_header->src_port;
                        service_connection_data.Init(ipv4_header->src_addr, tcp_header->src_port, worker_info.current_time_ms);
                        LocalPool::UnpackTupleSrc(syn_connection_data.connection->local, ipv4_header, tcp_header);
                        service_connection_data.connection->client_start_seq = syn_connection_data.connection->client_start_seq;
                        syn_connection_data.bucket->Clear(syn_connection_data.idx);
                        syn_connection_data.Unlock();
                        
                        service_connection_data.connection->flags = flags;
                        service_connection_data.connection->client_flags |= tcp_header->tcp_flags;
                        service_connection_data.connection->local = LocalPool::PackTuple(ipv4_header->src_addr, tcp_header->src_port);
                        if (metadata->flow.data.proxy_service.whitelist)
                        {
                            service_connection_data.connection->SetFlag(Connection::flag_whitelist);
                        }
                        
                        if (service.config.send_proxy_header)
                        {
                                tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, sizeof(proxy_v2_ipv4_hdr));
                                size_proxy_header = AddProxyHeader(service, mbuf, metadata, &ipv4_header, &tcp_header, src_addr, src_port);
                        }
    
                        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::new_connections]++;
                    }
                    else
                    {
                        action = false;
                    }
                }
            }
            else
            {
                syn_connection_data.Unlock();
                action = CheckSynCookie(mbuf, worker_info, service, metadata, ipv4_header, tcp_header, service_connection_data, flags, false);
            }
            
            break;
        }
    }

    service_connection_data.Unlock();

    if (action)
    {
        ipv4_header->dst_addr = service.config.upstream_addr4;
        tcp_header->dst_port = service.config.upstream_port;
        CheckSumAfterUpdate(service, ipv4_header, tcp_header, chksum_work, size_proxy_header);
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_client_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_client_bytes] += mbuf->pkt_len;
    }
    else
    {
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_bytes] += mbuf->pkt_len;
    }

    return action;
}

inline bool ActionServiceOnSynAck(rte_mbuf* mbuf, dataplane::proxy::WorkerInfo& worker_info)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    proxy_service_id_t service_id = metadata->flow.data.proxy_service.id;
    dataplane::proxy::proxy_service_t& service = worker_info.globalBase->proxy_services[service_id];

    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_server_syn_ack", service_id, ipv4_header, tcp_header);
    RINGLOG_CONDITION(worker_info.globalBase->ringlog_enabled);
    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::service_syn_ack_count]++;

    LocalPool::Client client_info = service.tables.local_pool.FindClientByLocal(ipv4_header->dst_addr, tcp_header->dst_port);
    if (client_info.address == 0)
    {
        DebugPacket("\tservice synack client not found", service_id, ipv4_header, tcp_header);
        RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynAckNoLoc, 0, tcp_header->dst_port));
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::failed_local_pool_search_syn_ack]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_bytes] += mbuf->pkt_len;
        return false;
    }

    SynConnectionData4 syn_connection_data;
    if (service.tables.syn_connections4.FindAndLock(client_info.address, client_info.port, worker_info.current_time_ms, syn_connection_data, false) == TableSearchResult::Found)
    {
        RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynAckInSyn, client_port, tcp_header->dst_port));
        DebugPacket("\tsyn.FindAndLock=Found", service_id, ipv4_header, tcp_header);

        syn_connection_data.connection->server_answer = true;
        syn_connection_data.connection->server_seq = rte_be_to_cpu_32(tcp_header->sent_seq);
        syn_connection_data.Unlock();

        uint32_t chksum_work = CheckSumBeforeUpdate(ipv4_header, tcp_header);
        if (service.config.send_proxy_header)
        {
            tcp_header->recv_ack = add_cpu_32(tcp_header->recv_ack, sizeof(proxy_v2_ipv4_hdr));
            TcpOptions tcp_options{};
            if (!tcp_options.Read(tcp_header))
            {
                worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::pkts_with_corrupted_tcp_opts_service]++;
            }
            tcp_options.mss -= int(sizeof(proxy_v2_ipv4_hdr));
            tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
        }

        ipv4_header->src_addr = service.config.proxy_addr4;
        ipv4_header->dst_addr = client_info.address;
        tcp_header->src_port = service.config.proxy_port;
        tcp_header->dst_port = client_info.port;
        CheckSumAfterUpdate(service, ipv4_header, tcp_header, chksum_work, 0);

        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_service_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_service_bytes] += mbuf->pkt_len;			

        return true;
    }
    syn_connection_data.Unlock();

    ServiceConnectionData4 service_connection_data;
    if (service.tables.service_connections4.FindAndLock(client_info.address, client_info.port, worker_info.current_time_ms, service_connection_data, false) != TableSearchResult::Found)
    {
        DebugPacket("\tservice.FindAndLock!=Found", service_id, ipv4_header, tcp_header);
        RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynAckNoCon, 0, tcp_header->dst_port));

        service_connection_data.Unlock();
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::failed_answer_service_syn_ack]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_bytes] += mbuf->pkt_len;
        return false;
    }

    bool action = true;
    service_connection_data.connection->flags |= Connection::flag_answer_from_server;
    service_connection_data.connection->service_flags |= tcp_header->tcp_flags;

    uint32_t chksum_work = CheckSumBeforeUpdate(ipv4_header, tcp_header);
    if (!service_connection_data.connection->CreatedFromSynCookie())
    {
        // todo
        RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynAckOkNoCookie, client_port, tcp_header->dst_port));
    }
    else
    {
        RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynAckOkFromCookie, client_port, tcp_header->dst_port));

        TcpOptions tcp_options{};
        if (!tcp_options.Read(tcp_header))
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::pkts_with_corrupted_tcp_opts_service]++;

        bool old_sack_permitted = tcp_options.sack_permitted;
        service_connection_data.connection->window_size_shift = (int)tcp_options.window_scaling - (int)service.config.tcp_options.winscale;

        if (tcp_options.timestamp_value != 0)
        {
            service_connection_data.connection->timestamp_shift = service_connection_data.connection->timestamp_proxy_first - tcp_options.timestamp_value;
            tcp_options.timestamp_value = service_connection_data.connection->timestamp_proxy_first;
        }
        else if ((service_connection_data.connection->flags & Connection::flag_no_timestamps) == 0)
        {
            tcp_options.timestamp_value = worker_info.current_time_sec;
#ifdef CONFIG_YADECAP_AUTOTEST
            tcp_options.timestamp_value = ++service_connection_data.connection->timestamp_proxy_first;
#endif
            tcp_options.timestamp_echo = service_connection_data.connection->timestamp_client_last;
            service_connection_data.connection->flags |= Connection::flag_timestamp_fail;
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::error_service_config_timestamps]++;
        }

        tcp_options.sack_permitted = false;
        tcp_options.mss = 0;
        tcp_options.window_scaling = 0;
        tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);

        
        tcp_header->rx_win = shift_cpu_16(tcp_header->rx_win, service_connection_data.connection->window_size_shift);

        service_connection_data.connection->shift_server = service_connection_data.connection->proxy_start_seq - rte_be_to_cpu_32(tcp_header->sent_seq);
        tcp_header->sent_seq = rte_cpu_to_be_32(service_connection_data.connection->proxy_start_seq + 1);

        tcp_header->tcp_flags = TCP_ACK_FLAG;

        if (service.config.send_proxy_header)
        {
            tcp_header->recv_ack = add_cpu_32(tcp_header->recv_ack, sizeof(proxy_v2_ipv4_hdr));
        }

        if (service.config.tcp_options.use_sack && !old_sack_permitted)
        {
            // error, server does not support SACK, although the configuration file states that it supports
            service_connection_data.connection->flags |= Connection::flag_clear_sack;
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::error_service_config_sack]++;
        }
    }

    service_connection_data.Unlock();

    ipv4_header->src_addr = service.config.proxy_addr4;
    ipv4_header->dst_addr = client_info.address;
    tcp_header->src_port = service.config.proxy_port;
    tcp_header->dst_port = client_info.port;
    
    if (action)
    {
        CheckSumAfterUpdate(service, ipv4_header, tcp_header, chksum_work, 0);
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_service_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_service_bytes] += mbuf->pkt_len;			
    }
    else
    {
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_bytes] += mbuf->pkt_len;
    }
    			
    return action;
}

inline bool ActionServiceOnAck(rte_mbuf* mbuf, dataplane::proxy::WorkerInfo& worker_info)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    proxy_service_id_t service_id = metadata->flow.data.proxy_service.id;
    dataplane::proxy::proxy_service_t& service = worker_info.globalBase->proxy_services[service_id];

    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_server_ack", service_id, ipv4_header, tcp_header);
    RINGLOG_CONDITION(worker_info.globalBase->ringlog_enabled);

    LocalPool::Client client_info = service.tables.local_pool.FindClientByLocal(ipv4_header->dst_addr, tcp_header->dst_port);
    if (client_info.address == 0)
    {
        DebugPacket("service ack client not found", service_id, ipv4_header, tcp_header);
        RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SrvAckNoLoc, tcp_header->dst_port, 0));
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::failed_local_pool_search_ack]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_bytes] += mbuf->pkt_len;
        return false;
    }

    uint32_t chksum_work = CheckSumBeforeUpdate(ipv4_header, tcp_header);
    ServiceConnectionData4 service_connection_data;
    if (service.tables.service_connections4.FindAndLock(client_info.address, client_info.port, worker_info.current_time_ms, service_connection_data, false) != TableSearchResult::Found)
    {
        DebugPacket("service ack connection not found", service_id, ipv4_header, tcp_header);
        service_connection_data.Unlock();
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::failed_search_client_service_ack]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_bytes] += mbuf->pkt_len;
        RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SrvAckNoCon, client_port, tcp_header->dst_port));
        return false;
    }

    service_connection_data.connection->service_flags |= tcp_header->tcp_flags;

    if (tcp_header->tcp_flags & TCP_RST_FLAG)
    {
        service_connection_data.Unlock();
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::rst_service]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_bytes] += mbuf->pkt_len;
        return false;
    }

    RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SrvAckOk, client_port, tcp_header->dst_port));
    if (service_connection_data.connection->CreatedFromSynCookie())
    {
        tcp_header->sent_seq = add_cpu_32(tcp_header->sent_seq, service_connection_data.connection->shift_server);

        TcpOptions tcp_options;
        memset(&tcp_options, 0, sizeof(tcp_options));
        if (!tcp_options.ReadOnlyTimestampsAndSack(tcp_header))
        {
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::pkts_with_corrupted_tcp_opts_service]++;
        }
        if (tcp_options.timestamp_value != 0)
        {
            tcp_options.timestamp_value += service_connection_data.connection->timestamp_shift;
            tcp_options.Write(mbuf, &ipv4_header, &tcp_header);
        }
        else if ((service_connection_data.connection->flags & Connection::flag_timestamp_fail) != 0)
        {
            tcp_options.timestamp_value = worker_info.current_time_sec;
#ifdef CONFIG_YADECAP_AUTOTEST
            tcp_options.timestamp_value = ++service_connection_data.connection->timestamp_proxy_first;
#endif
            tcp_options.timestamp_echo = service_connection_data.connection->timestamp_client_last;
            tcp_options.Write(mbuf, &ipv4_header, &tcp_header);
        }
        tcp_header->rx_win = shift_cpu_16(tcp_header->rx_win, service_connection_data.connection->window_size_shift);
    }
    service_connection_data.Unlock();

    ipv4_header->dst_addr = client_info.address;
    ipv4_header->src_addr = service.config.proxy_addr4;
    tcp_header->dst_port = client_info.port;
    tcp_header->src_port = service.config.proxy_port;

    CheckSumAfterUpdate(service, ipv4_header, tcp_header, chksum_work, 0);

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_service_packets]++;
    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_service_bytes] += mbuf->pkt_len;			

    return true;
}

template<typename ip_header_t, typename icmp_header_t>
inline bool ActionClientOnICMP(rte_mbuf* mbuf, WorkerInfo& worker_info)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    const dataplane::proxy::proxy_service_t& service = worker_info.globalBase->proxy_services[metadata->flow.data.proxy_service.id];

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_packets]++;
    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_bytes] += mbuf->pkt_len;

    icmp_header_t* icmp_header = rte_pktmbuf_mtod_offset(mbuf, icmp_header_t*, metadata->transport_headerOffset);

    icmp_header->type = ICMP_ECHOREPLY;
    icmp_header->code = 0;

    ip_header_t* ip_header = rte_pktmbuf_mtod_offset(mbuf, ip_header_t*, metadata->network_headerOffset);
    // YANET_LOG_WARNING("ping %s -> %s\n",
    // 		common::ipv4_address_t(rte_cpu_to_be_32(ipv4Header->src_addr)).toString().c_str(),
    // 		common::ipv4_address_t(rte_cpu_to_be_32(ipv4Header->dst_addr)).toString().c_str());

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::ping_count]++;

    SwapAddresses(ip_header);

    // it is a reply, ttl starts anew, route_handle() will decrease it and modify checksum accordingly
    if constexpr (std::is_same_v<ip_header_t, rte_ipv4_hdr>)
    {
        ip_header->time_to_live = 65;
        yanet_ipv4_checksum(ip_header);
    }
    else if constexpr (std::is_same_v<ip_header_t, rte_ipv6_hdr>)
    {
        ip_header->hop_limits = 65;
    }

    uint16_t icmp_checksum = ~icmp_header->checksum;
    icmp_checksum = csum_minus(icmp_checksum, ICMP_ECHO);
    icmp_checksum = csum_plus(icmp_checksum, ICMP_ECHOREPLY);
    icmp_header->checksum = ~icmp_checksum;

    // todo:
    // counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_generated_echo_reply_ipv4]++;
    return true;
}

}