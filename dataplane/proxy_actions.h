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
    tcp_header->cksum = rte_ipv4_udptcp_cksum((rte_ipv4_hdr*)ipv4_header, tcp_header);
}

inline bool NonEmptyTcpData(rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
    return (rte_be_to_cpu_16(ipv4_header->total_length) != sizeof(rte_ipv4_hdr) + tcp_header_len);
}

uint32_t CheckSumBeforeUpdate(rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header);
void CheckSumAfterUpdate(const proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header, uint32_t chksum_work, uint32_t size_data);

void PrepareSynAckToClient(const proxy_service_t& service, rte_mbuf* mbuf,
                           rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header,
                           uint64_t* counters, uint32_t current_time_sec);

void PrepareSynToService(const proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header, uint64_t local);

inline bool ActionClientOnSyn(rte_mbuf* mbuf, dataplane::proxy::WorkerInfo& worker_info)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    proxy_service_id_t service_id = metadata->flow.data.proxy_service.id;
    dataplane::proxy::proxy_service_t& service = worker_info.globalBase->proxy_services[service_id];

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_packets]++;
    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_bytes] += mbuf->pkt_len;

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::syn_count]++;

    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_client_syn", service_id, ipv4_header, tcp_header);
    RINGLOG_CONDITION(worker_info.globalBase->ringlog_enabled && worker_info.globalBase->ringlog_value == ipv4_header->src_addr);
    bool action = true;

    if (service.connection_limit_table.Exists(ipv4_header->src_addr, worker_info.current_time_ms))
    {
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_connection_limit]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_bytes] += mbuf->pkt_len;
        if (service.connection_limit_table.Mode() == common::proxy::limit_mode::on) return false;
    }
    if (!metadata->flow.data.proxy_service.whitelist
        && service.rate_limit_table.Check(ipv4_header->src_addr, worker_info.current_time_ms) != RateLimitResult::Pass)
    {
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_rate_limit]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_client_bytes] += mbuf->pkt_len;
        if (service.rate_limit_table.Mode() == common::proxy::limit_mode::on) return false;
    }

    bool is_syn_ack = false;
    uint32_t chksum_work = CheckSumBeforeUpdate(ipv4_header, tcp_header);
    SynConnectionData syn_connection_data;
    switch (service.tables.syn_connections.FindAndLock(ipv4_header->src_addr, tcp_header->src_port, worker_info.current_time_ms, syn_connection_data, !service.config.EnabledFlag(dataplane::proxy::proxy_service_config_t::flag_dont_use_bucket_optimization)))
    {
        case TableSearchResult::Overflow:
        {
            DebugPacket("\tsyn.FindAndLock=Overflow", service_id, ipv4_header, tcp_header);
		    RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynOverflow, tcp_header->src_port, 0));

            PrepareSynAckToClient(service, mbuf, ipv4_header, tcp_header, worker_info.counters, worker_info.current_time_sec);
            is_syn_ack = true;
            break;
        }
        case TableSearchResult::Found:
        {
            DebugPacket("\tsyn.FindAndLock=Found", service_id, ipv4_header, tcp_header);
            RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynFound, tcp_header->src_port, syn_connection_data.connection->local));
            if (++syn_connection_data.connection->retransmits_from_client > 3)
            {
                PrepareSynAckToClient(service, mbuf, ipv4_header, tcp_header, worker_info.counters, worker_info.current_time_sec);
                is_syn_ack = true;
            }
            else
            {
                PrepareSynToService(service, ipv4_header, tcp_header, syn_connection_data.connection->local);
            }
            break;
        }
        case TableSearchResult::NotFound:
        {
            DebugPacket("\tsyn.FindAndLock=NotFound", service_id, ipv4_header, tcp_header);
            uint64_t local = service.tables.local_pool.Allocate(worker_info.worker_id, ipv4_header->src_addr, tcp_header->src_port);
            if (local == 0)
            {
                DebugPacket("failed to allocate local address", service_id, ipv4_header, tcp_header);
                RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynErrLocal, tcp_header->src_port, 0));
                worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::failed_local_pool_allocation]++;
                action = false;
            }
            else
            {
                RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynAdd, tcp_header->src_port, local));
                syn_connection_data.Init(ipv4_header->src_addr, tcp_header->src_port, worker_info.current_time_ms);
                syn_connection_data.connection->local = local;
                syn_connection_data.connection->client_start_seq = tcp_header->sent_seq;

                PrepareSynToService(service, ipv4_header, tcp_header, local);
                worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::new_syn_connections]++;
            }
            break;
        }
    }
    syn_connection_data.Unlock();

    if (action)
    {
        CheckSumAfterUpdate(service, ipv4_header, tcp_header, chksum_work, 0);
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

uint32_t AddProxyHeader(const proxy_service_t& service, rte_mbuf* mbuf, dataplane::metadata* metadata,
                        rte_ipv4_hdr** ipv4_header, rte_tcp_hdr** tcp_header, uint32_t src_addr, uint16_t src_port);

uint32_t CheckSynCookie(const proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header);
bool CheckSynCookie(rte_mbuf* mbuf,
                    dataplane::proxy::WorkerInfo& worker_info,
                    dataplane::proxy::proxy_service_t& service,
                    dataplane::metadata* metadata,
                    rte_ipv4_hdr*& ipv4_header,
                    rte_tcp_hdr*& tcp_header,
                    ServiceConnectionData& service_connection_data,
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

    ServiceConnectionData service_connection_data;
    switch (service.tables.service_connections.FindAndLock(ipv4_header->src_addr, tcp_header->src_port, worker_info.current_time_ms, service_connection_data, false))
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

            SynConnectionData syn_connection_data;
            if (service.tables.syn_connections.FindAndLock(ipv4_header->src_addr, tcp_header->src_port, worker_info.current_time_ms, syn_connection_data, false) == TableSearchResult::Found)
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
                        service_connection_data.connection->local = ServiceSynConnections::Pack(ipv4_header->src_addr, tcp_header->src_port);
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
        ipv4_header->dst_addr = service.config.upstream_addr;
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

    uint64_t client_info = service.tables.local_pool.FindClientByLocal(ipv4_header->dst_addr, tcp_header->dst_port);
    if (client_info == 0)
    {
        DebugPacket("\tservice synack client not found", service_id, ipv4_header, tcp_header);
        RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SynAckNoLoc, 0, tcp_header->dst_port));
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::failed_local_pool_search_syn_ack]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_bytes] += mbuf->pkt_len;
        return false;
    }
    uint32_t client_addr;
    tPortId client_port;
    LocalPool::UnpackTuple(client_info, client_addr, client_port);

    SynConnectionData syn_connection_data;
    if (service.tables.syn_connections.FindAndLock(client_addr, client_port, worker_info.current_time_ms, syn_connection_data, false) == TableSearchResult::Found)
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

        ipv4_header->src_addr = service.config.proxy_addr;
        ipv4_header->dst_addr = client_addr;
        tcp_header->src_port = service.config.proxy_port;
        tcp_header->dst_port = client_port;
        CheckSumAfterUpdate(service, ipv4_header, tcp_header, chksum_work, 0);

        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_service_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_service_bytes] += mbuf->pkt_len;			

        return true;
    }
    syn_connection_data.Unlock();

    ServiceConnectionData service_connection_data;
    if (service.tables.service_connections.FindAndLock(client_addr, client_port, worker_info.current_time_ms, service_connection_data, false) != TableSearchResult::Found)
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

    ipv4_header->src_addr = service.config.proxy_addr;
    ipv4_header->dst_addr = client_addr;
    tcp_header->src_port = service.config.proxy_port;
    tcp_header->dst_port = client_port;
    
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

    uint64_t client_info = service.tables.local_pool.FindClientByLocal(ipv4_header->dst_addr, tcp_header->dst_port);
    if (client_info == 0)
    {
        DebugPacket("service ack client not found", service_id, ipv4_header, tcp_header);
        RINGLOG_ADD(*worker_info.ringlog, worker_info.current_time_ms, PackLog(common::ringlog::DebugEvent::SrvAckNoLoc, tcp_header->dst_port, 0));
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::failed_local_pool_search_ack]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_packets]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_service_bytes] += mbuf->pkt_len;
        return false;
    }
    uint32_t client_addr;
    tPortId client_port;
    LocalPool::UnpackTuple(client_info, client_addr, client_port);

    uint32_t chksum_work = CheckSumBeforeUpdate(ipv4_header, tcp_header);
    ServiceConnectionData service_connection_data;
    if (service.tables.service_connections.FindAndLock(client_addr, client_port, worker_info.current_time_ms, service_connection_data, false) != TableSearchResult::Found)
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

    ipv4_header->dst_addr = client_addr;
    ipv4_header->src_addr = service.config.proxy_addr;
    tcp_header->dst_port = client_port;
    tcp_header->src_port = service.config.proxy_port;

    CheckSumAfterUpdate(service, ipv4_header, tcp_header, chksum_work, 0);

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_service_packets]++;
    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::forward_service_bytes] += mbuf->pkt_len;			

    return true;
}

inline bool ActionClientOnICMP(rte_mbuf* mbuf, WorkerInfo& worker_info)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    const dataplane::proxy::proxy_service_t& service = worker_info.globalBase->proxy_services[metadata->flow.data.proxy_service.id];

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_packets]++;
    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_bytes] += mbuf->pkt_len;

    icmpv4_header_t* icmpHeader = rte_pktmbuf_mtod_offset(mbuf, icmpv4_header_t*, metadata->transport_headerOffset);

    icmpHeader->type = ICMP_ECHOREPLY;
    icmpHeader->code = 0;

    rte_ipv4_hdr* ipv4Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    // YANET_LOG_WARNING("ping %s -> %s\n",
    // 		common::ipv4_address_t(rte_cpu_to_be_32(ipv4Header->src_addr)).toString().c_str(),
    // 		common::ipv4_address_t(rte_cpu_to_be_32(ipv4Header->dst_addr)).toString().c_str());

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::ping_count]++;

    uint32_t tmp_for_swap = ipv4Header->src_addr;
    ipv4Header->src_addr = ipv4Header->dst_addr;
    ipv4Header->dst_addr = tmp_for_swap;

    // it is a reply, ttl starts anew, route_handle() will decrease it and modify checksum accordingly
    ipv4Header->time_to_live = 65;

    yanet_ipv4_checksum(ipv4Header);

    uint16_t icmp_checksum = ~icmpHeader->checksum;
    icmp_checksum = csum_minus(icmp_checksum, ICMP_ECHO);
    icmp_checksum = csum_plus(icmp_checksum, ICMP_ECHOREPLY);
    icmpHeader->checksum = ~icmp_checksum;

    // todo:
    // counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_generated_echo_reply_ipv4]++;
    return true;
}

inline bool ActionClientOnICMPv6(rte_mbuf* mbuf, WorkerInfo& worker_info)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    const dataplane::proxy::proxy_service_t& service = worker_info.globalBase->proxy_services[metadata->flow.data.proxy_service.id];

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_packets]++;
    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::client_bytes] += mbuf->pkt_len;

    icmpv6_header_t* icmpHeader = rte_pktmbuf_mtod_offset(mbuf, icmpv6_header_t*, metadata->transport_headerOffset);

    icmpHeader->type = ICMP_ECHOREPLY;
    icmpHeader->code = 0;

    rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::ping_count]++;

    uint8_t tmp_for_swap[sizeof(ipv6Header->src_addr)];
    rte_memcpy(tmp_for_swap, ipv6Header->src_addr, sizeof(tmp_for_swap));
    rte_memcpy(ipv6Header->src_addr, ipv6Header->dst_addr, sizeof(ipv6Header->src_addr));
    rte_memcpy(ipv6Header->dst_addr, tmp_for_swap, sizeof(ipv6Header->dst_addr));

    // it is a reply, ttl starts anew, route_handle() will decrease it and modify checksum accordingly
    ipv6Header->hop_limits = 65;

    uint16_t icmp_checksum = ~icmpHeader->checksum;
    icmp_checksum = csum_minus(icmp_checksum, ICMP_ECHO);
    icmp_checksum = csum_plus(icmp_checksum, ICMP_ECHOREPLY);
    icmpHeader->checksum = ~icmp_checksum;

    // todo:
    // counters[(uint32_t)common::globalBase::static_counter_type::balancer_icmp_generated_echo_reply_ipv6]++;
    return true;
}

}