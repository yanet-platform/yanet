#include "proxy_actions.h"

namespace dataplane::proxy
{

uint32_t AddProxyHeader(const proxy_service_t& service, rte_mbuf* mbuf, dataplane::metadata* metadata,
                        rte_ipv4_hdr** ipv4_header, rte_tcp_hdr** tcp_header, uint32_t src_addr, uint16_t src_port)
{
    size_t tcp_header_len = ((*tcp_header)->data_off >> 4) << 2;
    constexpr uint16_t size_proxy_header = sizeof(proxy_v2_ipv4_hdr);
    proxy_v2_ipv4_hdr* proxy_header = 
        rte_pktmbuf_mtod_offset(mbuf, proxy_v2_ipv4_hdr*, metadata->transport_headerOffset + tcp_header_len);
    uint16_t size_data = rte_be_to_cpu_16((*ipv4_header)->total_length) - rte_ipv4_hdr_len(*ipv4_header) - tcp_header_len;
    if (size_data != 0)
    {   
        rte_pktmbuf_prepend(mbuf, size_proxy_header);
        memmove(rte_pktmbuf_mtod(mbuf, char*), 
                rte_pktmbuf_mtod_offset(mbuf, char*, size_proxy_header),
                metadata->transport_headerOffset + tcp_header_len);
        *ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
        *tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
        proxy_header = 
            rte_pktmbuf_mtod_offset(mbuf, proxy_v2_ipv4_hdr*, metadata->transport_headerOffset + tcp_header_len);
    }
    
    uint16_t ipv4_total_length = rte_ipv4_hdr_len(*ipv4_header) + tcp_header_len + size_proxy_header + size_data;
    (*ipv4_header)->total_length = rte_cpu_to_be_16(ipv4_total_length);

    mbuf->data_len = sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr) + ipv4_total_length;
    mbuf->pkt_len = mbuf->data_len;

    *proxy_header = service.proxy_header;
    proxy_header->src_addr = src_addr;
    proxy_header->src_port = src_port;
    return size_proxy_header;
}

uint32_t CheckSynCookie(const proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    if (!service.config.EnabledFlag(dataplane::proxy::proxy_service_config_t::flag_ignore_size_update_detections) && 
        // ACK's seq has the same evenness bit as SYN's seq(encoded into cookie)
        // This means ACK's seq IS the same as SYN's. So it must be incremented
        (rte_be_to_cpu_32(tcp_header->sent_seq) & 1) == ((rte_be_to_cpu_32(tcp_header->recv_ack) - 1) & 1))
    {
        tcp_header->sent_seq = add_cpu_32(tcp_header->sent_seq, 1);
    }

    uint32_t cookie_data = service.syn_cookie.CheckCookie(rte_be_to_cpu_32(tcp_header->recv_ack) - 1, 
                                                                ipv4_header->src_addr, tcp_header->src_port, sub_cpu_32(tcp_header->sent_seq, 1));
    // YANET_LOG_WARNING("\tcookie_data=%d, ack=%u, seq=%u\n", cookie_data, tcp_header->recv_ack, tcp_header->sent_seq);

    return cookie_data;
}

bool CheckSynCookie(rte_mbuf* mbuf,
                    dataplane::proxy::WorkerInfo& worker_info,
                    dataplane::proxy::proxy_service_t& service,
                    dataplane::metadata* metadata,
                    rte_ipv4_hdr*& ipv4_header,
                    rte_tcp_hdr*& tcp_header,
                    ServiceConnectionData4& service_connection_data,
                    uint32_t flags,
                    bool reuse_connection)
{
	// try check cookie
    // todo - check time overflow
	uint32_t cookie_data = CheckSynCookie(service, ipv4_header, tcp_header);
	if (cookie_data == 0)
	{
		DebugPacket("!CheckSynCookie", service.config.service_id, ipv4_header, tcp_header);

		worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::failed_check_syn_cookie]++;
		return false;
	}

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::success_check_syn_cookie]++;

    RateLimitResult result = RateLimitResult::Pass;
    if (!metadata->flow.data.proxy_service.whitelist)
        result = service.rate_limit_table.CheckAndConsume(ipv4_header->src_addr, worker_info.current_time_ms);
    if (result != RateLimitResult::Pass)
    {
        if (result == RateLimitResult::Overflow)
            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::rate_limiter_overflow]++;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::drop_rate_limit]++;
        if (service.rate_limit_table.Mode() == common::proxy::limit_mode::on)
            return false;
    }

    uint64_t local;
    if (reuse_connection)
    {
        local = service_connection_data.connection->local;
        worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::reuse_old_rst_connection]++;
        service_connection_data.Reuse(worker_info.current_time_ms);
    }
    else
    {
        // get from local
        local = service.tables.local_pool.Allocate(worker_info.worker_id, ipv4_header->src_addr, tcp_header->src_port);
        if (local == 0)
        {
            DebugPacket("!local_pool.Allocate", service.config.service_id, ipv4_header, tcp_header);

            worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::failed_local_pool_allocation]++;
            return false;
        }
        service_connection_data.Init(ipv4_header->src_addr, tcp_header->src_port, worker_info.current_time_ms);
    }

    TcpOptions tcp_options;
    memset(&tcp_options, 0, sizeof(tcp_options));
    if (!tcp_options.Read(tcp_header))
    {
	    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::pkts_with_corrupted_tcp_opts_client]++;
	    // DebugFullHeader(mbuf, "ActionClientOnAck 3");
    }

    // Add to connections
    LocalPool::UnpackTupleSrc(local, ipv4_header, tcp_header);
    service_connection_data.connection->local = LocalPool::PackTuple(ipv4_header->src_addr, tcp_header->src_port);
    service_connection_data.connection->proxy_start_seq = rte_be_to_cpu_32(tcp_header->recv_ack) - 1;
    service_connection_data.connection->client_start_seq = sub_cpu_32(tcp_header->sent_seq, 1);
    service_connection_data.connection->timestamp_proxy_first = tcp_options.timestamp_echo;
    service_connection_data.connection->timestamp_client_last = tcp_options.timestamp_value;
    service_connection_data.connection->cookie_data = cookie_data;

    tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, 1 + (service.config.send_proxy_header ? sizeof(proxy_v2_ipv4_hdr) : 0));

    TcpOptions cookie_options = SynCookies::UnpackData(cookie_data);
    if (tcp_options.timestamp_value != 0 && service.config.tcp_options.timestamps)
    {
	    cookie_options.timestamp_value = tcp_options.timestamp_value;
    }
    else
    {
	    cookie_options.timestamp_value = 0;
	    flags |= Connection::flag_no_timestamps;
    }
    service_connection_data.connection->flags = Connection::flag_from_synkookie | flags;
    service_connection_data.connection->client_flags |= tcp_header->tcp_flags;
    if (metadata->flow.data.proxy_service.whitelist)
    {
	    service_connection_data.connection->SetFlag(Connection::flag_whitelist);
    }

    cookie_options.Write(mbuf, &ipv4_header, &tcp_header);
    ipv4_header->time_to_live = 64;
    tcp_header->recv_ack = 0;
    tcp_header->tcp_flags = TCP_SYN_FLAG;

    worker_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::new_connections]++;

	return true;
}

}