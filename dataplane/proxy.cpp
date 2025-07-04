#include <sstream>

#include "common/counters.h"

#include "common.h"
#include "globalbase.h"
#include "metadata.h"
#include "proxy.h"
#include "syncookies.h"

// #define TCP_PROXY_DEBUG

namespace dataplane::proxy
{

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

bool TcpOptions::Read(uint8_t* data, uint32_t len)
{
    uint32_t index = 0;
    while (index < len)
    {
        tcp_option_t* opt = (tcp_option_t*)&data[index];
        switch (opt->kind)
        {
        case TCP_OPTION_KIND_MSS:
            if (!CheckSize(index, len, data, TCP_OPTION_MSS_LEN)) {
                return false;
            }
            mss = rte_be_to_cpu_16(*(uint16_t*)opt->data);
            index += TCP_OPTION_MSS_LEN;
            break;

        case TCP_OPTION_KIND_SP:
            if (!CheckSize(index, len, data, TCP_OPTION_SP_LEN)) {
                return false;
            }
            sack_permitted = 1;
            index += TCP_OPTION_SP_LEN;
            break;

        case TCP_OPTION_KIND_TS:
            if (!CheckSize(index, len, data, TCP_OPTION_TS_LEN)) {
                return false;
            }
            timestamp_value = rte_be_to_cpu_32(*(uint32_t*)opt->data);
            timestamp_echo = rte_be_to_cpu_32(*(uint32_t*)(opt->data + 4));
            index += TCP_OPTION_TS_LEN;
            break;

        case TCP_OPTION_KIND_NOP:
            index += TCP_OPTION_NOP_LEN;
            break;

        case TCP_OPTION_KIND_EOL:
            return true;

        case TCP_OPTION_KIND_WS:
            if (!CheckSize(index, len, data, TCP_OPTION_WS_LEN)) {
                return false;
            }
            window_scaling = *(uint8_t*)opt->data;
            index += TCP_OPTION_WS_LEN;
            break;
        
        default:
            // unknown option
            return false;
            break;
        }
    }
    return true;
}

void TcpOptions::ReadOnlyTimestampsAndSack(rte_tcp_hdr* tcp_header)
{
    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
    uint8_t* options = (uint8_t*)tcp_header + sizeof(rte_tcp_hdr);
    uint32_t len = tcp_header_len - sizeof(rte_tcp_hdr);

    uint32_t index_read = 0;
    uint32_t count = 0;
    while ((index_read < len) && (count++ < TCP_OPTIONS_MAX_COUNT))
    {
        switch (options[index_read])
        {
        case TCP_OPTION_KIND_TS:
        {
            timestamp_value = rte_be_to_cpu_32(*((uint32_t*)(options + index_read + 2)));
            timestamp_echo = rte_be_to_cpu_32(*((uint32_t*)(options + index_read + 6)));
            index_read += TCP_OPTION_TS_LEN;
            break;
        }
        case TCP_OPTION_KIND_SACK:
        {
            if (sack_count < TCP_OPTIONS_MAX_SACK_COUNT)
            {
                sack_start[sack_count] = rte_be_to_cpu_32(*((uint32_t*)(options + index_read + 2)));
                sack_finish[sack_count] = rte_be_to_cpu_32(*((uint32_t*)(options + index_read + 6)));
                sack_count++;
            }
            index_read += TCP_OPTION_SACK_LEN;
            break;
        }
        case TCP_OPTION_KIND_NOP:
            index_read += TCP_OPTION_NOP_LEN;
            break;
        case TCP_OPTION_KIND_EOL:
            return;
        default:
            index_read += options[index_read + 1];
        }
    }    

}

uint32_t TcpOptions::WriteBuffer(uint8_t* data) const
{
    uint32_t len = 0;
    
    if (mss != 0)
    {
        tcp_option_t* opt = (tcp_option_t*)&data[len];
        opt->kind = TCP_OPTION_KIND_MSS;
        opt->len = TCP_OPTION_MSS_LEN;
        *(uint16_t*)opt->data = rte_cpu_to_be_16(mss);
        len += TCP_OPTION_MSS_LEN;
    }

    if (sack_permitted != 0)
    {
        tcp_option_t* opt = (tcp_option_t*)&data[len];
        opt->kind = TCP_OPTION_KIND_SP;
        opt->len = TCP_OPTION_SP_LEN;
        len += TCP_OPTION_SP_LEN;
    }

    for (uint32_t index = 0; index < sack_count; index++)
    {
        tcp_option_t* opt = (tcp_option_t*)&data[len];
        opt->kind = TCP_OPTION_KIND_SACK;
        opt->len = TCP_OPTION_SACK_LEN;
        *(uint32_t*)opt->data = rte_cpu_to_be_32(sack_start[index]);
        *(uint32_t*)(opt->data + 4) = rte_cpu_to_be_32(sack_finish[index]);
        len += TCP_OPTION_SACK_LEN;
    }

    if (timestamp_value != 0 || timestamp_echo != 0)
    {
        tcp_option_t* opt = (tcp_option_t*)&data[len];
        opt->kind = TCP_OPTION_KIND_TS;
        opt->len = TCP_OPTION_TS_LEN;
        *(uint32_t*)opt->data = rte_cpu_to_be_32(timestamp_value);
        *(uint32_t*)(opt->data + 4) = rte_cpu_to_be_32(timestamp_echo);
        len += TCP_OPTION_TS_LEN;
    }

    if (window_scaling != 0)
    {
        tcp_option_t* opt = (tcp_option_t*)&data[len];
        opt->kind = TCP_OPTION_KIND_WS;
        opt->len = TCP_OPTION_WS_LEN;
        *(uint8_t*)opt->data = window_scaling;
        len += TCP_OPTION_WS_LEN;
    }

    while ((len % 4) != 0)
    {
        data[len++] = TCP_OPTION_KIND_EOL;
    }

    return len;
}

uint32_t TcpOptions::Size() const {
    uint32_t size = sack_count * TCP_OPTION_SACK_LEN;
    if (mss != 0) size += TCP_OPTION_MSS_LEN;
    if (sack_permitted != 0) size += TCP_OPTION_SP_LEN;
    if (timestamp_value != 0 || timestamp_echo != 0) size += TCP_OPTION_TS_LEN;
    if (window_scaling != 0) size += TCP_OPTION_WS_LEN;
    // Round up to multiple of 4
    size = (size + 4 - 1) & -4;
    return size;
}

uint32_t TcpOptions::Write(rte_mbuf* mbuf, rte_ipv4_hdr** ipv4_header, rte_tcp_hdr** tcp_header) const
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    size_t tcp_header_len_old = ((*tcp_header)->data_off >> 4) << 2;
    uint16_t tcp_data_len = rte_be_to_cpu_16((*ipv4_header)->total_length) - rte_ipv4_hdr_len(*ipv4_header) - tcp_header_len_old;

    uint32_t old_opts_size = tcp_header_len_old - sizeof(rte_tcp_hdr);
    int diff = old_opts_size - Size();
    if (diff < 0) // Options size increased
    {
        rte_pktmbuf_prepend(mbuf, -diff);
        memmove(rte_pktmbuf_mtod(mbuf, char*),
                rte_pktmbuf_mtod_offset(mbuf, char*, -diff),
                metadata->transport_headerOffset + sizeof(rte_tcp_hdr));
    }
    else if (diff > 0) // Options size decreased
    {
        memmove(rte_pktmbuf_mtod_offset(mbuf, char*, diff),
                rte_pktmbuf_mtod(mbuf, char*),
                metadata->transport_headerOffset + sizeof(rte_tcp_hdr));
        rte_pktmbuf_adj(mbuf, diff);
    }
    *ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    *tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    uint32_t len = WriteBuffer((uint8_t*)(*tcp_header) + sizeof(rte_tcp_hdr));

    (*tcp_header)->data_off = ((sizeof(rte_tcp_hdr) + len) >> 2) << 4;
    
    uint16_t total_length = rte_ipv4_hdr_len(*ipv4_header) + sizeof(rte_tcp_hdr) + len + tcp_data_len;
    (*ipv4_header)->total_length = rte_cpu_to_be_16(total_length);

    mbuf->data_len = sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr) + total_length;
    mbuf->pkt_len = mbuf->data_len;

    return len;
}

bool TcpOptions::CheckSize(uint32_t index, uint32_t len, uint8_t* data, uint8_t expected)
{
    return (index + expected <= len) && (data[index + 1] == expected);
}

std::string TcpOptions::DebugInfo() const
{
    std::stringstream ss;
    
    ss << "MSS: " << mss;
    
    if (sack_permitted != 0)
    {
        ss << ", SACK";
    }
    
    if (timestamp_value != 0 || timestamp_echo != 0)
    {
        ss << ", timestamps: [" << timestamp_value << "," << timestamp_echo << "]";
    }

    if (window_scaling != 0)
    {
        ss << ", win scale: " << uint32_t(window_scaling);
    }

    return ss.str();
}

// Update

eResult TcpConnectionStore::ServiceUpdate(proxy_service_t& service, dataplane::memory_manager* memory_manager, uint8_t currentGlobalBaseId, bool first_state_update_global_base)
{
    proxy_service_id_t service_id = service.service_id;

    common::ipv4_prefix_t upstream_net(service.pool_prefix.address.address, service.pool_prefix.mask);
    YANET_LOG_WARNING("proxy_service_update: service_id=%d, proxy=%s:%d, upstream=%s:%d, prefix=%s, send_proxy_header=%d\n", 
        service_id, common::ipv4_address_t(rte_cpu_to_be_32(service.proxy_addr)).toString().c_str(), rte_cpu_to_be_16(service.proxy_port),
        common::ipv4_address_t(rte_cpu_to_be_32(service.upstream_addr)).toString().c_str(), rte_cpu_to_be_16(service.upstream_port), upstream_net.toString().c_str(),
        service.send_proxy_header);
    // YANET_LOG_WARNING("\t\tsize_connections_table=%d, size_syn_table=%d, counter_id=%d\n", service.size_connections_table, service.size_syn_table, service.counter_id);
    // YANET_LOG_WARNING("\t\ttimeouts: syn_rto=%d, syn_recv=%d, established=%d\n", service.timeout_syn_rto, service.timeout_syn_recv, service.timeout_established);
    // YANET_LOG_WARNING("\t\tuse_sack=%d, mss=%d, winscale=%d, timestamps=%d\n", service.use_sack, service.mss, service.winscale, service.timestamps);
	// YANET_LOG_WARNING("\t\t!!!!! currentGlobalBaseId=%d, first_state_update_global_base=%d\n", currentGlobalBaseId, first_state_update_global_base);

    std::lock_guard guard(mutex_);

    uint8_t newGlobalBaseId = currentGlobalBaseId ^ 1;
    eResult result;
    if (first_state_update_global_base)
    {
        result = updater_proxy_tables[service_id].FirstUpdate(currentGlobalBaseId, newGlobalBaseId, memory_manager, service);
    }
    else
    {
        result = updater_proxy_tables[service_id].SecondUpdate(currentGlobalBaseId, newGlobalBaseId, memory_manager);
    }

    if (result != eResult::success)
    {
        return result;
    }
    service.tables.CopyFrom(updater_proxy_tables[service_id].tables[newGlobalBaseId]);

    return eResult::success;
}

void TcpConnectionStore::ServiceRemove(proxy_service_t& service, dataplane::memory_manager* memory_manager, uint8_t currentGlobalBaseId, bool first_state_update_global_base)
{
    YANET_LOG_WARNING("proxy_service_remove: service_id=%d\n", service.service_id);
    uint8_t newGlobalBaseId = currentGlobalBaseId ^ 1;
    if (first_state_update_global_base)
    {
        updater_proxy_tables[service.service_id].FirstRemove(currentGlobalBaseId, newGlobalBaseId, memory_manager);
    }
    else
    {
        updater_proxy_tables[service.service_id].SecondRemove(currentGlobalBaseId, newGlobalBaseId, memory_manager);
    }
    service.tables.ClearLinks();
}

void TcpConnectionStore::CollectGarbage()
{
    // YANET_LOG_WARNING("TcpConnectionStore::CollectGarbage: current_time=%d\n", current_time);
    // uint64_t current_time = current_time_ms;
    // std::lock_guard guard(mutex_);
    // for (uint32_t index = 0; index < YANET_CONFIG_PROXY_SERVICES_SIZE; index++)
    // {
    //     // syn_connections_[index].CollectGarbage(current_time, local_pools_[index]);
    //     // service_connections_[index].CollectGarbage(current_time, local_pools_[index]);
    // }
}

void TcpConnectionStore::UpdateSynCookieKeys()
{
    // YANET_LOG_WARNING("TcpConnectionStore::UpdateSynCookieKeys\n");
    std::lock_guard guard(mutex_);
    for (uint32_t i = 0; i < YANET_CONFIG_PROXY_SERVICES_SIZE; i++)
        syn_cookies_[i].UpdateKeys();
}

// Info

common::idp::proxy_connections::response TcpConnectionStore::GetConnections(std::optional<proxy_service_id_t> service_id)
{
    common::idp::proxy_connections::response response;
    // uint64_t current_time = current_time_ms;
    // std::lock_guard guard(mutex_);

    // if (!service_id.has_value())
    // {
    //     for (uint32_t index = 0; index < YANET_CONFIG_PROXY_SERVICES_SIZE; index++)
    //     {
    //         service_connections_[index].GetConnections([&](ServiceConnections::Bucket& bucket, uint32_t conn_idx) {
    //             Connection& connection = bucket.connections[conn_idx];
    //             if (connection.local != 0 && !bucket.IsExpired(conn_idx, current_time))
    //             {
    //                 uint32_t local_addr;
    //                 uint16_t local_port;
    //                 ServiceConnections::Unpack(connection.local, local_addr, local_port);
    //                 response.emplace_back(index, bucket.addresses[conn_idx], bucket.ports[conn_idx], local_addr, local_port);
    //             }
    //         });
    //     }
    // }
    // else if (*service_id < YANET_CONFIG_PROXY_SERVICES_SIZE)
    // {
    //     service_connections_[*service_id].GetConnections([&](ServiceConnections::Bucket& bucket, uint32_t conn_idx) {
    //         Connection& connection = bucket.connections[conn_idx];
    //         if (connection.local != 0 && !bucket.IsExpired(conn_idx, current_time))
    //         {
    //             uint32_t local_addr;
    //             uint16_t local_port;
    //             ServiceConnections::Unpack(connection.local, local_addr, local_port);
    //             response.emplace_back(*service_id, bucket.addresses[conn_idx], bucket.ports[conn_idx], local_addr, local_port);
    //         }
    //     });
    // }

    return response;
}

common::idp::proxy_syn::response TcpConnectionStore::GetSyn(std::optional<proxy_service_id_t> service_id)
{
    common::idp::proxy_syn::response response;
    // uint64_t current_time = current_time_ms;
    // std::lock_guard guard(mutex_);
    
    // if (!service_id.has_value())
    // {
    //     for (uint32_t index = 0; index < YANET_CONFIG_PROXY_SERVICES_SIZE; index++)
    //     {
    //         syn_connections_[index].GetConnections([&](ServiceSynConnections::Bucket& bucket, uint32_t conn_idx) {
    //             if (!bucket.IsExpired(conn_idx, current_time, TIMEOUT_SYN))
    //             {
    //                 response.emplace_back(index, bucket.addresses[conn_idx], bucket.ports[conn_idx]);
    //             }
    //         });
    //     }
    // }
    // else if (*service_id < YANET_CONFIG_PROXY_SERVICES_SIZE)
    // {
    //     syn_connections_[*service_id].GetConnections([&](ServiceSynConnections::Bucket& bucket, uint32_t conn_idx) {
    //         if (!bucket.IsExpired(conn_idx, current_time, TIMEOUT_SYN))
    //         {
    //             response.emplace_back(*service_id, bucket.addresses[conn_idx], bucket.ports[conn_idx]);
    //         }
    //     });
    // }

    return response;
}

common::idp::proxy_local_pool::response TcpConnectionStore::GetLocalPool(std::optional<proxy_service_id_t> service_id)
{
    common::idp::proxy_local_pool::response response;
    // std::lock_guard guard(mutex_);

    // if (!service_id.has_value())
    // {
    //     for (uint32_t index = 0; index < YANET_CONFIG_PROXY_SERVICES_SIZE; index++)
    //     {
    //         local_pools_[index].GetLocalPool(index, response);
    //     }
    // }
    // else if (*service_id < YANET_CONFIG_PROXY_SERVICES_SIZE)
    // {
    //     local_pools_[*service_id].GetLocalPool(*service_id, response);
    // }

    return response;
}

common::idp::proxy_tables::response TcpConnectionStore::GetTables(std::optional<proxy_service_id_t> service_id)
{
    common::idp::proxy_tables::response response;

    // if (!service_id.has_value())
    // {
    //     for (uint32_t index = 0; index < YANET_CONFIG_PROXY_SERVICES_SIZE; index++)
    //     {
    //         if (service_connections_[index].IsInitialized())
    //         {
    //             response.emplace_back(index,
    //                               service_connections_[index].Size(), service_connections_[index].Capacity(),
    //                               syn_connections_[index].Size(), syn_connections_[index].Capacity());
    //         }
    //     }
    // }
    // else if (*service_id < YANET_CONFIG_PROXY_SERVICES_SIZE)
    // {
    //     return {{*service_id,
    //             service_connections_[*service_id].Size(), service_connections_[*service_id].Capacity(), 
    //             syn_connections_[*service_id].Size(), syn_connections_[*service_id].Capacity()}};
    // }

    return response;
}

void DebugPacket(const char* message, proxy_service_id_t service_id, const rte_ipv4_hdr* ipv4_header, const rte_tcp_hdr* tcp_header)
{
#ifdef TCP_PROXY_DEBUG
    YANET_LOG_WARNING("%s service_id=%d, %s:%d -> %s:%d, seq=%u, ack=%u\n", message, service_id,
        common::ipv4_address_t(rte_cpu_to_be_32(ipv4_header->src_addr)).toString().c_str(), rte_cpu_to_be_16(tcp_header->src_port),
        common::ipv4_address_t(rte_cpu_to_be_32(ipv4_header->dst_addr)).toString().c_str(), rte_cpu_to_be_16(tcp_header->dst_port),
        rte_cpu_to_be_32(tcp_header->sent_seq), rte_cpu_to_be_32(tcp_header->recv_ack));
#endif
}

void SwapAddresses(rte_ipv4_hdr* ipv4_header)
{
    rte_be32_t tmp = ipv4_header->src_addr;
    ipv4_header->src_addr = ipv4_header->dst_addr;
    ipv4_header->dst_addr = tmp;
}

void SwapPorts(rte_tcp_hdr* tcp_header)
{
    rte_be16_t tmp = tcp_header->src_port;
    tcp_header->src_port = tcp_header->dst_port;
    tcp_header->dst_port = tmp;
}

void UpdateCheckSums(rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    ipv4_header->hdr_checksum = 0;
    ipv4_header->hdr_checksum = rte_ipv4_cksum(ipv4_header);
    tcp_header->cksum = 0;
    tcp_header->cksum = rte_ipv4_udptcp_cksum((rte_ipv4_hdr*)ipv4_header, tcp_header);
}

void DecreaseMssInTcpOptions(rte_mbuf* mbuf, rte_ipv4_hdr** ipv4_header, rte_tcp_hdr** tcp_header)
{
	size_t tcp_header_len = ((*tcp_header)->data_off >> 4) << 2;
	TcpOptions tcp_options;
	memset(&tcp_options, 0, sizeof(tcp_options));
	tcp_options.Read((uint8_t*)(*tcp_header) + sizeof(rte_tcp_hdr), tcp_header_len);
	tcp_options.mss -= int(sizeof(proxy_v2_ipv4_hdr));
	tcp_options.Write(mbuf, ipv4_header, tcp_header);
}

bool NonEmptyTcpData(rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
    return (rte_be_to_cpu_16(ipv4_header->total_length) != sizeof(rte_ipv4_hdr) + tcp_header_len);
}

uint32_t TcpConnectionStore::BuildSynCookieAndFillTcpOptionsAnswer(proxy_service_id_t service_id, const proxy_service_t& service, rte_mbuf* mbuf, rte_ipv4_hdr** ipv4_header, rte_tcp_hdr** tcp_header)
{
    size_t tcp_header_len = ((*tcp_header)->data_off >> 4) << 2;
    TcpOptions tcp_options;
    memset(&tcp_options, 0, sizeof(tcp_options));
    tcp_options.Read((uint8_t*)(*tcp_header) + sizeof(rte_tcp_hdr), tcp_header_len);
    tcp_options.sack_permitted &= service.use_sack;
    tcp_options.mss = std::min(tcp_options.mss, (uint16_t)service.mss);

    uint32_t cookie_data = SynCookies::PackData(tcp_options);
    uint32_t cookie = syn_cookies_[service_id].GetCookie((*ipv4_header)->src_addr, (*tcp_header)->src_port, (*tcp_header)->sent_seq, cookie_data);
    // YANET_LOG_WARNING("\tcookie_data=%d, cookie=%u, seq=%u\n", cookie_data, cookie, tcp_header->sent_seq);

    tcp_options.window_scaling = service.winscale;
    if (tcp_options.timestamp_value != 0 && service.timestamps)
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
    if (service.send_proxy_header)
    {
        tcp_options.mss -= int(sizeof(proxy_v2_ipv4_hdr));
    }
    tcp_options.Write(mbuf, ipv4_header, tcp_header);

    return cookie;
}

void ActionClientOnSynPrepareSynToClient(rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header, uint32_t cookie)
{
    SwapAddresses(ipv4_header);
    ipv4_header->time_to_live = 64;
    tcp_header->recv_ack = add_cpu_32(tcp_header->sent_seq, 1);
    tcp_header->sent_seq = rte_cpu_to_be_32(cookie);
    tcp_header->tcp_flags = TCP_SYN_FLAG | TCP_ACK_FLAG;
    tcp_header->rx_win = 0;
    SwapPorts(tcp_header);
}

void ActionClientOnSynPrepareSynToService(const proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header, uint64_t local)
{
    LocalPool::UnpackTupleSrc(local, ipv4_header, tcp_header);
    if (service.send_proxy_header)
    {
        // При использовании ProxyHeader уменьшаем значение SEQ полученное от клиента
        tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, sizeof(proxy_v2_ipv4_hdr));
    }

    ipv4_header->dst_addr = service.upstream_addr;
    tcp_header->dst_port = service.upstream_port;
}

// Action from worker
bool TcpConnectionStore::ActionClientOnSyn(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters, uint32_t worker_id)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
	
    proxy_service_id_t service_id = metadata->flow.data.proxy_service_id;
    dataplane::proxy::proxy_service_t& service = base.globalBase->proxy_services[service_id];

	counters[service.counter_id + (tCounterId)::proxy::service_counter::packets_in]++;
    counters[service.counter_id + (tCounterId)::proxy::service_counter::bytes_in] += mbuf->pkt_len;
    counters[service.counter_id + (tCounterId)::proxy::service_counter::syn_count]++;

    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_client_syn", service_id, ipv4_header, tcp_header);
    bool action = true;

    ServiceConnectionData service_connection_data;
    switch (service.tables.service_connections.FindAndLock(ipv4_header->src_addr, tcp_header->src_port, current_time_ms, service_connection_data))
    {
        case TableSearchResult::Overflow:
        {
            counters[service.counter_id + (tCounterId)::proxy::service_counter::service_bucket_overflow]++;
            action = false;
            break;
        }
        case TableSearchResult::Found:
        {
            if (!service_connection_data.connection->CreatedFromSynCookie())
            {
                // todo
                action = false;
            }
            else
            {
                // todo
                action = false;
            }
            break;
        }
        case TableSearchResult::NotFound:
        {
            SynConnectionData syn_connection_data;
            switch (service.tables.syn_connections.FindAndLock(ipv4_header->src_addr, tcp_header->src_port, current_time_ms, syn_connection_data))
            {
                case TableSearchResult::Overflow:
                {
                    uint32_t cookie = BuildSynCookieAndFillTcpOptionsAnswer(service_id, service, mbuf, &ipv4_header, &tcp_header);
                    ActionClientOnSynPrepareSynToClient(ipv4_header, tcp_header, cookie);
                    counters[service.counter_id + (tCounterId)::proxy::service_counter::packets_out]++;
				    counters[service.counter_id + (tCounterId)::proxy::service_counter::bytes_out] += mbuf->pkt_len;
                    break;
                }
                case TableSearchResult::Found:
                {
                    ActionClientOnSynPrepareSynToService(service, ipv4_header, tcp_header, syn_connection_data.connection->local);
                    break;
                }
                case TableSearchResult::NotFound:
                {
                    uint64_t local = service.tables.local_pool.Allocate(worker_id, ipv4_header->src_addr, tcp_header->src_port);
                    if (local == 0)
                    {
                        counters[service.counter_id + (tCounterId)::proxy::service_counter::failed_local_pool_allocation]++;
                        action = false;
                    }
                    else
                    {
                        syn_connection_data.Init(ipv4_header->src_addr, tcp_header->src_port, current_time_ms);
                        syn_connection_data.connection->local = local;
                        syn_connection_data.connection->client_start_seq = tcp_header->sent_seq;

                        ActionClientOnSynPrepareSynToService(service, ipv4_header, tcp_header, local);
                        counters[service.counter_id + (tCounterId)::proxy::service_counter::new_syn_connections]++;
                    }
                    break;
                }
            }
            syn_connection_data.Unlock();
            break;
        }
    }
    service_connection_data.Unlock();

    if (action)
    {
        UpdateCheckSums(ipv4_header, tcp_header);
    }

    return action;
}

void AddProxyHeader(const proxy_service_t& service, rte_mbuf* mbuf, dataplane::metadata* metadata,
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
}

uint32_t TcpConnectionStore::CheckSynCookie(proxy_service_id_t service_id, const proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    if (!service.ignore_size_update_detections && 
        // ACK's seq has the same evenness bit as SYN's seq(encoded into cookie)
        // This means ACK's seq IS the same as SYN's. So it must be incremented
        (rte_be_to_cpu_32(tcp_header->sent_seq) & 1) == ((rte_be_to_cpu_32(tcp_header->recv_ack) - 1) & 1))
    {
        tcp_header->sent_seq = add_cpu_32(tcp_header->sent_seq, 1);
    }

    uint32_t cookie_data = syn_cookies_[service_id].CheckCookie(rte_cpu_to_be_32(tcp_header->recv_ack) - 1, 
                                                                ipv4_header->src_addr, tcp_header->src_port, sub_cpu_32(tcp_header->sent_seq, 1));
    // YANET_LOG_WARNING("\tcookie_data=%d, ack=%u, seq=%u\n", cookie_data, tcp_header->recv_ack, tcp_header->sent_seq);

    return cookie_data;
}

bool TcpConnectionStore::ActionClientOnAck(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters, uint32_t worker_id)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    proxy_service_id_t service_id = metadata->flow.data.proxy_service_id;
    dataplane::proxy::proxy_service_t& service = base.globalBase->proxy_services[service_id];

    counters[service.counter_id + (tCounterId)::proxy::service_counter::packets_in]++;
    counters[service.counter_id + (tCounterId)::proxy::service_counter::bytes_in] += mbuf->pkt_len;

    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_client_ack", service_id, ipv4_header, tcp_header);
    bool action = true;

    ServiceConnectionData service_connection_data;
    switch (service.tables.service_connections.FindAndLock(ipv4_header->src_addr, tcp_header->src_port, current_time_ms, service_connection_data))
    {
        case TableSearchResult::Overflow:
        {
            counters[service.counter_id + (tCounterId)::proxy::service_counter::service_bucket_overflow]++;
            action = false;
            break;
        }
        case TableSearchResult::Found:
        {
            // check non-empty tcp-data packet
            if (NonEmptyTcpData(ipv4_header, tcp_header))
            {
                service_connection_data.connection->flags |= Connection::flag_nonempty_ack_from_client;
            }

            if (tcp_header->sent_seq == service_connection_data.connection->client_start_seq)
            {
                // todo - add check + only syn-cookie
                if (service.ignore_size_update_detections)
                {
                    counters[service.counter_id + (tCounterId)::proxy::service_counter::ignored_size_update_detections]++;
                    action = false;
                }
                else
                {
                    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
                    TcpOptions tcp_options;
                    memset(&tcp_options, 0, sizeof(tcp_options));
                    tcp_options.Read((uint8_t*)tcp_header + sizeof(rte_tcp_hdr), tcp_header_len);

                    LocalPool::UnpackTupleSrc(service_connection_data.connection->local, ipv4_header, tcp_header);
                    tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, (service.send_proxy_header ? sizeof(proxy_v2_ipv4_hdr) : 0));

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
                tcp_options.ReadOnlyTimestampsAndSack(tcp_header);
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
                if (is_first_ack && service.send_proxy_header)
                {
                    tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, sizeof(proxy_v2_ipv4_hdr));
                    AddProxyHeader(service, mbuf, metadata, &ipv4_header, &tcp_header, src_addr, src_port);
                }
            }

            break;
        }
        case TableSearchResult::NotFound:
        {
            uint32_t flags = (NonEmptyTcpData(ipv4_header, tcp_header) ? Connection::flag_nonempty_ack_from_client : 0);

            SynConnectionData syn_connection_data;
            if (service.tables.syn_connections.FindAndLock(ipv4_header->src_addr, tcp_header->src_port, current_time_ms, syn_connection_data) == TableSearchResult::Found)
            {
                if (!syn_connection_data.connection->server_answer)
                {
                    // ack, but server didn't answer
                    syn_connection_data.Unlock();
                    counters[service.counter_id + (tCounterId)::proxy::service_counter::ack_without_service_answer]++;
                    action = false;
                }
                else
                {
                    uint32_t src_addr = ipv4_header->src_addr;
                    uint16_t src_port = tcp_header->src_port;
                    service_connection_data.Init(ipv4_header->src_addr, tcp_header->src_port, current_time_ms);
                    LocalPool::UnpackTupleSrc(syn_connection_data.connection->local, ipv4_header, tcp_header);
                    service_connection_data.connection->client_start_seq = syn_connection_data.connection->client_start_seq;
                    syn_connection_data.bucket->Clear(syn_connection_data.idx);
                    syn_connection_data.Unlock();

                    service_connection_data.connection->flags = flags;
                    service_connection_data.connection->local = ServiceSynConnections::Pack(ipv4_header->src_addr, tcp_header->src_port);

                    if (service.send_proxy_header)
                    {
                            tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, sizeof(proxy_v2_ipv4_hdr));
                            AddProxyHeader(service, mbuf, metadata, &ipv4_header, &tcp_header, src_addr, src_port);
                    }

                    counters[service.counter_id + (tCounterId)::proxy::service_counter::new_connections]++;
                }
            }
            else
            {
                syn_connection_data.Unlock();

                // try check cookie
                // todo - check time overflow
                uint32_t cookie_data = CheckSynCookie(service_id, service, ipv4_header, tcp_header);
                if (cookie_data == 0)
                {
                    counters[service.counter_id + (tCounterId)::proxy::service_counter::failed_check_syn_cookie]++;
                    action = true;
                }
                else
                {
                    // get from local
                    uint64_t local = service.tables.local_pool.Allocate(worker_id, ipv4_header->src_addr, tcp_header->src_port);
                    if (local == 0)
                    {
                        counters[service.counter_id + (tCounterId)::proxy::service_counter::failed_local_pool_allocation]++;
                        action = false;
                    }
                    else
                    {
                        size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
                        TcpOptions tcp_options;
                        memset(&tcp_options, 0, sizeof(tcp_options));
                        tcp_options.Read((uint8_t*)tcp_header + sizeof(rte_tcp_hdr), tcp_header_len);

                        // Add to connections
                        service_connection_data.Init(ipv4_header->src_addr, tcp_header->src_port, current_time_ms);
                        LocalPool::UnpackTupleSrc(local, ipv4_header, tcp_header);
                        service_connection_data.connection->local = ServiceSynConnections::Pack(ipv4_header->src_addr, tcp_header->src_port);
                        service_connection_data.connection->proxy_start_seq = rte_be_to_cpu_32(tcp_header->recv_ack) - 1;
                        service_connection_data.connection->client_start_seq = sub_cpu_32(tcp_header->sent_seq, 1);
                        service_connection_data.connection->timestamp_proxy_first = tcp_options.timestamp_echo;
                        service_connection_data.connection->timestamp_client_last = tcp_options.timestamp_value;
                        service_connection_data.connection->cookie_data = cookie_data;

                        tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, 1 + (service.send_proxy_header ? sizeof(proxy_v2_ipv4_hdr) : 0));

                        TcpOptions cookie_options = SynCookies::UnpackData(cookie_data);
                        if (tcp_options.timestamp_value != 0 && service.timestamps)
                        {
                            cookie_options.timestamp_value = tcp_options.timestamp_value;
                        }
                        else
                        {
                            cookie_options.timestamp_value = 0;
                            flags |= Connection::flag_no_timestamps;
                        }
                        service_connection_data.connection->flags = Connection::flag_from_synkookie | flags;

                        cookie_options.Write(mbuf, &ipv4_header, &tcp_header);
                        ipv4_header->time_to_live = 64;
                        tcp_header->recv_ack = 0;
                        tcp_header->tcp_flags = TCP_SYN_FLAG;

                        counters[service.counter_id + (tCounterId)::proxy::service_counter::new_connections]++;
                    }
                }
            }
                        
            break;
        }
    }

    service_connection_data.Unlock();

    if (action)
    {
        ipv4_header->dst_addr = service.upstream_addr;
        tcp_header->dst_port = service.upstream_port;
        UpdateCheckSums(ipv4_header, tcp_header);
    }

    return action;
}

bool TcpConnectionStore::ActionServiceOnSynAck(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    proxy_service_id_t service_id = metadata->flow.data.proxy_service_id;
    dataplane::proxy::proxy_service_t& service = base.globalBase->proxy_services[service_id];

    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_server_syn_ack", service_id, ipv4_header, tcp_header);

    uint64_t client_info = service.tables.local_pool.FindClientByLocal(ipv4_header->dst_addr, tcp_header->dst_port);
    if (client_info == 0)
    {
        counters[service.counter_id + (tCounterId)::proxy::service_counter::failed_local_pool_search]++;
        return false;
    }
    uint32_t client_addr;
    tPortId client_port;
    LocalPool::UnpackTuple(client_info, client_addr, client_port);

    SynConnectionData syn_connection_data;
    if (service.tables.syn_connections.FindAndLock(client_addr, client_port, current_time_ms, syn_connection_data) == TableSearchResult::Found)
    {
        syn_connection_data.connection->server_answer = true;
        syn_connection_data.Unlock();

        if (service.send_proxy_header)
        {
            tcp_header->recv_ack = add_cpu_32(tcp_header->recv_ack, sizeof(proxy_v2_ipv4_hdr));
            DecreaseMssInTcpOptions(mbuf, &ipv4_header, &tcp_header);
        }

        ipv4_header->src_addr = service.proxy_addr;
        ipv4_header->dst_addr = client_addr;
        tcp_header->src_port = service.proxy_port;
        tcp_header->dst_port = client_port;
        UpdateCheckSums(ipv4_header, tcp_header);

        counters[service.counter_id + (tCounterId)::proxy::service_counter::packets_out]++;
        counters[service.counter_id + (tCounterId)::proxy::service_counter::bytes_out] += mbuf->pkt_len;			

        return true;
    }
    syn_connection_data.Unlock();

    ServiceConnectionData service_connection_data;
    if (service.tables.service_connections.FindAndLock(client_addr, client_port, current_time_ms, service_connection_data) != TableSearchResult::Found)
    {
        service_connection_data.Unlock();
        counters[service.counter_id + (tCounterId)::proxy::service_counter::failed_answer_service_syn_ack]++;
        return false;
    }

    bool action = true;
    service_connection_data.connection->flags |= Connection::flag_answer_from_server;
    if (!service_connection_data.connection->CreatedFromSynCookie())
    {
        // todo
    }
    else
    {
        size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
        TcpOptions tcp_options;
        memset(&tcp_options, 0, sizeof(tcp_options));
        tcp_options.Read((uint8_t*)tcp_header + sizeof(rte_tcp_hdr), tcp_header_len);

        bool old_sack_permitted = tcp_options.sack_permitted;
        service_connection_data.connection->window_size_shift = (int)tcp_options.window_scaling - (int)service.winscale;

        if (tcp_options.timestamp_value != 0)
        {
            service_connection_data.connection->timestamp_shift = service_connection_data.connection->timestamp_proxy_first - tcp_options.timestamp_value;
            tcp_options.timestamp_value = service_connection_data.connection->timestamp_proxy_first;
        }
        else if ((service_connection_data.connection->flags & Connection::flag_no_timestamps) == 0)
        {
            tcp_options.timestamp_value = current_time_sec;
#ifdef CONFIG_YADECAP_AUTOTEST
            tcp_options.timestamp_value = ++service_connection_data.connection->timestamp_proxy_first;
#endif
            tcp_options.timestamp_echo = service_connection_data.connection->timestamp_client_last;
            service_connection_data.connection->flags |= Connection::flag_timestamp_fail;
            counters[service.counter_id + (tCounterId)::proxy::service_counter::error_service_config_timestamps]++;
        }

        tcp_options.sack_permitted = false;
        tcp_options.mss = 0;
        tcp_options.window_scaling = 0;
        tcp_options.Write(mbuf, &ipv4_header, &tcp_header);

        
        tcp_header->rx_win = shift_cpu_16(tcp_header->rx_win, service_connection_data.connection->window_size_shift);

        service_connection_data.connection->shift_server = service_connection_data.connection->proxy_start_seq - rte_be_to_cpu_32(tcp_header->sent_seq);
        tcp_header->sent_seq = rte_cpu_to_be_32(service_connection_data.connection->proxy_start_seq + 1);

        tcp_header->tcp_flags = TCP_ACK_FLAG;

        if (service.send_proxy_header)
        {
            tcp_header->recv_ack = add_cpu_32(tcp_header->recv_ack, sizeof(proxy_v2_ipv4_hdr));
        }

        if (service.use_sack && !old_sack_permitted)
        {
            // error, server does not support SACK, although the configuration file states that it supports
            service_connection_data.connection->flags |= Connection::flag_clear_sack;
            counters[service.counter_id + (tCounterId)::proxy::service_counter::error_service_config_sack]++;
        }
    }

    service_connection_data.Unlock();

    ipv4_header->src_addr = service.proxy_addr;
    ipv4_header->dst_addr = client_addr;
    tcp_header->src_port = service.proxy_port;
    tcp_header->dst_port = client_port;
    
    UpdateCheckSums(ipv4_header, tcp_header);

    counters[service.counter_id + (tCounterId)::proxy::service_counter::packets_out]++;
    counters[service.counter_id + (tCounterId)::proxy::service_counter::bytes_out] += mbuf->pkt_len;			

    return action;
}

bool TcpConnectionStore::ActionServiceOnAck(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    proxy_service_id_t service_id = metadata->flow.data.proxy_service_id;
    dataplane::proxy::proxy_service_t& service = base.globalBase->proxy_services[service_id];

    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_server_ack", service_id, ipv4_header, tcp_header);

    uint64_t client_info = service.tables.local_pool.FindClientByLocal(ipv4_header->dst_addr, tcp_header->dst_port);
    if (client_info == 0)
    {
        counters[service.counter_id + (tCounterId)::proxy::service_counter::failed_local_pool_search]++;
        return false;
    }
    uint32_t client_addr;
    tPortId client_port;
    LocalPool::UnpackTuple(client_info, client_addr, client_port);

    ServiceConnectionData service_connection_data;
    if (service.tables.service_connections.FindAndLock(client_addr, client_port, current_time_ms, service_connection_data) != TableSearchResult::Found)
    {
        service_connection_data.Unlock();
        counters[service.counter_id + (tCounterId)::proxy::service_counter::failed_search_client_service_ack]++;
        return false;
    }

    if (service_connection_data.connection->CreatedFromSynCookie())
    {
        tcp_header->sent_seq = add_cpu_32(tcp_header->sent_seq, service_connection_data.connection->shift_server);

        TcpOptions tcp_options;
        memset(&tcp_options, 0, sizeof(tcp_options));
        tcp_options.ReadOnlyTimestampsAndSack(tcp_header);
        if (tcp_options.timestamp_value != 0)
        {
            tcp_options.timestamp_value += service_connection_data.connection->timestamp_shift;
            tcp_options.Write(mbuf, &ipv4_header, &tcp_header);
        }
        else if ((service_connection_data.connection->flags & Connection::flag_timestamp_fail) != 0)
        {
            tcp_options.timestamp_value = current_time_sec;
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
    ipv4_header->src_addr = service.proxy_addr;
    tcp_header->dst_port = client_port;
    tcp_header->src_port = service.proxy_port;

    UpdateCheckSums(ipv4_header, tcp_header);

    counters[service.counter_id + (tCounterId)::proxy::service_counter::packets_out]++;
    counters[service.counter_id + (tCounterId)::proxy::service_counter::bytes_out] += mbuf->pkt_len;			

    return true;
}

void TcpConnectionStore::GetDataForRetramsits(uint32_t before_time, rte_ring* ring_retransmit_free, rte_ring* ring_retransmit_send)
{
    // YANET_LOG_WARNING("TcpConnectionStore::GetDataForRetramsits\n");
//     uint32_t count = 0;
//     for (uint32_t index_service = 0; (index_service < YANET_CONFIG_PROXY_SERVICES_SIZE) && (rte_ring_empty(ring_retransmit_free) == 0) && count < MAX_COUNT_RETRANSMITS_ALL_SERVICES; index_service++)
//     {
//         count += service_connections_[index_start_check_retransmits_].GetDataForRetramsits([&](ServiceConnections::Bucket& bucket, uint32_t conn_idx, uint64_t service_key) -> bool {
//             Connection& connection = bucket.connections[conn_idx];
//             if ((ServiceConnections::Pack(bucket.addresses[conn_idx], bucket.ports[conn_idx]) != 0) && (bucket.last_times[conn_idx] != 0) && (bucket.last_times[conn_idx] <= before_time) && 
//                 ((connection.flags & Connection::flag_from_synkookie) != 0) && ((connection.flags & Connection::flag_sent_rentransmit_syn_to_server) == 0) &&
//                 ((connection.flags & Connection::flag_nonempty_ack_from_client) == 0)) {
//                 DataForRetransmit* data;
//                 if (rte_ring_dequeue(ring_retransmit_free, (void**)&data) != 0)
//                 {
//                     return true;
//                 }

//                 TcpOptions tcp_options = SynCookies::UnpackData(connection.cookie_data);
//                 tcp_options.timestamp_value = connection.timestamp_client_last;
//                 tcp_options.timestamp_echo = 0;

//                 data->tcp_options_len = tcp_options.WriteBuffer(data->tcp_options_data);

// #ifdef TCP_PROXY_DEBUG
//                 YANET_LOG_WARNING("Add to retransmit, cookie_data=%d, tcp_options=%s, flags=%u\n", connection.cookie_data, tcp_options.DebugInfo().c_str(), connection.flags);
// #endif

//                 data->service_id = index_start_check_retransmits_;
//                 ServiceConnections::Unpack(connection.local, data->src, data->sport);
//                 ServiceConnections::Unpack(service_key, data->dst, data->dport);
//                 data->client_start_seq = connection.client_start_seq;
//                 data->flow = next_flow_;

//                 if (rte_ring_enqueue(ring_retransmit_send, (void*)data) != 0)
//                 {
//                     return true;
//                 }

//                 connection.flags |= Connection::flag_sent_rentransmit_syn_to_server;

//                 count++;
//                 if (count >= MAX_COUNT_RETRANSMITS_PER_SERVICE) {
//                     return true;
//                 }
//             }
//             return false;
//         });

//         index_start_check_retransmits_++;
//         if (index_start_check_retransmits_ >= YANET_CONFIG_PROXY_SERVICES_SIZE)
//         {
//             index_start_check_retransmits_ = 0;
//         }
//     }
}

TcpConnectionStore::TcpConnectionStore()
{
    for (uint32_t index = 0; index < YANET_CONFIG_PROXY_SERVICES_SIZE; index++)
    {
        // updater_proxy_tables[index] = UpdaterProxyTables();
    }
}

UpdaterProxyTables::UpdaterProxyTables()
{
    // tables[0] = ProxyTables();
    // tables[1] = ProxyTables();
}

eResult UpdaterProxyTables::FirstUpdate(uint8_t old_index, uint8_t new_index, dataplane::memory_manager* memory_manager, const proxy_service_t& service)
{
    YANET_LOG_WARNING("First update, activate: %d\n", new_index);
    if (!tables[new_index].NeedUpdate(service))
    {
        return eResult::success;
    }

    tables[new_index].ClearIfNotEqual(tables[old_index], memory_manager);
    return tables[new_index].Allocate(memory_manager, service);
}

eResult UpdaterProxyTables::SecondUpdate(uint8_t old_index, uint8_t new_index, dataplane::memory_manager* memory_manager)
{
    YANET_LOG_WARNING("Second update, move: %d->%d\n", old_index, new_index);
    tables[new_index].ClearIfNotEqual(tables[old_index], memory_manager);
    tables[new_index].CopyFrom(tables[old_index]);
    return eResult::success;
}

void UpdaterProxyTables::FirstRemove(uint8_t old_index, uint8_t new_index, dataplane::memory_manager* memory_manager)
{
    tables[new_index].ClearIfNotEqual(tables[old_index], memory_manager);
    tables[new_index].ClearLinks();
}

void UpdaterProxyTables::SecondRemove(uint8_t old_index, uint8_t new_index, dataplane::memory_manager* memory_manager)
{
    tables[new_index].ClearIfNotEqual(tables[old_index], memory_manager);
}

bool ProxyTables::NeedUpdate(const proxy_service_t& service)
{
    return service_connections.NeedUpdate(service.size_connections_table) || syn_connections.NeedUpdate(service.size_syn_table) || local_pool.NeedUpdate(service.pool_prefix);
}

void ProxyTables::ClearIfNotEqual(const ProxyTables& other, dataplane::memory_manager* memory_manager)
{
    service_connections.ClearIfNotEqual(other.service_connections, memory_manager);
    syn_connections.ClearIfNotEqual(other.syn_connections, memory_manager);
    local_pool.ClearIfNotEqual(other.local_pool, memory_manager);
}

eResult ProxyTables::Allocate(dataplane::memory_manager* memory_manager, const proxy_service_t& service)
{
    if (!service_connections.Init(service.service_id, service.size_connections_table, memory_manager, service.upstream_addr, service.upstream_port))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.ServiceConnections, service: %d\n", service.service_id);
        return eResult::errorAllocatingMemory;
    }

    if (!syn_connections.Init(service.service_id, service.size_syn_table, memory_manager, service.upstream_addr, service.upstream_port))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.SynConnections, service: %d\n", service.service_id);
        return eResult::errorAllocatingMemory;
    }

    
    if (!local_pool.Init(service.service_id, service.pool_prefix, memory_manager))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.LocalPool, service: %d\n", service.service_id);
        return eResult::errorAllocatingMemory;
    }

    return eResult::success;
}

void ProxyTables::CopyFrom(const ProxyTables& other)
{
    service_connections.CopyFrom(other.service_connections);
    syn_connections.CopyFrom(other.syn_connections);
    local_pool.CopyFrom(other.local_pool);
}

void ProxyTables::ClearLinks()
{
    service_connections.ClearLinks();
    syn_connections.ClearLinks();
    local_pool.ClearLinks();
}

}
