#include <sstream>

#include "common/counters.h"

#include "common.h"
#include "metadata.h"
#include "proxy.h"

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

const uint8_t PROXY_V2_SIGNATURE[12] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

bool TcpOptions::Read(uint8_t* data, uint32_t len)
{
    uint32_t index = 0;
    while (index < len)
    {
        switch (data[index])
        {
        case TCPOPT_MSS:
            if (!CheckSize(index, len, data, 4)) {
                return false;
            }
            mss = rte_be_to_cpu_16(*((uint16_t*)(data + index + 2)));
            index += 4;
            break;

        case TCPOPT_SACK_PERM:
            if (!CheckSize(index, len, data, 2)) {
                return false;
            }
            sack_permitted = 1;

            index += 2;
            break;

        case TCPOPT_TIMESTAMP:
            if (!CheckSize(index, len, data, 10)) {
                return false;
            }

            timestamp_value = rte_be_to_cpu_32(*((uint32_t*)(data + index + 2)));
            timestamp_echo = rte_be_to_cpu_32(*((uint32_t*)(data + index + 6)));

            index += 10;
            break;

        case TCPOPT_NOP:
            index++;
            break;

        case TCPOPT_EOL:
            return true;

        case TCPOPT_WINDOW:
            if (!CheckSize(index, len, data, 3)) {
                return false;
            }

            window_scaling = data[index + 2];
            
            index += 3;
            break;
        
        default:
            // unknown option
            return false;
            break;
        }
    }
    return true;
}

uint32_t TcpOptions::WriteBuffer(uint8_t* data) const
{
    uint32_t len = 0;
    
    if (mss != 0)
    {
        data[len] = TCPOPT_MSS;
        data[len + 1] = 4;
        *((uint16_t*)(data + len + 2)) = rte_cpu_to_be_16(mss);
        len += 4;
    }

    if (sack_permitted != 0)
    {
        data[len] = TCPOPT_SACK_PERM;
        data[len + 1] = 2;
        len += 2;
    }

    if (timestamp_value != 0 || timestamp_echo != 0)
    {
        data[len] = TCPOPT_TIMESTAMP;
        data[len + 1] = 10;
        *((uint32_t*)(data + len + 2)) = rte_cpu_to_be_32(timestamp_value);
        *((uint32_t*)(data + len + 6)) = rte_cpu_to_be_32(timestamp_echo);
        len += 10;
    }

    if (window_scaling != 0)
    {
        data[len] = TCPOPT_WINDOW;
        data[len + 1] = 3;
        data[len + 2] = window_scaling;
        len += 3;
    }

    while ((len % 4) != 0)
    {
        data[len++] = TCPOPT_NOP;
    }

    return len;
}

uint32_t TcpOptions::Write(rte_mbuf* mbuf) const
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    size_t tcp_header_len_old = (tcp_header->data_off >> 4) << 2;
    uint16_t tcp_data_len = rte_be_to_cpu_16(ipv4_header->total_length) - rte_ipv4_hdr_len(ipv4_header) - tcp_header_len_old;

    uint8_t* data = (uint8_t*)tcp_header + sizeof(rte_tcp_hdr);
    uint32_t len = WriteBuffer(data);

    tcp_header->data_off = ((sizeof(rte_tcp_hdr) + len) >> 2) << 4;
    
    uint16_t total_length = rte_ipv4_hdr_len(ipv4_header) + sizeof(rte_tcp_hdr) + len + tcp_data_len;
    ipv4_header->total_length = rte_cpu_to_be_16(total_length);

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

void ShiftTcpOptions(rte_tcp_hdr* tcp_header, uint32_t sack, uint32_t timestamp_value, uint32_t timestamp_echo)
{
    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
    uint8_t* options = (uint8_t*)tcp_header + sizeof(rte_tcp_hdr);
    uint32_t len = tcp_header_len - sizeof(rte_tcp_hdr);

    uint32_t index = 0;
    while (index < len)
    {
        switch (options[index])
        {
        case TCPOPT_SACK:
            *((uint32_t*)(options + index + 2)) = add_cpu_32(*((uint32_t*)(options + index + 2)), sack);
            *((uint32_t*)(options + index + 6)) = add_cpu_32(*((uint32_t*)(options + index + 6)), sack);
            index += 10;
            break;
        case TCPOPT_TIMESTAMP:
            *((uint32_t*)(options + index + 2)) = add_cpu_32(*((uint32_t*)(options + index + 2)), timestamp_value);
            *((uint32_t*)(options + index + 6)) = add_cpu_32(*((uint32_t*)(options + index + 6)), timestamp_echo);
            index += 10;
            break;
        case TCPOPT_NOP:
            index++;
            break;
        case TCPOPT_EOL:
            return;
        default:
            index += options[index + 1]; // todo =0?
        }
    }
}

void FillProxyHeader(proxy_v2_ipv4_hdr* proxy_header, uint32_t src_addr, tPortId src_port, uint32_t dst_addr, tPortId dst_port)
{
    rte_memcpy(proxy_header->signature, PROXY_V2_SIGNATURE, 12);
    proxy_header->version_cmd = (PROXY_VERSION_V2 << 4) + PROXY_CMD_LOCAL;
    proxy_header->af_proto = (PROXY_AF_INET << 4) + PROXY_PROTO_STREAM;
    proxy_header->addr_len = rte_cpu_to_be_16(4+4+4);
    proxy_header->src_addr = src_addr;
    proxy_header->dst_addr = dst_addr;
    proxy_header->src_port = src_port;
    proxy_header->dst_port = dst_port;
}



// Update

void TcpConnectionStore::proxy_update(proxy_id_t proxy_id, const dataplane::globalBase::proxy_t& proxy)
{
    YANET_LOG_WARNING("proxy_update: proxy_id=%d\n", proxy_id);
    YANET_LOG_WARNING("\ttimeout_syn_rto=%d, timeout_syn_recv=%d, timeout_established=%d, flow=%s\n", proxy.timeout_syn_rto, proxy.timeout_syn_recv, proxy.timeout_established, proxy.flow.to_string().c_str());

    next_flow_ = proxy.flow;
}

void TcpConnectionStore::proxy_remove(proxy_id_t proxy_id)
{
    YANET_LOG_WARNING("proxy_remove: proxy_id=%d\n", proxy_id);
}

eResult TcpConnectionStore::proxy_service_update(proxy_service_id_t service_id, const dataplane::globalBase::proxy_service_t& service, const common::ipv4_prefix_t& prefix, dataplane::memory_manager* memory_manager)
{
    YANET_LOG_WARNING("proxy_service_update: service_id=%d, proxy=%s:%d, upstream=%s:%d, prefix=%s, proxy_header=%d, size_connections_table=%d, size_syn_table=%d\n",
        service_id, common::ipv4_address_t(rte_cpu_to_be_32(service.proxy_addr)).toString().c_str(), rte_cpu_to_be_16(service.proxy_port),
        common::ipv4_address_t(rte_cpu_to_be_32(service.upstream_addr)).toString().c_str(), rte_cpu_to_be_16(service.upstream_port), prefix.toString().c_str(), service.proxy_header, service.size_connections_table, service.size_syn_table);

    std::lock_guard guard(mutex_);

    if (!service_connections_[service_id].Initialize(service_id, service.size_connections_table, memory_manager, service.upstream_addr, service.upstream_port))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.ServiceConnections, service: %d\n", service_id);
        return eResult::errorAllocatingMemory;
    }

    if (!syn_connections_[service_id].Initialize(service_id, service.size_syn_table, memory_manager, service.upstream_addr, service.upstream_port))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.SynConnections, service: %d\n", service_id);
        return eResult::errorAllocatingMemory;
    }

    ipv4_prefix_t pool_prefix;
    pool_prefix.address = ipv4_address_t::convert(prefix.address());
    pool_prefix.address.address = rte_be_to_cpu_32(pool_prefix.address.address);
    pool_prefix.mask = prefix.mask();
    if (!local_pools_[service_id].Init(service_id, pool_prefix, memory_manager))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.LocalPool, service: %d\n", service_id);
        return eResult::errorAllocatingMemory;
    }

    return eResult::success;
}

void TcpConnectionStore::proxy_service_remove(proxy_service_id_t service_id)
{
    YANET_LOG_WARNING("proxy_service_remove: service_id=%d\n", service_id);
}

void TcpConnectionStore::CollectGarbage(uint32_t current_time)
{
    // YANET_LOG_WARNING("TcpConnectionStore::CollectGarbage: current_time=%d\n", current_time);
    std::lock_guard guard(mutex_);
    for (uint32_t index = 0; index < YANET_CONFIG_PROXY_SERVICES_SIZE; index++)
    {
        syn_connections_[index].CollectGarbage(current_time, local_pools_[index]);
        service_connections_[index].CollectGarbage(current_time, local_pools_[index]);
    }
}

void TcpConnectionStore::UpdateSynCookieKeys()
{
    YANET_LOG_WARNING("TcpConnectionStore::UpdateSynCookieKeys\n");
    std::lock_guard guard(mutex_);
    syn_cookies_.UpdateKeys();
}

// Info

common::idp::proxy_connections::response TcpConnectionStore::GetConnections(std::optional<proxy_service_id_t> service_id)
{
    common::idp::proxy_connections::response response;
    uint32_t current_time = currentTime;
    std::lock_guard guard(mutex_);

    if (!service_id.has_value())
    {
        for (uint32_t index = 0; index < YANET_CONFIG_PROXY_SERVICES_SIZE; index++)
        {
            service_connections_[index].GetConnections([&](ServiceConnections::Bucket& bucket, uint32_t conn_idx) {
                Connection& connection = bucket.connections[conn_idx];
                if (connection.local != 0 && !bucket.IsExpired(conn_idx, current_time))
                {
                    uint32_t local_addr;
                    uint16_t local_port;
                    ServiceConnections::Unpack(connection.local, local_addr, local_port);
                    response.emplace_back(index, bucket.addresses[conn_idx], bucket.ports[conn_idx], local_addr, local_port);
                }
            });
        }
    }
    else if (*service_id < YANET_CONFIG_PROXY_SERVICES_SIZE)
    {
        service_connections_[*service_id].GetConnections([&](ServiceConnections::Bucket& bucket, uint32_t conn_idx) {
            Connection& connection = bucket.connections[conn_idx];
            if (connection.local != 0 && !bucket.IsExpired(conn_idx, current_time))
            {
                uint32_t local_addr;
                uint16_t local_port;
                ServiceConnections::Unpack(connection.local, local_addr, local_port);
                response.emplace_back(*service_id, bucket.addresses[conn_idx], bucket.ports[conn_idx], local_addr, local_port);
            }
        });
    }

    return response;
}

common::idp::proxy_syn::response TcpConnectionStore::GetSyn(std::optional<proxy_service_id_t> service_id)
{
    common::idp::proxy_syn::response response;
    uint32_t current_time = currentTime;
    std::lock_guard guard(mutex_);
    
    if (!service_id.has_value())
    {
        for (uint32_t index = 0; index < YANET_CONFIG_PROXY_SERVICES_SIZE; index++)
        {
            syn_connections_[index].GetConnections([&](ServiceSynConnections::Bucket& bucket, uint32_t conn_idx) {
                if (!bucket.IsExpired(conn_idx, current_time, TIMEOUT_SYN))
                {
                    response.emplace_back(index, bucket.addresses[conn_idx], bucket.ports[conn_idx]);
                }
            });
        }
    }
    else if (*service_id < YANET_CONFIG_PROXY_SERVICES_SIZE)
    {
        syn_connections_[*service_id].GetConnections([&](ServiceSynConnections::Bucket& bucket, uint32_t conn_idx) {
            if (!bucket.IsExpired(conn_idx, current_time, TIMEOUT_SYN))
            {
                response.emplace_back(*service_id, bucket.addresses[conn_idx], bucket.ports[conn_idx]);
            }
        });
    }

    return response;
}

common::idp::proxy_local_pool::response TcpConnectionStore::GetLocalPool(std::optional<proxy_service_id_t> service_id)
{
    common::idp::proxy_local_pool::response response;
    std::lock_guard guard(mutex_);

    if (!service_id.has_value())
    {
        for (uint32_t index = 0; index < YANET_CONFIG_PROXY_SERVICES_SIZE; index++)
        {
            local_pools_[index].GetLocalPool(index, response);
        }
    }
    else if (*service_id < YANET_CONFIG_PROXY_SERVICES_SIZE)
    {
        local_pools_[*service_id].GetLocalPool(*service_id, response);
    }

    return response;
}


void DebugPacket(const char* message, const rte_ipv4_hdr* ipv4_header, const rte_tcp_hdr* tcp_header)
{
    YANET_LOG_WARNING("%s %s:%d -> %s:%d, seq=%u, ack=%u\n", message,
        common::ipv4_address_t(rte_cpu_to_be_32(ipv4_header->src_addr)).toString().c_str(), rte_cpu_to_be_16(tcp_header->src_port),
        common::ipv4_address_t(rte_cpu_to_be_32(ipv4_header->dst_addr)).toString().c_str(), rte_cpu_to_be_16(tcp_header->dst_port),
        rte_cpu_to_be_32(tcp_header->sent_seq), rte_cpu_to_be_32(tcp_header->recv_ack));
}

uint32_t BuildResult(uint32_t flags, ::proxy::service_counter counter)
{
    return flags | uint32_t(counter);
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

void DecreaseMssInTcpOptions(rte_tcp_hdr* tcp_header, rte_mbuf* mbuf)
{
	size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
	TcpOptions tcp_options;
	memset(&tcp_options, 0, sizeof(tcp_options));
	tcp_options.Read((uint8_t*)tcp_header + sizeof(rte_tcp_hdr), tcp_header_len);
	tcp_options.mss -= int(sizeof(proxy_v2_ipv4_hdr));
	tcp_options.Write(mbuf);
}

void ClearTcpOptionsOnlyTimestamps(rte_tcp_hdr* tcp_header, rte_mbuf* mbuf, uint32_t timestamp_shift)
{
    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
    TcpOptions tcp_options;
    memset(&tcp_options, 0, sizeof(tcp_options));
    tcp_options.Read((uint8_t*)tcp_header + sizeof(rte_tcp_hdr), tcp_header_len);
    tcp_options.sack_permitted = false;
    tcp_options.mss = 0;
    tcp_options.window_scaling = 0;
    tcp_options.Write(mbuf);
    ShiftTcpOptions(tcp_header, 0, timestamp_shift, 0);
}

std::pair<uint32_t, uint8_t> ClearTcpOptionsSetTimestamps(rte_tcp_hdr* tcp_header, rte_mbuf* mbuf, uint32_t timestamp_value)
{
    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
    TcpOptions tcp_options;
    memset(&tcp_options, 0, sizeof(tcp_options));
    tcp_options.Read((uint8_t*)tcp_header + sizeof(rte_tcp_hdr), tcp_header_len);
    uint32_t old_value = tcp_options.timestamp_value;
    uint8_t old_window_scaling = tcp_options.window_scaling;
    tcp_options.sack_permitted = false;
    tcp_options.mss = 0;
    tcp_options.window_scaling = 0;
    tcp_options.timestamp_value = timestamp_value;
    tcp_options.Write(mbuf);
    return {old_value, old_window_scaling};
}

bool NonEmptyTcpData(rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
    return (rte_be_to_cpu_16(ipv4_header->total_length) != sizeof(rte_ipv4_hdr) + tcp_header_len);
}

uint32_t TcpConnectionStore::BuildSynCookieAndFillTcpOptionsAnswer(const dataplane::globalBase::proxy_service_t& service, rte_mbuf* mbuf, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
    TcpOptions tcp_options;
    memset(&tcp_options, 0, sizeof(tcp_options));
    tcp_options.Read((uint8_t*)tcp_header + sizeof(rte_tcp_hdr), tcp_header_len);
    tcp_options.sack_permitted &= service.use_sack;
    tcp_options.mss = std::min(tcp_options.mss, (uint16_t)service.mss);

    uint32_t cookie_data = SynCookies::PackData({SynCookies::MssToTable(tcp_options.mss), tcp_options.sack_permitted, tcp_options.window_scaling, 0}); // ecn
    uint32_t cookie = syn_cookies_.GetCookie(ipv4_header->src_addr, service.upstream_addr, tcp_header->src_port, service.upstream_port, tcp_header->sent_seq, cookie_data);
    // YANET_LOG_WARNING("\tcookie_data=%d, cookie=%u, seq=%u\n", cookie_data, cookie, tcp_header->sent_seq);

    tcp_options.window_scaling = service.winscale;
    tcp_options.timestamp_echo = tcp_options.timestamp_value;
    tcp_options.timestamp_value = 1;
    if (service.proxy_header)
    {
        tcp_options.mss -= int(sizeof(proxy_v2_ipv4_hdr));
    }
    tcp_options.Write(mbuf);

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

void ActionClientOnSynPrepareSynToService(const dataplane::globalBase::proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header, uint64_t local)
{
    LocalPool::UnpackTupleSrc(local, ipv4_header, tcp_header);
    if (service.proxy_header)
    {
        // При использовании ProxyHeader уменьшаем значение SEQ полученное от клиента
        tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, sizeof(proxy_v2_ipv4_hdr));
    }

    ipv4_header->dst_addr = service.upstream_addr;
    tcp_header->dst_port = service.upstream_port;
}

// Action from worker
uint32_t TcpConnectionStore::ActionClientOnSyn(proxy_service_id_t service_id,
                                               uint32_t worker_id,
                                               const dataplane::globalBase::proxy_service_t& service,
                                               uint32_t current_time,
                                               rte_mbuf* mbuf)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_client_syn", ipv4_header, tcp_header);
    uint32_t action = 0;

    ServiceConnectionData service_connection_data;
    switch (service_connections_[service_id].FindAndLock(ipv4_header->src_addr, tcp_header->src_port, current_time, service_connection_data))
    {
        case TableSearchResult::Overflow:
        {
            action = BuildResult(flag_action_drop, ::proxy::service_counter::service_bucket_overflow);
            break;
        }
        case TableSearchResult::Found:
        {
            if (!service_connection_data.connection->CreatedFromSynCookie())
            {
                // todo
                action = flag_action_drop;
            }
            else
            {
                // todo
                action = flag_action_drop;
            }
            break;
        }
        case TableSearchResult::NotFound:
        {
            SynConnectionData syn_connection_data;
            switch (syn_connections_[service_id].FindAndLock(ipv4_header->src_addr, tcp_header->src_port, current_time, syn_connection_data))
            {
                case TableSearchResult::Overflow:
                {
                    uint32_t cookie = BuildSynCookieAndFillTcpOptionsAnswer(service, mbuf, ipv4_header, tcp_header);
                    ActionClientOnSynPrepareSynToClient(ipv4_header, tcp_header, cookie);
                    action = flag_action_to_client;
                    break;
                }
                case TableSearchResult::Found:
                {
                    ActionClientOnSynPrepareSynToService(service, ipv4_header, tcp_header, syn_connection_data.connection->local);
                    action = flag_action_to_service;
                    break;
                }
                case TableSearchResult::NotFound:
                {
                    uint64_t local = local_pools_[service_id].Allocate(worker_id, ipv4_header->src_addr, tcp_header->src_port);
                    if (local == 0)
                    {
                        action = BuildResult(flag_action_drop, ::proxy::service_counter::failed_local_pool_allocation);
                    }
                    else
                    {
                        syn_connection_data.Init(ipv4_header->src_addr, tcp_header->src_port, current_time);
                        syn_connection_data.connection->local = local;
                        syn_connection_data.connection->recv_seq = tcp_header->sent_seq;

                        ActionClientOnSynPrepareSynToService(service, ipv4_header, tcp_header, local);
                        action = flag_action_to_service;
                    }
                    break;
                }
            }
            syn_connection_data.Unlock();
            break;
        }
    }
    service_connection_data.Unlock();

    if ((action & flag_action_drop) == 0)
    {
        UpdateCheckSums(ipv4_header, tcp_header);
    }

    return action;
}

void ActionClientOnAckForward(const dataplane::globalBase::proxy_service_t& service, rte_mbuf* mbuf, dataplane::metadata* metadata,
    rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header, uint32_t shift_seq, uint32_t shift_ack,
    uint32_t shift_timestamp, bool add_proxy_header, uint32_t src_addr, uint16_t src_port)
{
    ShiftTcpOptions(tcp_header, shift_ack, 0, shift_timestamp);
    tcp_header->sent_seq = add_cpu_32(tcp_header->sent_seq, shift_seq);
    tcp_header->recv_ack = add_cpu_32(tcp_header->recv_ack, shift_ack);

    if (add_proxy_header)
    {
        size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
        constexpr uint16_t size_proxy_header = sizeof(proxy_v2_ipv4_hdr);
        proxy_v2_ipv4_hdr* proxy_header = 
            rte_pktmbuf_mtod_offset(mbuf, proxy_v2_ipv4_hdr*, metadata->transport_headerOffset + tcp_header_len);
        uint16_t size_data = rte_be_to_cpu_16(ipv4_header->total_length) - rte_ipv4_hdr_len(ipv4_header) - tcp_header_len;
        if (size_data != 0)
        {
            memmove((uint8_t*)proxy_header + size_proxy_header, proxy_header, size_data); // using intermediate buffer impacts performance
        }
        
        uint16_t ipv4_total_length = rte_ipv4_hdr_len(ipv4_header) + tcp_header_len + size_proxy_header + size_data;
        ipv4_header->total_length = rte_cpu_to_be_16(ipv4_total_length);

        mbuf->data_len = sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr) + ipv4_total_length;
        mbuf->pkt_len = mbuf->data_len;

        FillProxyHeader(proxy_header, src_addr, src_port, service.proxy_addr, service.proxy_port);
    }
}

uint32_t TcpConnectionStore::CheckSynCookie(const dataplane::globalBase::proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    uint32_t cookie_data = syn_cookies_.CheckCookie(rte_cpu_to_be_32(tcp_header->recv_ack) - 1, ipv4_header->src_addr, service.upstream_addr, tcp_header->src_port, service.upstream_port, sub_cpu_32(tcp_header->sent_seq, 1));
    // YANET_LOG_WARNING("\tcookie_data=%d, ack=%u, seq=%u\n", cookie_data, tcp_header->recv_ack, tcp_header->sent_seq);

    if (cookie_data == 0 && !service.ignore_size_update_detections)
    {
        cookie_data = syn_cookies_.CheckCookie(rte_cpu_to_be_32(tcp_header->recv_ack) - 1, ipv4_header->src_addr, service.upstream_addr, tcp_header->src_port, service.upstream_port, tcp_header->sent_seq);
        // YANET_LOG_WARNING("\tsecond cookie_data=%d, ack=%u, seq=%u\n", cookie_data, tcp_header->recv_ack, tcp_header->sent_seq);
        if (cookie_data != 0)
        {
            tcp_header->sent_seq = add_cpu_32(tcp_header->sent_seq, 1);
        }
    }
    return cookie_data;
}

uint32_t TcpConnectionStore::ActionClientOnAck(proxy_service_id_t service_id,
                                               uint32_t worker_id,
                                               const dataplane::globalBase::proxy_service_t& service,
                                               uint32_t current_time,
                                               rte_mbuf* mbuf)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_client_ack", ipv4_header, tcp_header);
    uint32_t action = 0;

    ServiceConnectionData service_connection_data;
    switch (service_connections_[service_id].FindAndLock(ipv4_header->src_addr, tcp_header->src_port, current_time, service_connection_data))
    {
        case TableSearchResult::Overflow:
        {
            action = BuildResult(flag_action_drop, ::proxy::service_counter::service_bucket_overflow);
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
                if (service.ignore_size_update_detections)
                {
                    action = BuildResult(flag_action_drop, ::proxy::service_counter::ignored_size_update_detections);
                }
                else
                {
                    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
                    TcpOptions tcp_options;
                    memset(&tcp_options, 0, sizeof(tcp_options));
                    tcp_options.Read((uint8_t*)tcp_header + sizeof(rte_tcp_hdr), tcp_header_len);

                    LocalPool::UnpackTupleSrc(service_connection_data.connection->local, ipv4_header, tcp_header);
                    tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, (service.proxy_header ? sizeof(proxy_v2_ipv4_hdr) : 0));

                    // todo - need save options in ServiceConnections !!!
                    tcp_options.mss = 1300;
                    tcp_options.sack_permitted = true;
                    tcp_options.window_scaling = 5;
                    tcp_options.timestamp_echo = 0;

                    tcp_options.Write(mbuf);
                    ipv4_header->time_to_live = 64;
                    tcp_header->recv_ack = 0;
                    tcp_header->tcp_flags = TCP_SYN_FLAG;

                    action = flag_action_to_service;
		        }
            }
            else
            {
                uint32_t src_addr = ipv4_header->src_addr;
                uint16_t src_port = tcp_header->src_port;
                LocalPool::UnpackTupleSrc(service_connection_data.connection->local, ipv4_header, tcp_header);

                uint32_t shift_seq = 0;
                uint32_t shift_ack = -service_connection_data.connection->shift_server;
                uint32_t shift_timestamp = -service_connection_data.connection->timestamp_shift;
                bool add_proxy_header = false;

                bool is_first_ack = (tcp_header->sent_seq == add_cpu_32(service_connection_data.connection->client_start_seq, 1)); // todo - check time
                if (is_first_ack)
                {
                    add_proxy_header = service.proxy_header;
                    if (add_proxy_header)
                    {
                        shift_seq = -int(sizeof(proxy_v2_ipv4_hdr));
                    }
                }
                ActionClientOnAckForward(service, mbuf, metadata, ipv4_header, tcp_header, shift_seq, shift_ack, shift_timestamp, add_proxy_header, src_addr, src_port);

                action = flag_action_to_service;
            }

            break;
        }
        case TableSearchResult::NotFound:
        {
            uint32_t flags = (NonEmptyTcpData(ipv4_header, tcp_header) ? Connection::flag_nonempty_ack_from_client : 0);

            SynConnectionData syn_connection_data;
            if (syn_connections_[service_id].FindAndLock(ipv4_header->src_addr, tcp_header->src_port, current_time, syn_connection_data) == TableSearchResult::Found)
            {
                uint32_t src_addr = ipv4_header->src_addr;
                uint16_t src_port = tcp_header->src_port;
                service_connection_data.Init(ipv4_header->src_addr, tcp_header->src_port, current_time);
                LocalPool::UnpackTupleSrc(syn_connection_data.connection->local, ipv4_header, tcp_header);
                service_connection_data.connection->client_start_seq = syn_connection_data.connection->recv_seq;
                syn_connection_data.bucket->Clear(syn_connection_data.idx);
                syn_connection_data.Unlock();

                service_connection_data.connection->local = ServiceSynConnections::Pack(ipv4_header->src_addr, tcp_header->src_port);
                service_connection_data.connection->flags = flags;

                bool add_proxy_header = service.proxy_header;
                uint32_t shift_seq = (add_proxy_header ? -int(sizeof(proxy_v2_ipv4_hdr)) : 0);
                ActionClientOnAckForward(service, mbuf, metadata, ipv4_header, tcp_header, shift_seq, 0, 0, add_proxy_header, src_addr, src_port);

                action = flag_action_to_service;
            }
            else
            {
                syn_connection_data.Unlock();

                // try check cookie
                uint32_t cookie_data = CheckSynCookie(service, ipv4_header, tcp_header);
                if (cookie_data == 0)
                {
                    action = BuildResult(flag_action_drop, ::proxy::service_counter::failed_check_syn_cookie);
                }
                else
                {
                    // get from local
                    uint64_t local = local_pools_[service_id].Allocate(worker_id, ipv4_header->src_addr, tcp_header->src_port);
                    if (local == 0)
                    {
                        action = BuildResult(flag_action_drop, ::proxy::service_counter::failed_local_pool_allocation);
                    }
                    else
                    {
                        size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
                        TcpOptions tcp_options;
                        memset(&tcp_options, 0, sizeof(tcp_options));
                        tcp_options.Read((uint8_t*)tcp_header + sizeof(rte_tcp_hdr), tcp_header_len);

                        SynCookies::TCPOptions options = SynCookies::UnpackData(cookie_data);
                        // YANET_LOG_WARNING("\tmss=%d, sack=%d, wscale=%d\n", SynCookies::MssFromTable(options.mss), options.sack, options.wscale);

                        // // Add to connections
                        service_connection_data.Init(ipv4_header->src_addr, tcp_header->src_port, current_time);
                        LocalPool::UnpackTupleSrc(local, ipv4_header, tcp_header);
                        service_connection_data.connection->local = ServiceSynConnections::Pack(ipv4_header->src_addr, tcp_header->src_port);
                        service_connection_data.connection->sent_seq = rte_cpu_to_be_32(tcp_header->recv_ack) - 1;
                        service_connection_data.connection->client_start_seq = sub_cpu_32(tcp_header->sent_seq, 1);
                        service_connection_data.connection->timestamp_echo = tcp_options.timestamp_echo;
                        service_connection_data.connection->flags = Connection::flag_from_synkookie | flags;
                        service_connection_data.connection->client_timestamp_start = tcp_options.timestamp_value;
                        service_connection_data.connection->cookie_data = cookie_data;

                        tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, 1 + (service.proxy_header ? sizeof(proxy_v2_ipv4_hdr) : 0));

                        tcp_options.mss = SynCookies::MssFromTable(options.mss);
                        tcp_options.sack_permitted = options.sack;
                        tcp_options.window_scaling = options.wscale;
                        tcp_options.timestamp_echo = 0;

                        tcp_options.Write(mbuf);
                        ipv4_header->time_to_live = 64;
                        tcp_header->recv_ack = 0;
                        tcp_header->tcp_flags = TCP_SYN_FLAG;
                    }
                }
            }
                        
            break;
        }
    }

    service_connection_data.Unlock();

    if ((action & flag_action_drop) == 0)
    {
        ipv4_header->dst_addr = service.upstream_addr;
        tcp_header->dst_port = service.upstream_port;
        UpdateCheckSums(ipv4_header, tcp_header);
    }

    return action;
}

uint32_t TcpConnectionStore::ActionServerOnSynAck(proxy_service_id_t service_id,
                                                  const dataplane::globalBase::proxy_service_t& service,
                                                  uint32_t current_time,
                                                  rte_mbuf* mbuf)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_server_syn_ack", ipv4_header, tcp_header);

    uint64_t client_info = local_pools_[service_id].FindClientByLocal(ipv4_header->dst_addr, tcp_header->dst_port);
    if (client_info == 0)
    {
        return BuildResult(flag_action_drop, ::proxy::service_counter::failed_local_pool_search);   // для этого заведем отдельный счетчик
    }
    uint32_t client_addr;
    tPortId client_port;
    LocalPool::UnpackTuple(client_info, client_addr, client_port);

    SynConnectionData syn_connection_data;
    if (syn_connections_[service_id].FindAndLock(client_addr, client_port, current_time, syn_connection_data) == TableSearchResult::Found)
    {
        syn_connection_data.connection->server_answer = true;
        syn_connection_data.Unlock();

        if (service.proxy_header)
        {
            tcp_header->recv_ack = add_cpu_32(tcp_header->recv_ack, sizeof(proxy_v2_ipv4_hdr));
            DecreaseMssInTcpOptions(tcp_header, mbuf);
        }

        ipv4_header->src_addr = service.proxy_addr;
        ipv4_header->dst_addr = client_addr;
        tcp_header->src_port = service.proxy_port;
        tcp_header->dst_port = client_port;
        UpdateCheckSums(ipv4_header, tcp_header);

        return flag_action_to_client;
    }
    syn_connection_data.Unlock();

    ServiceConnectionData service_connection_data;
    if (service_connections_[service_id].FindAndLock(client_addr, client_port, current_time, service_connection_data) != TableSearchResult::Found)
    {
        service_connection_data.Unlock();
        return BuildResult(flag_action_drop, ::proxy::service_counter::failed_answer_service_syn_ack);
    }

    service_connection_data.connection->flags |= Connection::flag_answer_from_server;
    if (!service_connection_data.connection->CreatedFromSynCookie())
    {
        // todo
    }
    else
    {
        // timestamps shift
        auto [old_timestamp_value, window_scaling] = ClearTcpOptionsSetTimestamps(tcp_header, mbuf, service_connection_data.connection->timestamp_echo);        
        service_connection_data.connection->timestamp_shift = service_connection_data.connection->timestamp_echo - old_timestamp_value;
        
        service_connection_data.connection->window_size_shift = (int)window_scaling - (int)service.winscale;
        tcp_header->rx_win = shift_cpu_16(tcp_header->rx_win, service_connection_data.connection->window_size_shift);

        service_connection_data.connection->shift_server = service_connection_data.connection->sent_seq - rte_be_to_cpu_32(tcp_header->sent_seq);
        tcp_header->sent_seq = rte_cpu_to_be_32(service_connection_data.connection->sent_seq + 1);

        tcp_header->tcp_flags = TCP_ACK_FLAG;

        if (service.proxy_header)
        {
            tcp_header->recv_ack = add_cpu_32(tcp_header->recv_ack, sizeof(proxy_v2_ipv4_hdr));
        }
    }

    service_connection_data.Unlock();

    ipv4_header->src_addr = service.proxy_addr;
    ipv4_header->dst_addr = client_addr;
    tcp_header->src_port = service.proxy_port;
    tcp_header->dst_port = client_port;
    
    UpdateCheckSums(ipv4_header, tcp_header);

    return flag_action_to_client;
}

uint32_t TcpConnectionStore::ActionServerOnAck(proxy_service_id_t service_id,
                                               const dataplane::globalBase::proxy_service_t& service,
                                               uint32_t current_time,
                                               rte_mbuf* mbuf)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    DebugPacket("proxy_server_ack", ipv4_header, tcp_header);

    uint64_t client_info = local_pools_[service_id].FindClientByLocal(ipv4_header->dst_addr, tcp_header->dst_port);
    if (client_info == 0)
    {
        return BuildResult(flag_action_drop, ::proxy::service_counter::failed_local_pool_search);
    }
    uint32_t client_addr;
    tPortId client_port;
    LocalPool::UnpackTuple(client_info, client_addr, client_port);

    ServiceConnectionData service_connection_data;
    if (service_connections_[service_id].FindAndLock(client_addr, client_port, current_time, service_connection_data) != TableSearchResult::Found)
    {
        service_connection_data.Unlock();
        return BuildResult(flag_action_drop, ::proxy::service_counter::failed_answer_service_syn_ack);
    }

    if (service_connection_data.connection->CreatedFromSynCookie())
    {
        tcp_header->sent_seq = add_cpu_32(tcp_header->sent_seq, service_connection_data.connection->shift_server);
        ShiftTcpOptions(tcp_header, 0, service_connection_data.connection->timestamp_shift, 0);
        tcp_header->rx_win = shift_cpu_16(tcp_header->rx_win, service_connection_data.connection->window_size_shift);
    }
    service_connection_data.Unlock();

    ipv4_header->dst_addr = client_addr;
    ipv4_header->src_addr = service.proxy_addr;
    tcp_header->dst_port = client_port;
    tcp_header->src_port = service.proxy_port;

    UpdateCheckSums(ipv4_header, tcp_header);

    return flag_action_to_client;
}

void TcpConnectionStore::GetDataForRetramsits(uint32_t before_time, rte_ring* ring_retransmit_free, rte_ring* ring_retransmit_send)
{
    // YANET_LOG_WARNING("TcpConnectionStore::GetDataForRetramsits\n");
    uint32_t count = 0;
    for (uint32_t index_service = 0; (index_service < YANET_CONFIG_PROXY_SERVICES_SIZE) && (rte_ring_empty(ring_retransmit_free) == 0) && count < MAX_COUNT_RETRANSMITS_ALL_SERVICES; index_service++)
    {
        count += service_connections_[index_start_check_retransmits_].GetDataForRetramsits([&](ServiceConnections::Bucket& bucket, uint32_t conn_idx, uint64_t service_key) -> bool {
            Connection& connection = bucket.connections[conn_idx];
            if ((ServiceConnections::Pack(bucket.addresses[conn_idx], bucket.ports[conn_idx]) != 0) && (bucket.last_times[conn_idx] != 0) && (bucket.last_times[conn_idx] <= before_time) && 
                ((connection.flags & Connection::flag_from_synkookie) != 0) && ((connection.flags & Connection::flag_sent_rentransmit_syn_to_server) == 0) &&
                ((connection.flags & Connection::flag_nonempty_ack_from_client) == 0)) {
                DataForRetransmit* data;
                if (rte_ring_dequeue(ring_retransmit_free, (void**)&data) != 0)
                {
                    return true;
                }

                SynCookies::TCPOptions options = SynCookies::UnpackData(connection.cookie_data);
                TcpOptions tcp_options;
                tcp_options.timestamp_value = connection.client_timestamp_start;
                tcp_options.timestamp_echo = 0;
                tcp_options.mss = SynCookies::MssFromTable(options.mss);
                tcp_options.sack_permitted = options.sack;
                tcp_options.window_scaling = options.wscale;

                data->tcp_options_len = tcp_options.WriteBuffer(data->tcp_options_data);

                YANET_LOG_WARNING("Add to retransmit, cookie_data=%d, tcp_options=%s, flags=%u\n", connection.cookie_data, tcp_options.DebugInfo().c_str(), connection.flags);

                data->service_id = service_key;
                ServiceConnections::Unpack(connection.local, data->src, data->sport);
                ServiceConnections::Unpack(service_key, data->dst, data->dport);
                data->client_start_seq = connection.client_start_seq;
                data->flow = next_flow_;

                if (rte_ring_enqueue(ring_retransmit_send, (void*)data) != 0)
                {
                    return true;
                }

                connection.flags |= Connection::flag_sent_rentransmit_syn_to_server;

                count++;
                if (count >= MAX_COUNT_RETRANSMITS_PER_SERVICE) {
                    return true;
                }
            }
            return false;
        });

        index_start_check_retransmits_++;
        if (index_start_check_retransmits_ > YANET_CONFIG_PROXY_SERVICES_SIZE)
        {
            index_start_check_retransmits_ = 0;
        }
    }
}

}
