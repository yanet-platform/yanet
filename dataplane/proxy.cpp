#include "proxy.h"

#include <sstream>
#include "metadata.h"
#include "common.h"

namespace dataplane::proxy
{

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
            *((uint32_t*)(options + index + 2)) = dataplane::proxy::add_cpu_32(*((uint32_t*)(options + index + 2)), sack);
            *((uint32_t*)(options + index + 6)) = dataplane::proxy::add_cpu_32(*((uint32_t*)(options + index + 6)), sack);
            index += 10;
            break;
        case TCPOPT_TIMESTAMP:
            *((uint32_t*)(options + index + 2)) = dataplane::proxy::add_cpu_32(*((uint32_t*)(options + index + 2)), timestamp_value);
            *((uint32_t*)(options + index + 6)) = dataplane::proxy::add_cpu_32(*((uint32_t*)(options + index + 6)), timestamp_echo);
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
    rte_memcpy(proxy_header->signature, dataplane::proxy::PROXY_V2_SIGNATURE, 12);
    proxy_header->version_cmd = (dataplane::proxy::PROXY_VERSION_V2 << 4) + dataplane::proxy::PROXY_CMD_LOCAL;
    proxy_header->af_proto = (dataplane::proxy::PROXY_AF_INET << 4) + dataplane::proxy::PROXY_PROTO_STREAM;
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

void TcpConnectionStore::proxy_add_local_pool(proxy_service_id_t service_id, const common::ip_prefix_t& prefix)
{
    YANET_LOG_WARNING("proxy_add_local_pool service_id=%d, prefix=%s\n", service_id, prefix.toString().c_str());
    ipv4_prefix_t prefix_pool;
    prefix_pool.address = ipv4_address_t::convert(prefix.get_ipv4().address());
    prefix_pool.address.address = rte_cpu_to_be_32(prefix_pool.address.address);
    prefix_pool.mask = prefix.mask();
    local_pools_[service_id].Add(prefix_pool);
}

eResult TcpConnectionStore::proxy_service_update(proxy_service_id_t service_id, const dataplane::globalBase::proxy_service_t& service, dataplane::memory_manager* memory_manager)
{
    YANET_LOG_WARNING("proxy_service_update: service_id=%d, proxy=%s:%d, upstream=%s:%d, proxy_header=%d, size_connections_table=%d, size_syn_table=%d\n",
        service_id, common::ipv4_address_t(rte_cpu_to_be_32(service.proxy_addr.address)).toString().c_str(), service.proxy_port,
        common::ipv4_address_t(rte_cpu_to_be_32(service.upstream_addr.address)).toString().c_str(), service.upstream_port, service.proxy_header, service.size_connections_table, service.size_syn_table);

    std::lock_guard guard(mutex_);

    if (!service_connections_[service_id].Initialize(service_id, service.size_connections_table, memory_manager, service.upstream_addr.address, service.upstream_port))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.ServiceConnections, service: %d\n", service_id);
        return eResult::errorAllocatingMemory;
    }

    if (!syn_connections_[service_id].Initialize(service_id, service.size_syn_table, memory_manager, service.upstream_addr.address, service.upstream_port))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.SynConnections, service: %d\n", service_id);
        return eResult::errorAllocatingMemory;
    }

    if (!local_pools_[service_id].Init(service_id, memory_manager))
    {
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
                    response.emplace_back(index, bucket.addresses[conn_idx], bucket.ports[conn_idx], local_addr, local_port, static_cast<uint16_t>(connection.state));
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
                response.emplace_back(*service_id, bucket.addresses[conn_idx], bucket.ports[conn_idx], local_addr, local_port, static_cast<uint16_t>(connection.state));
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
                SynConnection& connection = bucket.connections[conn_idx];
                if (!bucket.IsExpired(conn_idx, current_time, TIMEOUT_SYN))
                {
                    uint32_t src_addr;
                    uint16_t src_port;
                    ServiceSynConnections::Unpack(connection.client, src_addr, src_port);
                    response.emplace_back(index, src_addr, src_port);
                }
            });
        }
    }
    else if (*service_id < YANET_CONFIG_PROXY_SERVICES_SIZE)
    {
        syn_connections_[*service_id].GetConnections([&](ServiceSynConnections::Bucket& bucket, uint32_t conn_idx) {
            SynConnection& connection = bucket.connections[conn_idx];
            if (!bucket.IsExpired(conn_idx, current_time, TIMEOUT_SYN))
            {
                uint32_t src_addr;
                uint16_t src_port;
                ServiceSynConnections::Unpack(connection.client, src_addr, src_port);
                response.emplace_back(*service_id, src_addr, src_port);
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

// Action from worker
ActionClientOnSyn_Result TcpConnectionStore::ActionClientOnSyn(proxy_service_id_t service_id,
                                                               uint32_t worker_id,
                                                               const dataplane::globalBase::proxy_service_t& service,
                                                               uint32_t current_time,
                                                               uint32_t src_addr,
                                                               uint16_t src_port,
                                                               uint32_t seq,
                                                               const TcpOptions& tcp_options)
{
    ActionClientOnSyn_Result action;
    ConnectionData<SynConnection> data;
    auto result = syn_connections_[service_id].FindAndLock(src_addr, src_port, current_time, data);
    switch(result)
    {
    case TableSearchResult::Overflow:
    {
        uint32_t cookie_data = SynCookies::PackData({SynCookies::MssToTable(tcp_options.mss), tcp_options.sack_permitted, tcp_options.window_scaling, 0}); // ecn
        uint32_t cookie = syn_cookies_.GetCookie(src_addr, service.upstream_addr.address, src_port, service.upstream_port, seq, cookie_data); // dst_addr, dst_port
        YANET_LOG_WARNING("\tcookie_data=%d, cookie=%u, seq=%u\n", cookie_data, cookie, seq);
        action = ActionClientOnSyn_SynAckToClient{rte_cpu_to_be_32(cookie), add_cpu_32(seq, 1)};
    }
    break;
    case TableSearchResult::Found:
    {
        YANET_LOG_WARNING("\tSyn Exists\n");
        if (service.proxy_header)
        {
            seq = add_cpu_32(seq, -int(sizeof(proxy_v2_ipv4_hdr)));
        }
        uint32_t local_addr;
        uint16_t local_port;
        ServiceSynConnections::Unpack(data.connection->local, local_addr, local_port);
        action = ActionClientOnSyn_SynToServer{seq, local_addr, local_port};
    }
    break;
    case TableSearchResult::NotFound:
    {
        uint64_t local = local_pools_[service_id].Allocate(worker_id, src_addr, src_port);
        if (local != 0)
        {
            YANET_LOG_WARNING("\tSyn New Record\n");
            uint32_t local_addr;
            tPortId local_port;
            LocalPool::UnpackTuple(local, local_addr, local_port);
            data.Init(src_addr, src_port, current_time);
            data.connection->local = ServiceSynConnections::Pack(local_addr, local_port);
            data.connection->recv_seq = seq;
            if (service.proxy_header)
            {
                seq = add_cpu_32(seq, -int(sizeof(proxy_v2_ipv4_hdr)));
            }
            action = ActionClientOnSyn_SynToServer{seq, local_addr, local_port};
        }
    }
    break;
    }

    if (data.connection) data.Unlock();
    return action;
}

ActionClientOnAck_Result TcpConnectionStore::ActionClientOnAck(proxy_service_id_t service_id,
                                                               uint32_t worker_id,
                                                               const dataplane::globalBase::proxy_service_t& service,
                                                               uint32_t current_time,
                                                               uint32_t src_addr,
                                                               uint16_t src_port,
                                                               uint32_t seq,
                                                               uint32_t ack,
                                                               uint32_t timestamp_echo,
                                                               bool empty_tcp_data,
                                                               uint32_t client_timestamp_start)
{
    ConnectionData<Connection> data;
    auto result = service_connections_[service_id].FindAndLock(src_addr, src_port, current_time, data);
    if (result == TableSearchResult::Overflow)
    {
        YANET_LOG_WARNING("connections overflow\n");
        return ActionDrop{0};
    }

    if(result == TableSearchResult::Found)
    {
        // check non-empty tcp-data packet
        if (!empty_tcp_data)
        {
            data.connection->flags |= Connection::flag_nonempty_ack_from_client;
        }

        // YANET_LOG_WARNING("\t\tTcpConnectionStore::ActionClientOnAck: seq=%u, ack=%u, client_start_seq=%u, empty_tcp_data=%d, flags=%d\n",
        //                 seq, ack, conn_ptr->connection->client_start_seq, empty_tcp_data, conn_ptr->connection->flags);
        if (seq == data.connection->client_start_seq)
        {
            // YANET_LOG_WARNING("\t !!!! Need send SYN\n");

            bool ignore_size_update_detections = false;
            if (ignore_size_update_detections)
            {
                YANET_LOG_WARNING("unimplemented\n");
                data.Unlock();
                return ActionDrop{0};
            }
            else
            {
                ActionClientOnAck_NewServerConnection new_server_connection;
                ServiceConnections::Unpack(data.connection->local, new_server_connection.local_addr, new_server_connection.local_port);
                new_server_connection.seq = add_cpu_32(seq, (service.proxy_header ? -int(sizeof(proxy_v2_ipv4_hdr)) : 0));
    
                TcpOptions tcp_options{};
                // todo - need save options in ServiceConnections !!!
                tcp_options.mss = 1300;
                tcp_options.sack_permitted = true;
                tcp_options.window_scaling = 5;
    
                new_server_connection.tcp_options = tcp_options;
    
                data.Unlock();
                return new_server_connection;
            }

        }
        bool is_first_ack = (seq == add_cpu_32(data.connection->client_start_seq, 1)); // todo - check time

        ActionClientOnAck_Forward action;
        ServiceConnections::Unpack(data.connection->local, action.local_addr, action.local_port);
        action.add_proxy_header = false;
        action.shift_ack = -data.connection->shift_server;
        action.shift_seq = 0;
        action.shift_timestamp = -data.connection->timestamp_shift;

        // if (conn_ptr->connection->state == ConnectionState::SENT_PROXY_HEADER)
        if (is_first_ack)
        {
            // YANET_LOG_WARNING("\t\t\tchange state from SENT_PROXY_HEADER -> ESTABLISHED\n");
            data.connection->state = Connection::State::ESTABLISHED;
            action.add_proxy_header = service.proxy_header;
            if (action.add_proxy_header)
            {
                action.shift_seq = -int(sizeof(proxy_v2_ipv4_hdr));
            }
        }

        data.Unlock();
        return action;
    }

    uint32_t flags = 0;
    if (!empty_tcp_data)
    {
        flags |= Connection::flag_nonempty_ack_from_client;
    }

    // new connection
    ConnectionData<SynConnection> syn_data;
    YANET_LOG_WARNING("Search in syns\n");
    auto syn_result = syn_connections_[service_id].FindAndLock(src_addr, src_port, current_time, syn_data);
    if (syn_result == TableSearchResult::Found)
    {
        uint32_t local_addr;
        uint16_t local_port;
        ServiceSynConnections::Unpack(syn_data.connection->local, local_addr, local_port);
        data.Init(src_addr, src_port, current_time);
        data.connection->local = ServiceSynConnections::Pack(local_addr, local_port);
        data.connection->state = Connection::State::ESTABLISHED;
        data.connection->sent_seq = 0;
        data.connection->client_start_seq = syn_data.connection->recv_seq;
        data.connection->timestamp_echo = 0;
        data.connection->flags = flags;
        data.connection->client_timestamp_start = 0;
        data.connection->cookie_data = 0;

        ActionClientOnAck_Forward action;
        action.local_addr = local_addr;
        action.local_port = local_port;
        action.add_proxy_header = service.proxy_header;
        action.shift_ack = 0;
        action.shift_seq = (action.add_proxy_header ? -int(sizeof(proxy_v2_ipv4_hdr)) : 0);
        syn_data.bucket->Clear(syn_data.idx);

        data.Unlock();
        syn_data.Unlock();
        return action;
    }

    // try check cookie
    uint32_t cookie_data = syn_cookies_.CheckCookie(rte_cpu_to_be_32(ack) - 1, src_addr, service.upstream_addr.address, src_port, service.upstream_port, add_cpu_32(seq, -1));
    YANET_LOG_WARNING("\tcookie_data=%d, ack=%u, seq=%u\n", cookie_data, ack, seq);

    if (cookie_data == 0)
    {
        cookie_data = syn_cookies_.CheckCookie(rte_cpu_to_be_32(ack) - 1, src_addr, service.upstream_addr.address, src_port, service.upstream_port, seq);
        YANET_LOG_WARNING("\tsecond cookie_data=%d, ack=%u, seq=%u\n", cookie_data, ack, seq);
        if (cookie_data == 0)
        {
            data.Unlock();
            if (syn_data.connection) syn_data.Unlock();
            YANET_LOG_WARNING("\tcookie check error\n");
            return ActionDrop{0};
        }
        seq = add_cpu_32(seq, 1);
    }

    SynCookies::TCPOptions options = SynCookies::UnpackData(cookie_data);
    YANET_LOG_WARNING("\tmss=%d, sack=%d, wscale=%d\n", SynCookies::MssFromTable(options.mss), options.sack, options.wscale);

    // get from local
    uint64_t local = local_pools_[service_id].Allocate(worker_id, src_addr, src_port);
    if (local == 0)
    {
        YANET_LOG_WARNING("\tcan't allocate in local pool\n");
        data.Unlock();
        if (syn_data.connection) syn_data.Unlock();
        return ActionDrop{1};
    }
    uint32_t local_addr;
    tPortId local_port;
    LocalPool::UnpackTuple(local, local_addr, local_port);

    // Add to connections
    data.Init(src_addr, src_port, current_time);
    data.connection->local = ServiceSynConnections::Pack(local_addr, local_port);
    data.connection->state = Connection::State::SENT_SYN_SERVER;
    data.connection->sent_seq = rte_cpu_to_be_32(ack) - 1;
    data.connection->client_start_seq = add_cpu_32(seq, -1);
    data.connection->timestamp_echo = timestamp_echo;
    data.connection->flags = Connection::flag_from_synkookie | flags;
    data.connection->client_timestamp_start = client_timestamp_start;
    data.connection->cookie_data = cookie_data;

    ActionClientOnAck_NewServerConnection new_server_connection;
    new_server_connection.local_addr = local_addr;
    new_server_connection.local_port = local_port;
    new_server_connection.seq = add_cpu_32(seq, -1 + (service.proxy_header ? -int(sizeof(proxy_v2_ipv4_hdr)) : 0));

    TcpOptions tcp_options{};
    tcp_options.mss = SynCookies::MssFromTable(options.mss);
    tcp_options.sack_permitted = options.sack;
    tcp_options.window_scaling = options.wscale;

    new_server_connection.tcp_options = tcp_options;

    data.Unlock();
    if (syn_data.connection) syn_data.Unlock();

    return new_server_connection;
}

ActionServerOnSynAck_Result TcpConnectionStore::ActionServerOnSynAck(proxy_service_id_t service_id,
                                                                     const dataplane::globalBase::proxy_service_t& service,
                                                                     uint32_t current_time,
                                                                     uint32_t dst_addr,
                                                                     uint16_t dst_port,
                                                                     uint32_t seq,
                                                                     uint32_t ack,
                                                                     const TcpOptions& tcp_options)
{
    // find in local pool
    uint64_t client_info = local_pools_[service_id].FindClientByLocal(dst_addr, dst_port);
    if (client_info == 0)
    {
        YANET_LOG_ERROR("Not found in local connections\n");
        return ActionDrop{0};
    }
    uint32_t client_addr;
    tPortId client_port;
    LocalPool::UnpackTuple(client_info, client_addr, client_port);

    // find in syn or conneсtions
    ConnectionData<SynConnection> syn_data;
    auto syn_result = syn_connections_[service_id].FindAndLock(client_addr, client_port, current_time, syn_data);
    if (syn_result == TableSearchResult::Found)
    {
        syn_data.connection->server_answer = true;
        syn_data.connection->last_time = current_time;
        if (service.proxy_header)
        {
            ack = add_cpu_32(ack, int(sizeof(proxy_v2_ipv4_hdr)));
        }
        if (syn_data.connection) syn_data.Unlock();
        return ActionServerOnSynAck_SynAckToClient{ack, client_addr, client_port};
    }

    // find in connections
    ConnectionData<Connection> data;
    auto result = service_connections_[service_id].FindAndLock(client_addr, client_port, current_time, data);
    if (result != TableSearchResult::Found)
    {
        YANET_LOG_WARNING("not found in connections\n");
        if (data.connection) data.Unlock();
        if (syn_data.connection) syn_data.Unlock();
        return ActionDrop{0};
    }

    data.connection->shift_server = data.connection->sent_seq - rte_be_to_cpu_32(seq);
    data.connection->state = Connection::State::SENT_PROXY_HEADER;
    YANET_LOG_WARNING("\t\tshift_seq=%u\n", data.connection->shift_server);
    uint32_t sent_seq = data.connection->sent_seq;

    // timestamps shift
    uint32_t timestamp_shift = data.connection->timestamp_echo - tcp_options.timestamp_value;
    YANET_LOG_WARNING("\t timestamps: proxy_start=%d, server_start=%d, shift=%d\n", data.connection->timestamp_echo, tcp_options.timestamp_value, timestamp_shift);
    data.connection->timestamp_shift = timestamp_shift;

    if ((data.connection->flags & Connection::flag_from_synkookie) != 0)
    {
        data.connection->window_size_shift = tcp_options.window_scaling - service.winscale;
    }

    auto action = ActionServerOnSynAck_AckToClient{
        .client_addr = client_addr,
        .client_port = client_port,
        .seq = rte_cpu_to_be_32(sent_seq + 1),
        .ack = (service.proxy_header ? add_cpu_32(ack, int(sizeof(proxy_v2_ipv4_hdr))) : ack),
        .timestamp_shift = timestamp_shift,
        .window_size_shift = data.connection->window_size_shift };

    if (data.connection) data.Unlock();
    if (syn_data.connection) syn_data.Unlock();

    return action;
}

ActionServerOnAck_Result TcpConnectionStore::ActionServerOnAck(proxy_service_id_t service_id,
                                                               const dataplane::globalBase::proxy_service_t& service,
                                                               uint32_t current_time,
                                                               uint32_t dst_addr,
                                                               uint16_t dst_port,
                                                               uint32_t seq,
                                                               uint32_t ack)
{
    // find in local
    uint64_t client_info = local_pools_[service_id].FindClientByLocal(dst_addr, dst_port);
    if (client_info == 0)
    {
        YANET_LOG_ERROR("Not found in local connections");
        return ActionDrop{0};
    }
    uint32_t client_addr;
    tPortId client_port;
    dataplane::proxy::LocalPool::UnpackTuple(client_info, client_addr, client_port);

    // find in connections
    ConnectionData<Connection> data;
    auto result = service_connections_[service_id].FindAndLock(client_addr, client_port, current_time, data);
    if (result != TableSearchResult::Found)
    {
        YANET_LOG_WARNING("not found in connections\n");
        if (data.connection) data.Unlock();
        return ActionDrop{0};
    }

    if (data.connection->state == Connection::State::SENT_PROXY_HEADER)
    {
        YANET_LOG_ERROR("unimplemented\n");
        if (data.connection) data.Unlock();
        return ActionDrop{0};
    }
    else
    {
        // state == ESTABLISHED
        ActionServerOnAck_Forward forward;
        forward.dst_addr = client_addr;
        forward.dst_port = client_port;
        forward.shift_seq = data.connection->shift_server;
        forward.timestamp_shift = data.connection->timestamp_shift;
        forward.window_size_shift = data.connection->window_size_shift;
        if (data.connection) data.Unlock();
        return forward;
    }
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
