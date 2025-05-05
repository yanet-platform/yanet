#include "proxy.h"

#include <rte_tcp.h>
#include <sstream>

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
            sack = 1;

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

uint32_t TcpOptions::Write(uint8_t* data) const
{
    uint32_t len = 0;
    
    if (mss != 0)
    {
        data[len] = TCPOPT_MSS;
        data[len + 1] = 4;
        *((uint16_t*)(data + len + 2)) = rte_cpu_to_be_16(mss);
        len += 4;
    }

    if (sack != 0)
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

bool TcpOptions::CheckSize(uint32_t index, uint32_t len, uint8_t* data, uint8_t expected)
{
    return (index + expected <= len) && (data[index + 1] == expected);
}

std::string TcpOptions::DebugInfo() const
{
    std::stringstream ss;
    
    ss << "MSS: " << mss;
    
    if (sack != 0)
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
    YANET_LOG_WARNING("proxy_update: proxy_id=%d, syn_type=%s, max_local_addresses=%d, mem_size_syn=%d, mem_size_connections=%d\n", proxy_id, from_proxy_type(proxy.syn_type), proxy.max_local_addresses, proxy.mem_size_syn, proxy.mem_size_connections);
    YANET_LOG_WARNING("\ttimeout_syn=%d, timeout_connection=%d, timeout_fin=%d, flow=%s\n", proxy.timeout_syn, proxy.timeout_connection, proxy.timeout_fin, proxy.flow.to_string().c_str());
}

void TcpConnectionStore::proxy_remove(proxy_id_t proxy_id)
{
    YANET_LOG_WARNING("proxy_remove: proxy_id=%d\n", proxy_id);
}

void TcpConnectionStore::proxy_add_local_pool(proxy_id_t proxy_id, const common::ip_prefix_t& prefix)
{
    YANET_LOG_WARNING("proxy_add_local_pool proxy_id=%d, prefix=%s\n", proxy_id, prefix.toString().c_str());
    ipv4_prefix_t prefix_pool;
    prefix_pool.address = ipv4_address_t::convert(prefix.get_ipv4().address());
    prefix_pool.address.address = rte_cpu_to_be_32(prefix_pool.address.address);
    prefix_pool.mask = prefix.mask();
    local_pool_.Add(proxy_id, prefix_pool);
}

void TcpConnectionStore::proxy_service_update(proxy_service_id_t service_id, const dataplane::globalBase::proxy_service_t& service)
{
    YANET_LOG_WARNING("proxy_service_update: service_id=%d, proxy=%s:%d, service=%s:%d, proxy_header=%d, size_syn_table=%d\n",
        service_id, common::ipv4_address_t(rte_cpu_to_be_32(service.proxy_addr.address)).toString().c_str(), service.proxy_port,
        common::ipv4_address_t(rte_cpu_to_be_32(service.service_addr.address)).toString().c_str(), service.service_port, service.proxy_header, service.size_syn_table);

    std::lock_guard guard(mutex_);
    services_info_[service_id].proxy_header = service.proxy_header;
    services_info_[service_id].size_syn_table = service.size_syn_table;
    
    services_info_[service_id].use_sack = service.use_sack;
    services_info_[service_id].mss = service.mss;
    services_info_[service_id].winscale = service.winscale;

    table_syn_.SetConfig(service_id, service.size_syn_table);
}

void TcpConnectionStore::proxy_service_remove(proxy_service_id_t service_id)
{
    YANET_LOG_WARNING("proxy_service_remove: service_id=%d\n", service_id);
}

// Info

common::idp::proxy_connections::response TcpConnectionStore::GetConnections(std::optional<proxy_service_id_t> service_id)
{
    common::idp::proxy_connections::response response;
    std::lock_guard guard(mutex_);

    for (const auto& [key, info] : connections_)
    {
        auto [service, src_addr, src_port] = key;
        if (service_id.has_value() && *service_id != service)
        {
            continue;
        }

        response.emplace_back(service, src_addr, src_port, info.local_addr, info.local_port, static_cast<uint16_t>(info.state));
    }

    return response;
}

common::idp::proxy_syn::response TcpConnectionStore::GetSyn(std::optional<proxy_service_id_t> service_id)
{
    return table_syn_.GetSyn(service_id);
}


// Action from worker
ActionClientOnSyn_Result TcpConnectionStore::ActionClientOnSyn(proxy_id_t proxy_id,
                                                               proxy_service_id_t service_id,
                                                               uint32_t src_addr,
                                                               uint16_t src_port,
                                                               uint32_t seq,
                                                               TcpOptions& tcp_options)
{
    std::lock_guard guard(mutex_);

    // syn - retransmit ????

    if (table_syn_.TryInsertClient({service_id, src_addr, src_port}))
    {
        std::optional<std::pair<uint32_t, tPortId>> local = local_pool_.Allocate(proxy_id, service_id, src_addr, src_port);
        if (local.has_value())
        {
            auto [local_addr, local_port] = *local;
            table_syn_.UpdateInfo({service_id, src_addr, src_port}, local_addr, local_port, seq);
            if (services_info_[service_id].proxy_header)
            {
                seq = add_cpu_32(seq, -int(sizeof(proxy_v2_ipv4_hdr)));
            }
            return ActionClientOnSyn_SynToServer{seq, local_addr, local_port};
        }
        table_syn_.Free({service_id, src_addr, src_port});
    }

    // return table_syn_.ActionClientOnSyn(proxy_id, service_id, src_addr, src_port, seq, tcp_options);
    // YANET_LOG_ERROR("We need syn-cookie!\n");

    tcp_options.sack &= services_info_[service_id].use_sack;
    tcp_options.mss = std::min(tcp_options.mss, (uint16_t)services_info_[service_id].mss);

    uint32_t cookie_data = SynCookies::PackData({SynCookies::MssToTable(tcp_options.mss), tcp_options.sack, tcp_options.window_scaling});
    uint32_t cookie = syn_cookies_.GetCookie(src_addr, 0, src_port, 0, seq, cookie_data); // dst_addr, dst_port
    YANET_LOG_WARNING("\tcookie_data=%d, cookie=%u, seq=%u\n", cookie_data, cookie, seq);

    tcp_options.window_scaling = services_info_[service_id].winscale;
    tcp_options.timestamp_echo = tcp_options.timestamp_value;
    tcp_options.timestamp_value = 1;

    return ActionClientOnSyn_SynAckToClient{rte_cpu_to_be_32(cookie), add_cpu_32(seq, 1)};
}

ActionClientOnAck_Result TcpConnectionStore::ActionClientOnAck(proxy_id_t proxy_id,
                                                               proxy_service_id_t service_id,
                                                               uint32_t src_addr,
                                                               uint16_t src_port,
                                                               uint32_t seq,
                                                               uint32_t ack)
{
    std::lock_guard guard(mutex_);
    auto iter_con = connections_.find({service_id, src_addr, src_port});
    if (iter_con == connections_.end())
    {
        // new connection
        SynConnectionInfo* syn_info = table_syn_.FindConnection({service_id, src_addr, src_port});
        if (syn_info != nullptr)
        {
            // Try add to connections, can fail !!!!
            ConnectionInfo& con_info = connections_[{service_id, src_addr, src_port}];
            con_info.local_addr = syn_info->local_addr;
            con_info.local_port = syn_info->local_port;
            con_info.shift_server = 0;
            con_info.state = ConnectionState::ESTABLISHED;

            // Remove from syns
            table_syn_.Free({service_id, src_addr, src_port});


            ActionClientOnAck_Forward result;
            result.local_addr = syn_info->local_addr;
            result.local_port = syn_info->local_port;
            result.add_proxy_header = services_info_[service_id].proxy_header;
            result.shift_ack = 0;
            result.shift_seq = (result.add_proxy_header ? -int(sizeof(proxy_v2_ipv4_hdr)) : 0);

            return result;            
        }
        
        // try check cookie
        uint32_t cookie_data;
        uint32_t result = syn_cookies_.CheckCookie(rte_cpu_to_be_32(ack) - 1, src_addr, 0, src_port, 0, add_cpu_32(seq, -1)); // dst_addr, dst_port
        YANET_LOG_WARNING("\tresult=%d, cookie_data=%d, ack=%u, seq=%u\n", result, cookie_data, ack, seq);

        if (result == 0)
        {
            YANET_LOG_WARNING("\tcookie check error\n");
            return ActionDrop{0};
        }

        SynCookies::TCPOptions options = SynCookies::UnpackData(result);
        YANET_LOG_WARNING("\tmss=%d, sack=%d, wscale=%d\n", SynCookies::MssFromTable(options.mss), options.sack, options.wscale);

        // get from local
        auto local = local_pool_.Allocate(proxy_id, service_id, src_addr, src_port);
        if (!local.has_value())
        {
            YANET_LOG_WARNING("\tcan't allocate in local pool\n");
            return ActionDrop{1};
        }

        // try add to connections
        // can fail!

        // Add to connections_
        ConnectionInfo& connection_info = connections_[{service_id, src_addr, src_port}];
        connection_info.local_addr = std::get<0>(*local);
        connection_info.local_port = std::get<1>(*local);
        connection_info.state = ConnectionState::SENT_SYN_SERVER;
        connection_info.sent_seq = rte_cpu_to_be_32(ack) - 1;

        ActionClientOnAck_NewServerConnection new_server_connection;
        new_server_connection.local_addr = std::get<0>(*local);
        new_server_connection.local_port = std::get<1>(*local);
        new_server_connection.seq = add_cpu_32(seq, -1 + (services_info_[service_id].proxy_header ? -int(sizeof(proxy_v2_ipv4_hdr)) : 0));

        TcpOptions tcp_options;
        tcp_options.mss = SynCookies::MssFromTable(options.mss);
        tcp_options.sack = options.sack;
        tcp_options.window_scaling = options.wscale;

        new_server_connection.tcp_options = tcp_options;

        return new_server_connection;

    }
    else
    {
        ActionClientOnAck_Forward result;
        result.local_addr = iter_con->second.local_addr;
        result.local_port = iter_con->second.local_port;
        result.add_proxy_header = false;
        result.shift_ack = -iter_con->second.shift_server;
        result.shift_seq = 0;

        if (iter_con->second.state == ConnectionState::SENT_PROXY_HEADER)
        {
            YANET_LOG_WARNING("\t\t\tchange state from SENT_PROXY_HEADER -> ESTABLISHED\n");
            iter_con->second.state = ConnectionState::ESTABLISHED;
            result.add_proxy_header = services_info_[service_id].proxy_header;
            if (result.add_proxy_header)
            {
                result.shift_seq = -int(sizeof(proxy_v2_ipv4_hdr));
            }
        }

        return result;
    }
}

ActionServerOnSynAck_Result TcpConnectionStore::ActionServerOnSynAck(proxy_id_t proxy_id,
                                                                     proxy_service_id_t service_id,
                                                                     uint32_t dst_addr,
                                                                     uint16_t dst_port,
                                                                     uint32_t seq,
                                                                     uint32_t ack,
                                                                     uint8_t* tcp_options,
                                                                     size_t tcp_options_size)
{
    // find in local pool
    std::optional<std::pair<uint32_t, tPortId>> client_info = local_pool_.FindClientByLocal(dst_addr, dst_port);
    if (!client_info.has_value())
    {
        YANET_LOG_ERROR("Not found in local connections");
        return ActionDrop{0};
    }
    auto [client_addr, client_port] = *client_info;

    // find in syn or conncetions
    SynConnectionInfo* syn_info = table_syn_.FindConnection({service_id, client_addr, client_port});
    if (syn_info != nullptr)
    {
        if (services_info_[service_id].proxy_header)
        {
            ack = add_cpu_32(ack, int(sizeof(proxy_v2_ipv4_hdr)));
        }
        return ActionServerOnSynAck_SynAckToClient{ack, client_addr, client_port};
    }

    std::lock_guard guard(mutex_);

    // find in connections_
    auto iter_con = connections_.find({service_id, client_addr, client_port});
    if (iter_con == connections_.end())
    {
        YANET_LOG_WARNING("not found in connections_\n");
        return ActionDrop{0};
    }

    // iter_con->second.shift_server = iter_con->second.sent_seq + (iter_con->second.state == ConnectionState::ESTABLISHED ? 1 : 0) - rte_be_to_cpu_32(seq);
    iter_con->second.shift_server = iter_con->second.sent_seq - rte_be_to_cpu_32(seq);
    iter_con->second.state = ConnectionState::SENT_PROXY_HEADER;
    YANET_LOG_WARNING("\t\tshift_seq=%u\n", iter_con->second.shift_server);

    return ActionServerOnSynAck_AckToClient{
	    .client_addr = client_addr,
	    .client_port = client_port,
	    .seq = rte_cpu_to_be_32(iter_con->second.sent_seq + 1),
	    .ack = (services_info_[service_id].proxy_header ? add_cpu_32(ack, int(sizeof(proxy_v2_ipv4_hdr))) : ack) };
}

ActionServerOnAck_Result TcpConnectionStore::ActionServerOnAck(proxy_id_t proxy_id,
                                                               proxy_service_id_t service_id,
                                                               uint32_t dst_addr,
                                                               uint16_t dst_port,
                                                               uint32_t seq,
                                                               uint32_t ack)
{
    std::lock_guard guard(mutex_);

    // find in local
    std::optional<std::pair<uint32_t, tPortId>> client_info = local_pool_.FindClientByLocal(dst_addr, dst_port);
    if (!client_info.has_value())
    {
        YANET_LOG_ERROR("Not found in local connections");
        return ActionDrop{0};
    }
    auto [client_addr, client_port] = *client_info;


    // find in connections_
    auto iter_con = connections_.find({service_id, client_addr, client_port});
    if (iter_con == connections_.end())
    {
        YANET_LOG_WARNING("not found in connections_\n");
        return ActionDrop{0};
    }

    if (iter_con->second.state == ConnectionState::SENT_PROXY_HEADER)
    {
        YANET_LOG_ERROR("unimplemented\n");
        return ActionDrop{0};

    }
    else
    {
        // state == ESTABLISHED
        
        ActionServerOnAck_Forward forward;
        forward.dst_addr = client_addr;
        forward.dst_port = client_port;
        forward.shift_seq = iter_con->second.shift_server;
        return forward;
    }
}



void SynFromClients::SetConfig(proxy_service_id_t service_id, uint32_t size_syn_table)
{
    configs_[service_id] = size_syn_table;
}

bool SynFromClients::TryInsertClient(connection_key key)
{
    return configs_[std::get<0>(key)] != 0;
}

void SynFromClients::Free(connection_key key)
{
    std::lock_guard guard(mutex_);
    connections_.erase(key);
}

void SynFromClients::UpdateInfo(connection_key key, uint32_t local_addr, tPortId local_port, uint32_t seq)
{
    std::lock_guard guard(mutex_);
    SynConnectionInfo connection_info;
    connection_info.recv_seq = seq;
    connection_info.local_addr = local_addr;
    connection_info.local_port = local_port;
    connections_[key] = connection_info;
}

SynConnectionInfo* SynFromClients::FindConnection(connection_key key)
{
    std::lock_guard guard(mutex_);
    auto iter = connections_.find(key);
    if (iter == connections_.end())
    {
        return nullptr;
    }
    return &iter->second;
}

common::idp::proxy_syn::response SynFromClients::GetSyn(std::optional<proxy_service_id_t> service_id)
{
    common::idp::proxy_syn::response response;
    std::lock_guard guard(mutex_);

    for (const auto& iter : connections_)
    {
        auto [service, src_addr, src_port] = iter.first;
        if (service_id.has_value() && *service_id != service)
        {
            continue;
        }

        response.emplace_back(service, src_addr, src_port);
    }

    return response;
}

}
