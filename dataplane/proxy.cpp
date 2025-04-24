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
    YANET_LOG_WARNING("proxy_service_update: service_id=%d, proxy=%s:%d, service=%s:%d\n",
        service_id, common::ipv4_address_t(rte_cpu_to_be_32(service.proxy_addr.address)).toString().c_str(), service.proxy_port,
        common::ipv4_address_t(rte_cpu_to_be_32(service.service_addr.address)).toString().c_str(), service.service_port);
}

void TcpConnectionStore::proxy_service_remove(proxy_service_id_t service_id)
{
    YANET_LOG_WARNING("proxy_service_remove: service_id=%d\n", service_id);
}


// Action from worker
std::optional<AcceptClientSyn> TcpConnectionStore::ActionClientOnSyn(proxy_id_t proxy_id,
                                                                     proxy_service_id_t service_id,
                                                                     uint32_t src_addr,
                                                                     uint16_t src_port,
                                                                     uint32_t seq,
                                                                     TcpOptions&tcp_options)
{
    return table_syn_.ActionClientOnSyn(proxy_id, service_id, src_addr, src_port, seq, tcp_options);
}

ActionClientOnAckResult TcpConnectionStore::ActionClientOnAck(proxy_id_t proxy_id,
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
        if (syn_info == nullptr)
        {
            return ActionDrop{0};
        }

        auto local = local_pool_.Allocate(proxy_id, service_id);
        if (!local.has_value())
        {
            return ActionDrop{1};
        }

        ActionClientOnAckNewServerConnection new_server_connection;
        new_server_connection.local_addr = std::get<0>(*local);
        new_server_connection.local_port = std::get<1>(*local);
        new_server_connection.seq = add_cpu_32(syn_info->recv_seq, -int(sizeof(proxy_v2_ipv4_hdr)));
        new_server_connection.tcp_options = syn_info->tcp_options;
        // new_server_connection.tcp_options_size = syn_info->tcp_options_size;
        // memcpy(new_server_connection.tcp_options, syn_info->tcp_options, syn_info->tcp_options_size);

        // Add to connections_
        ConnectionInfo& connection_info = connections_[{service_id, src_addr, src_port}];
        connection_info.local_addr = std::get<0>(*local);
        connection_info.local_port = std::get<1>(*local);
        connection_info.state = ConnectionState::SENT_SYN_SERVER;
        connection_info.sent_seq = syn_info->sent_seq;

        // Add to server_connections_
        server_connections_[{service_id, std::get<0>(*local), std::get<1>(*local)}] = {service_id, src_addr, src_port};

        return new_server_connection;
    }
    else
    {
        ActionClientOnAckForward forward;
        forward.local_addr = iter_con->second.local_addr;
        forward.local_port = iter_con->second.local_port;
        forward.shift_ack = -iter_con->second.shift_seq;
        return forward;
    }
}

ActionServerOnSynAckResult TcpConnectionStore::ActionServerOnSynAck(proxy_id_t proxy_id,
                                                                    proxy_service_id_t service_id,
                                                                    uint32_t dst_addr,
                                                                    uint16_t dst_port,
                                                                    uint32_t seq,
                                                                    uint32_t ack,
                                                                    uint8_t* tcp_options,
                                                                    size_t tcp_options_size)
{
    std::lock_guard guard(mutex_);

    // find in server_connections_
    auto iter_sc = server_connections_.find({service_id, dst_addr, dst_port});
    if (iter_sc == server_connections_.end())
    {
        YANET_LOG_WARNING("not found in server_connections_\n");
        return ActionDrop{0};
    }

    // find in connections_
    auto iter_con = connections_.find(iter_sc->second);
    if (iter_con == connections_.end())
    {
        YANET_LOG_WARNING("not found in connections_\n");
        return ActionDrop{0};
    }

    iter_con->second.state = ConnectionState::SENT_PROXY_HEADER;
    if (tcp_options_size < sizeof(rte_tcp_hdr) || tcp_options_size > sizeof(rte_tcp_hdr) + MAX_SIZE_TCP_OPTIONS)
    {
        iter_con->second.tcp_options_size = 0;
    }
    else
    {
        iter_con->second.tcp_options_size = tcp_options_size - sizeof(rte_tcp_hdr);
        memcpy(iter_con->second.tcp_options, tcp_options + sizeof(rte_tcp_hdr), iter_con->second.tcp_options_size);
    }

    ActionServerOnSynAckSentProxyHeader result;

    result.src_addr = std::get<1>(iter_con->first);
    result.src_port = std::get<2>(iter_con->first);
    result.ack = add_cpu_32(seq, 1);
    result.seq = ack;

    return result;
}

ActionServerOnAckResult TcpConnectionStore::ActionServerOnAck(proxy_id_t proxy_id,
                                                              proxy_service_id_t service_id,
                                                              uint32_t dst_addr,
                                                              uint16_t dst_port,
                                                              uint32_t seq,
                                                              uint32_t ack)
{
    std::lock_guard guard(mutex_);

    // find in server_connections_
    auto iter_sc = server_connections_.find({service_id, dst_addr, dst_port});
    if (iter_sc == server_connections_.end())
    {
        YANET_LOG_WARNING("not found in server_connections_\n");
        return ActionDrop{0};
    }

    // find in connections_
    auto iter_con = connections_.find(iter_sc->second);
    if (iter_con == connections_.end())
    {
        YANET_LOG_WARNING("not found in connections_\n");
        return ActionDrop{0};
    }

    if (iter_con->second.state == ConnectionState::SENT_PROXY_HEADER)
    {
        iter_con->second.shift_seq = rte_cpu_to_be_32(iter_con->second.sent_seq) - rte_cpu_to_be_32(seq) + 1;
        iter_con->second.state = ConnectionState::ESTABLISHED;
        // YANET_LOG_WARNING("\t seq: first_sent=%d, from_server=%d, shift=%d\n", iter_con->second.sent_seq, seq, iter_con->second.shift_seq);

        ActionServerOnAckForwardFirst forward_result;

        forward_result.dst_addr = std::get<1>(iter_con->first);
        forward_result.dst_port = std::get<2>(iter_con->first);
        forward_result.seq = add_cpu_32(seq, iter_con->second.shift_seq);
        forward_result.ack = ack;

        TcpOptions tcp_options;
        memset(&tcp_options, 0, sizeof(tcp_options));
        tcp_options.Read(iter_con->second.tcp_options, iter_con->second.tcp_options_size);
        tcp_options.sack = false;
        tcp_options.mss = 0;
        tcp_options.window_scaling = 0;

        // forward_result.tcp_options_size = iter_con->second.tcp_options_size;
        // memcpy(forward_result.tcp_options, iter_con->second.tcp_options, iter_con->second.tcp_options_size);
        forward_result.tcp_options_size = tcp_options.Write(forward_result.tcp_options);

        return forward_result;
    }
    else
    {
        ActionServerOnAckForward forward;
        forward.dst_addr = std::get<1>(iter_con->first);
        forward.dst_port = std::get<2>(iter_con->first);
        forward.shift_seq = iter_con->second.shift_seq;
        return forward;
    }
}




std::optional<AcceptClientSyn> SynFromClients::ActionClientOnSyn(proxy_id_t proxy_id,
                                                                 proxy_service_id_t service_id,
                                                                 uint32_t src_addr,
                                                                 uint16_t src_port,
                                                                 uint32_t seq,
                                                                 TcpOptions&tcp_options)
{
    std::lock_guard guard(mutex_);

    uint32_t sent_seq = rte_cpu_to_be_32(2000);

    SynConnectionInfo& info = connections_[{service_id, src_addr, src_port}];
    info.recv_seq = seq;
    info.sent_seq = sent_seq;
    info.tcp_options = tcp_options;

    // if (tcp_options_size < sizeof(rte_tcp_hdr) || tcp_options_size > sizeof(rte_tcp_hdr) + MAX_SIZE_TCP_OPTIONS)
    // {
    //     info.tcp_options_size = 0;
    // }
    // else
    // {
    //     info.tcp_options_size = tcp_options_size - sizeof(rte_tcp_hdr);
    //     memcpy(info.tcp_options, tcp_options + sizeof(rte_tcp_hdr), info.tcp_options_size);
    // }

    tcp_options.window_scaling = 3;
    tcp_options.mss = 1000;
    if (tcp_options.timestamp_value != 0)
    {
        tcp_options.timestamp_echo = tcp_options.timestamp_value;
        tcp_options.timestamp_value = 1234567;
    }
    
	return AcceptClientSyn{sent_seq, add_cpu_32(seq, 1)};
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


}
