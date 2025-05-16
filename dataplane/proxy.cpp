#include "proxy.h"

#include <sstream>
#include "metadata.h"
#include "common.h"

#define TIMEOUT_ACK 3 // todo

namespace dataplane::proxy
{

inline uint64_t KeyConnection(uint32_t addr, tPortId port)
{
    return (((uint64_t)addr) << 16) | (uint64_t)port;
}

inline void UnpackKeyConnection(uint64_t key, uint32_t& addr, uint16_t& port)
{
    port = key & 0xffff;
    addr = key >> 16;
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

uint32_t TcpOptions::Write(rte_mbuf* mbuf) const
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
    size_t tcp_header_len_old = (tcp_header->data_off >> 4) << 2;
    uint16_t tcp_data_len = rte_be_to_cpu_16(ipv4_header->total_length) - rte_ipv4_hdr_len(ipv4_header) - tcp_header_len_old;

    uint8_t* data = (uint8_t*)tcp_header + sizeof(rte_tcp_hdr);
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

void ShiftSAcks(rte_tcp_hdr* tcp_header, uint32_t shift)
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
            *((uint32_t*)(options + index + 2)) = dataplane::proxy::add_cpu_32(*((uint32_t*)(options + index + 2)), shift);
            *((uint32_t*)(options + index + 6)) = dataplane::proxy::add_cpu_32(*((uint32_t*)(options + index + 6)), shift);
            index += 10;
            break;
        case TCPOPT_TIMESTAMP:
            index += 10;
            break;
        case TCPOPT_NOP:
            index++;
            break;
        case TCPOPT_EOL:
            return;
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
    YANET_LOG_WARNING("proxy_update: proxy_id=%d, syn_type=%s, max_local_addresses=%d, mem_size_syn=%d, mem_size_connections=%d\n", proxy_id, from_proxy_type(proxy.syn_type), proxy.max_local_addresses, proxy.mem_size_syn, proxy.mem_size_connections);
    YANET_LOG_WARNING("\ttimeout_syn=%d, timeout_connection=%d, timeout_fin=%d, flow=%s\n", proxy.timeout_syn, proxy.timeout_connection, proxy.timeout_fin, proxy.flow.to_string().c_str());
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
    YANET_LOG_WARNING("proxy_service_update: service_id=%d, proxy=%s:%d, service=%s:%d, proxy_header=%d, size_connections_table=%d, size_syn_table=%d\n",
        service_id, common::ipv4_address_t(rte_cpu_to_be_32(service.proxy_addr.address)).toString().c_str(), service.proxy_port,
        common::ipv4_address_t(rte_cpu_to_be_32(service.service_addr.address)).toString().c_str(), service.service_port, service.proxy_header, service.size_connections_table, service.size_syn_table);

    std::lock_guard guard(mutex_);

    if (!service_connections_[service_id].Initialize(service_id, service.size_connections_table, memory_manager))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.ServiceConnections, service: %d\n", service_id);
        return eResult::errorAllocatingMemory;
    }

    if (!syn_connections_[service_id].Initialize(service_id, service.size_syn_table, memory_manager))
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
    YANET_LOG_WARNING("TcpConnectionStore::CollectGarbage: current_time=%d\n", current_time);
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
            service_connections_[index].GetConnections(index, current_time, response);
        }
    }
    else if (*service_id < YANET_CONFIG_PROXY_SERVICES_SIZE)
    {
        service_connections_[*service_id].GetConnections(*service_id, current_time, response);
    }

    // response.emplace_back(service, src_addr, src_port, info.local_addr, info.local_port, static_cast<uint16_t>(info.state));

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
            syn_connections_[index].GetSyn(index, current_time, response);
        }
    }
    else if (*service_id < YANET_CONFIG_PROXY_SERVICES_SIZE)
    {
        syn_connections_[*service_id].GetSyn(*service_id, current_time, response);
    }

    return response;
}


// Action from worker
ActionClientOnSyn_Result TcpConnectionStore::ActionClientOnSyn(proxy_service_id_t service_id,
                                                               const dataplane::globalBase::proxy_service_t& service,
                                                               uint32_t current_time,
                                                               uint32_t src_addr,
                                                               uint16_t src_port,
                                                               uint32_t seq,
                                                               TcpOptions& tcp_options)
{
    SynOperationData operation_data;
    SynInsertResult result_insert_syn = syn_connections_[service_id].TryInsertClient(src_addr, src_port, seq, current_time, operation_data);

    if (result_insert_syn == SynInsertResult::exists)
    {
        YANET_LOG_WARNING("\tSynInsertResult::exists\n");
        if (service.proxy_header)
        {
            seq = add_cpu_32(seq, -int(sizeof(proxy_v2_ipv4_hdr)));
        }
        return ActionClientOnSyn_SynToServer{seq, operation_data.local_addr, operation_data.local_port};
    }
    else if (result_insert_syn == SynInsertResult::new_record)
    {
        YANET_LOG_WARNING("\tSynInsertResult::new_record\n");
        std::optional<std::pair<uint32_t, tPortId>> local = local_pools_[service_id].Allocate(src_addr, src_port);
        if (local.has_value())
        {
            YANET_LOG_WARNING("\tlocal.has_value\n");
            operation_data.local_addr = std::get<0>(*local);
            operation_data.local_port = std::get<1>(*local);
            syn_connections_[service_id].UpdateLocal(src_addr, src_port, current_time, operation_data);
            if (service.proxy_header)
            {
                seq = add_cpu_32(seq, -int(sizeof(proxy_v2_ipv4_hdr)));
            }
            return ActionClientOnSyn_SynToServer{seq, operation_data.local_addr, operation_data.local_port};
        }
        syn_connections_[service_id].Remove(src_addr, src_port, current_time, operation_data);
    }

    tcp_options.sack_permitted &= service.use_sack;
    tcp_options.mss = std::min(tcp_options.mss, (uint16_t)service.mss);

    uint32_t cookie_data = SynCookies::PackData({SynCookies::MssToTable(tcp_options.mss), tcp_options.sack_permitted, tcp_options.window_scaling, 0}); // ecn
    uint32_t cookie = syn_cookies_.GetCookie(src_addr, service.service_addr.address, src_port, service.service_port, seq, cookie_data); // dst_addr, dst_port
    YANET_LOG_WARNING("\tcookie_data=%d, cookie=%u, seq=%u\n", cookie_data, cookie, seq);

    tcp_options.window_scaling = service.winscale;
    tcp_options.timestamp_echo = tcp_options.timestamp_value;
    tcp_options.timestamp_value = 1;

    return ActionClientOnSyn_SynAckToClient{rte_cpu_to_be_32(cookie), add_cpu_32(seq, 1)};
}

ActionClientOnAck_Result TcpConnectionStore::ActionClientOnAck(proxy_service_id_t service_id,
                                                               const dataplane::globalBase::proxy_service_t& service,
                                                               uint32_t current_time,
                                                               uint32_t src_addr,
                                                               uint16_t src_port,
                                                               uint32_t seq,
                                                               uint32_t ack)
{
    OneConnection* connection;
    ConnectionBucket* bucket;
    if (service_connections_[service_id].Find(src_addr, src_port, current_time, false, &connection, &bucket))
    {
        ActionClientOnAck_Forward result;
        UnpackKeyConnection(connection->local, result.local_addr, result.local_port);
        result.add_proxy_header = false;
        result.shift_ack = -connection->shift_server;
        result.shift_seq = 0;

        if (connection->state == ConnectionState::SENT_PROXY_HEADER)
        {
            YANET_LOG_WARNING("\t\t\tchange state from SENT_PROXY_HEADER -> ESTABLISHED\n");
            connection->state = ConnectionState::ESTABLISHED;
            result.add_proxy_header = service.proxy_header;
            if (result.add_proxy_header)
            {
                result.shift_seq = -int(sizeof(proxy_v2_ipv4_hdr));
            }
        }
        bucket->Unlock();

        return result;
    }

    // new connection
    SynOperationData operation_data;
    if (syn_connections_[service_id].SearchAndRemove(src_addr, src_port, current_time, operation_data))
    {
        // todo - Try add to connections, can fail !!!!
        if (!service_connections_[service_id].Find(src_addr, src_port, current_time, true, &connection, &bucket))
        {
            YANET_LOG_WARNING("failed insert to connections\n");
            return ActionDrop{0};
        }
        connection->local = KeyConnection(operation_data.local_addr, operation_data.local_port);
        connection->shift_server = 0;
        connection->state = ConnectionState::ESTABLISHED;
        bucket->Unlock();

        ActionClientOnAck_Forward result;
        result.local_addr = operation_data.local_addr;
        result.local_port = operation_data.local_port;
        result.add_proxy_header = service.proxy_header;
        result.shift_ack = 0;
        result.shift_seq = (result.add_proxy_header ? -int(sizeof(proxy_v2_ipv4_hdr)) : 0);

        return result;            
    }
    
    // try check cookie
    uint32_t cookie_data;
    uint32_t result = syn_cookies_.CheckCookie(rte_cpu_to_be_32(ack) - 1, src_addr, service.service_addr.address, src_port, service.service_port, add_cpu_32(seq, -1)); // dst_addr, dst_port
    YANET_LOG_WARNING("\tresult=%d, cookie_data=%d, ack=%u, seq=%u\n", result, cookie_data, ack, seq);

    if (result == 0)
    {
        YANET_LOG_WARNING("\tcookie check error\n");
        return ActionDrop{0};
    }

    SynCookies::TCPOptions options = SynCookies::UnpackData(result);
    YANET_LOG_WARNING("\tmss=%d, sack=%d, wscale=%d\n", SynCookies::MssFromTable(options.mss), options.sack, options.wscale);

    // get from local
    auto local = local_pools_[service_id].Allocate(src_addr, src_port);
    if (!local.has_value())
    {
        YANET_LOG_WARNING("\tcan't allocate in local pool\n");
        return ActionDrop{1};
    }

    // try add to connections
    // can fail!

    // Add to connections
    if (!service_connections_[service_id].Find(src_addr, src_port, current_time, true, &connection, &bucket))
    {
        YANET_LOG_WARNING("failed insert to connections\n");
        return ActionDrop{0};
    }
    connection->local = KeyConnection(std::get<0>(*local), std::get<1>(*local));
    connection->state = ConnectionState::SENT_SYN_SERVER;
    connection->sent_seq = rte_cpu_to_be_32(ack) - 1;
    bucket->Unlock();

    ActionClientOnAck_NewServerConnection new_server_connection;
    new_server_connection.local_addr = std::get<0>(*local);
    new_server_connection.local_port = std::get<1>(*local);
    new_server_connection.seq = add_cpu_32(seq, -1 + (service.proxy_header ? -int(sizeof(proxy_v2_ipv4_hdr)) : 0));

    TcpOptions tcp_options;
    tcp_options.mss = SynCookies::MssFromTable(options.mss);
    tcp_options.sack_permitted = options.sack;
    tcp_options.window_scaling = options.wscale;

    new_server_connection.tcp_options = tcp_options;

    return new_server_connection;
}

ActionServerOnSynAck_Result TcpConnectionStore::ActionServerOnSynAck(proxy_service_id_t service_id,
                                                                     const dataplane::globalBase::proxy_service_t& service,
                                                                     uint32_t current_time,
                                                                     uint32_t dst_addr,
                                                                     uint16_t dst_port,
                                                                     uint32_t seq,
                                                                     uint32_t ack,
                                                                     uint8_t* tcp_options,
                                                                     size_t tcp_options_size)
{
    // find in local pool
    std::optional<std::pair<uint32_t, tPortId>> client_info = local_pools_[service_id].FindClientByLocal(dst_addr, dst_port);
    if (!client_info.has_value())
    {
        YANET_LOG_ERROR("Not found in local connections\n");
        return ActionDrop{0};
    }
    auto [client_addr, client_port] = *client_info;

    // find in syn or conncetions
    if (syn_connections_[service_id].UpdateTimeFromServerAnswer(client_addr, client_port, current_time))
    {
        if (service.proxy_header)
        {
            ack = add_cpu_32(ack, int(sizeof(proxy_v2_ipv4_hdr)));
        }
        return ActionServerOnSynAck_SynAckToClient{ack, client_addr, client_port};
    }

    // find in connections
    OneConnection* connection;
    ConnectionBucket* bucket;
    if (!service_connections_[service_id].Find(client_addr, client_port, current_time, false, &connection, &bucket))
    {
        YANET_LOG_WARNING("not found in connections\n");
        return ActionDrop{0};
    }

    connection->shift_server = connection->sent_seq - rte_be_to_cpu_32(seq);
    connection->state = ConnectionState::SENT_PROXY_HEADER;
    YANET_LOG_WARNING("\t\tshift_seq=%u\n", connection->shift_server);
    uint32_t sent_seq = connection->sent_seq;
    bucket->Unlock();

    return ActionServerOnSynAck_AckToClient{
	    .client_addr = client_addr,
	    .client_port = client_port,
	    .seq = rte_cpu_to_be_32(sent_seq + 1),
	    .ack = (service.proxy_header ? add_cpu_32(ack, int(sizeof(proxy_v2_ipv4_hdr))) : ack) };
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
    std::optional<std::pair<uint32_t, tPortId>> client_info = local_pools_[service_id].FindClientByLocal(dst_addr, dst_port);
    if (!client_info.has_value())
    {
        YANET_LOG_ERROR("Not found in local connections");
        return ActionDrop{0};
    }
    auto [client_addr, client_port] = *client_info;


    // find in connections
    OneConnection* connection;
    ConnectionBucket* bucket;
    if (!service_connections_[service_id].Find(client_addr, client_port, current_time, false, &connection, &bucket))
    {
        YANET_LOG_WARNING("not found in connections\n");
        return ActionDrop{0};
    }

    if (connection->state == ConnectionState::SENT_PROXY_HEADER)
    {
        bucket->Unlock();
        YANET_LOG_ERROR("unimplemented\n");
        return ActionDrop{0};

    }
    else
    {
        // state == ESTABLISHED
        
        ActionServerOnAck_Forward forward;
        forward.dst_addr = client_addr;
        forward.dst_port = client_port;
        forward.shift_seq = connection->shift_server;
        bucket->Unlock();        
        return forward;
    }
}

// Connections


void OneConnection::Clear()
{
    last_time = 0;
    local = 0;
}

bool OneConnection::IsExpired(uint32_t current_time)
{
    return last_time + TIMEOUT_ACK < current_time;
}

ConnectionBucket::ConnectionBucket()
{
    for (uint32_t index = 0; index < bucket_size; index++)
    {
        connections[index].Clear();
    }
}

bool ServiceConnections::Initialize(proxy_service_id_t service_id, uint32_t number_buckets, dataplane::memory_manager* memory_manager)
{
    if (initialized_)
    {
        return true;
    }

    size_t mem_size = number_buckets * sizeof(ConnectionBucket);
    YANET_LOG_WARNING("ServiceConnections::Initialize number_buckets=%d, mem_size=%ld\n", number_buckets, mem_size);

    tSocketId socket_id = 0; // todo !!!
    std::string name = "tcp_proxy.connections." + std::to_string(service_id);
    buckets_ = memory_manager->create_static_array<ConnectionBucket>(name.data(), number_buckets, socket_id);
    if (buckets_ == nullptr)
    {
        return false;
    }

    number_buckets_ = number_buckets;
    initialized_ = true;
    return true;
}

void ConnectionBucket::Lock()
{
    mutex.lock();
}

void ConnectionBucket::Unlock()
{
    mutex.unlock();
}

bool ServiceConnections::Find(uint32_t addr, uint16_t port, uint32_t current_time, bool create, OneConnection** connection, ConnectionBucket** bucket)
{
    if (number_buckets_ == 0)
    {
        return false;
    }

    uint64_t key = KeyConnection(addr, port);
    uint32_t bucket_index = key & (number_buckets_ - 1);
    uint32_t record_index = ConnectionBucket::bucket_size;
    *bucket = &buckets_[bucket_index];
    (*bucket)->Lock();

    for (uint32_t index = 0; index < ConnectionBucket::bucket_size; index++)
    {
        *connection = &(*bucket)->connections[index];
        if (!(*connection)->IsExpired(current_time))    // todo - check time = 0
        {
            // time ok
            if ((*connection)->client == key)
            {
                return true;
            }
        }
        else if ((*connection)->local == 0 && record_index == ConnectionBucket::bucket_size)
        {
            record_index = index;
        }
    }

    if (!create || record_index == ConnectionBucket::bucket_size)
    {
        (*bucket)->Unlock();
        return false;
    }

    *connection = &(*bucket)->connections[record_index];
    (*connection)->Clear();
    (*connection)->client = key;
    (*connection)->last_time = current_time;

    return true;
}

void ServiceConnections::GetConnections(proxy_service_id_t service_id, uint32_t current_time, common::idp::proxy_connections::response& response)
{

}

void ServiceConnections::CollectGarbage(uint32_t current_time, LocalPool& local_pool)
{
    for (uint32_t index = 0; index < number_buckets_; index++)
    {
        ConnectionBucket& bucket = buckets_[index];
        bucket.Lock();
        for (uint32_t i = 0; i < ConnectionBucket::bucket_size; i++)
        {
            OneConnection& connection = bucket.connections[i];
            if (connection.IsExpired(current_time))
            {
                uint32_t addr;
                uint16_t port;
                UnpackKeyConnection(connection.client, addr, port);
                local_pool.Free(addr, port);
                connection.Clear();
            }
        }
        bucket.Unlock();
    }
}

}
