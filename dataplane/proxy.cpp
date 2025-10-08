#include <sstream>

#include "common/counters.h"

#include "common.h"
#include "globalbase.h"
#include "metadata.h"
#include "proxy.h"
#include "syncookies.h"

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

bool TcpOptions::Read(rte_tcp_hdr* tcp_header)
{
    size_t tcp_header_len = std::max(sizeof(rte_tcp_hdr), (size_t)(tcp_header->data_off >> 4) << 2);
    uint8_t* data = (uint8_t*)tcp_header + sizeof(rte_tcp_hdr);
    uint32_t len = tcp_header_len - sizeof(rte_tcp_hdr);

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

bool TcpOptions::ReadOnlyTimestampsAndSack(rte_tcp_hdr* tcp_header)
{
    size_t tcp_header_len = std::max(sizeof(rte_tcp_hdr), (size_t)(tcp_header->data_off >> 4) << 2);
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
            if (!CheckSize(index_read, len, options, TCP_OPTION_TS_LEN)) {
                return false;
            }
            timestamp_value = rte_be_to_cpu_32(*((uint32_t*)(options + index_read + 2)));
            timestamp_echo = rte_be_to_cpu_32(*((uint32_t*)(options + index_read + 6)));
            index_read += TCP_OPTION_TS_LEN;
            break;
        }
        case TCP_OPTION_KIND_SACK:
        {
            uint32_t cur_sack_count = (options[index_read + 1] >> 3);
            if (options[index_read + 1] != 8 * cur_sack_count + 2)
            {
                return false;
            }
            uint32_t index = 0;
            while (index < cur_sack_count && sack_count < TCP_OPTIONS_MAX_SACK_COUNT)
            {
                sack_start[sack_count] = rte_be_to_cpu_32(*((uint32_t*)(options + index_read + 2 + 8 * index)));
                sack_finish[sack_count] = rte_be_to_cpu_32(*((uint32_t*)(options + index_read + 6 + 8 * index)));
                sack_count++;
                index++;
            }
            if (index < cur_sack_count)
            {
                return false;
            }
            index_read += options[index_read + 1];
            break;
        }
        case TCP_OPTION_KIND_NOP:
            index_read += TCP_OPTION_NOP_LEN;
            break;
        case TCP_OPTION_KIND_EOL:
            return true;
        default:
            index_read += options[index_read + 1];
        }
    }    
    return true;
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

    if (sack_count != 0)
    {
        tcp_option_t* opt = (tcp_option_t*)&data[len];
        opt->kind = TCP_OPTION_KIND_SACK;
        opt->len = 2 + 8 * sack_count;
        for (uint32_t index = 0; index < sack_count; index++)
        {
            *(uint32_t*)(opt->data + 8 * index) = rte_cpu_to_be_32(sack_start[index]);
            *(uint32_t*)(opt->data + 4 + 8 * index) = rte_cpu_to_be_32(sack_finish[index]);
        }
        len += 2 + 8 * sack_count;
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
    uint32_t size = (sack_count == 0 ? 0 : 2 + 8 * sack_count);
    if (mss != 0) size += TCP_OPTION_MSS_LEN;
    if (sack_permitted != 0) size += TCP_OPTION_SP_LEN;
    if (timestamp_value != 0 || timestamp_echo != 0) size += TCP_OPTION_TS_LEN;
    if (window_scaling != 0) size += TCP_OPTION_WS_LEN;
    // Round up to multiple of 4
    size = (size + 4 - 1) & -4;
    return size;
}

uint32_t TcpOptions::WriteSYN(rte_mbuf* mbuf, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header) const
{
    uint32_t len = WriteBuffer((uint8_t*)(tcp_header) + sizeof(rte_tcp_hdr));

    tcp_header->data_off = ((sizeof(rte_tcp_hdr) + len) >> 2) << 4;
    
    uint16_t total_length = rte_ipv4_hdr_len(ipv4_header) + sizeof(rte_tcp_hdr) + len;
    ipv4_header->total_length = rte_cpu_to_be_16(total_length);

    mbuf->data_len = sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr) + total_length;
    mbuf->pkt_len = mbuf->data_len;

    return len;
}

uint32_t TcpOptions::Write(rte_mbuf* mbuf, rte_ipv4_hdr** ipv4_header, rte_tcp_hdr** tcp_header) const
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    size_t tcp_header_len_old = std::max(sizeof(rte_tcp_hdr), (size_t)((*tcp_header)->data_off >> 4) << 2);
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

void TcpOptions::Clear()
{
    timestamp_value = 0;
    timestamp_echo = 0;
    mss = 0;
    sack_permitted = false;
    window_scaling = 0;

    sack_count = 0;
    memset(sack_start, 0, sizeof(sack_start));
    memset(sack_finish, 0, sizeof(sack_finish));
}

eResult TcpConnectionStore::ActivateSocket(tSocketId socket_id, dataplane::memory_manager* memory_manager)
{
    std::lock_guard<std::mutex> guard(mutex_);

	auto iter = data_on_sockets_.find(socket_id);
	if (iter != data_on_sockets_.end())
	{
		return eResult::success;
	}

	ConnectionStoreOnSocket& store_on_socket = data_on_sockets_[socket_id];

#ifdef CONFIG_YADECAP_UNITTEST
    GCC_BUG_UNUSED(store_on_socket);
#else
    // check YANET_PROXY_SIZE_RTE_PROXY_RETRANSMITS is power of 2
    assert((YANET_PROXY_SIZE_RTE_PROXY_RETRANSMITS & (YANET_PROXY_SIZE_RTE_PROXY_RETRANSMITS - 1)) == 0);

	store_on_socket.ring_retransmit_free = rte_ring_create(("tcp_proxy.retransmits_free." + std::to_string(socket_id)).c_str(),
	                                                       YANET_PROXY_SIZE_RTE_PROXY_RETRANSMITS,
	                                                       socket_id,
	                                                       RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (!store_on_socket.ring_retransmit_free)
	{
        YANET_LOG_ERROR("Error create ring tcp_proxy.retransmits_free, errno: %d\n", rte_errno);
		return eResult::errorInitRing;
	}

	auto* data_for_retransmits = memory_manager->create_static_array<DataForRetransmit>(
	        "tcp_proxy.data_for_retransmits",
	        YANET_PROXY_SIZE_RTE_PROXY_RETRANSMITS - 1,
	        socket_id);
	if (!data_for_retransmits)
	{
        YANET_LOG_ERROR("Error create tcp_proxy.data_for_retransmits\n");
		return eResult::errorAllocatingMemory;
	}
	for (uint32_t index = 0; index < YANET_PROXY_SIZE_RTE_PROXY_RETRANSMITS - 1; index++)
	{
		rte_ring_sp_enqueue(store_on_socket.ring_retransmit_free, (void*)&data_for_retransmits[index]);
	}

	store_on_socket.ring_retransmit_send = rte_ring_create(("tcp_proxy.retransmits_send." + std::to_string(socket_id)).c_str(),
	                                                       YANET_PROXY_SIZE_RTE_PROXY_RETRANSMITS,
	                                                       socket_id,
	                                                       RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (!store_on_socket.ring_retransmit_send)
	{
        YANET_LOG_ERROR("Error create ring tcp_proxy.retransmits_send, errno: %d\n", rte_errno);
		return eResult::errorInitRing;
	}
#endif

	return eResult::success;
}

utils::StaticVector<std::pair<rte_ring*, rte_ring*>, 8> TcpConnectionStore::GetRetransmitRings()
{
    std::lock_guard<std::mutex> guard(mutex_);
    utils::StaticVector<std::pair<rte_ring*, rte_ring*>, 8> rings;

    for (const auto& iter_socket : data_on_sockets_)
    {
        const ConnectionStoreOnSocket& data_on_socket = iter_socket.second;
        if (rings.size() < rings.capacity())
        {
            rings.push_back(std::make_pair(data_on_socket.ring_retransmit_free, data_on_socket.ring_retransmit_send));
        }
    }

    return rings;
}

bool proxy_service_config_t::ReadConfig(const controlplane::proxy::service_t& service_info, tCounterId service_counter_id)
{
	service_id = service_info.service_id;
    socket_id = service_info.socket_id;
	counter_id = service_counter_id;
    proxy_flow = service_info.flow;

	// proxy and service address, port
	proxy_addr = ipv4_address_t::convert(service_info.proxy_addr.get_ipv4()).address;
	proxy_port = rte_cpu_to_be_16(service_info.proxy_port);
	upstream_addr = ipv4_address_t::convert(service_info.upstream_addr.get_ipv4()).address;
	upstream_port = rte_cpu_to_be_16(service_info.upstream_port);

	// pool_prefix
	if (service_info.upstream_nets.empty())
	{
		YADECAP_LOG_ERROR("upstream_nets empty'\n");
		return false;
	}
	pool_prefix.address = ipv4_address_t::convert(service_info.upstream_nets[0].address());
    pool_prefix.address.address = rte_be_to_cpu_32(pool_prefix.address.address);
    pool_prefix.mask = service_info.upstream_nets[0].mask();

	// sizes of tables
	size_connections_table = service_info.size_connections_table;
	size_syn_table = service_info.size_syn_table;

	send_proxy_header = service_info.send_proxy_header;

	// tcp options
	tcp_options = service_info.tcp_options;
	// temp - develop
	debug_flags = service_info.debug_flags;

	// timeouts
	timeouts.syn_rto = 1000 * service_info.timeouts.syn_rto;
	timeouts.syn_recv = 1000 * service_info.timeouts.syn_recv;
	timeouts.established = 1000 * service_info.timeouts.established;

    rate_limit = service_info.rate_limit;
    connection_limit = service_info.connection_limit;
    connection_limit.timeout = 1000 * connection_limit.timeout;

    return true;
}

eResult proxy_service_on_socket_t::UpdateFirstStage(dataplane::proxy::proxy_service_t& service, dataplane::memory_manager* memory_manager) {
    if (tables_tmp.NeedUpdate(service.config))
    {
        tables_tmp.ClearIfNotEqual(tables_work, memory_manager);
        tables_tmp.ClearLinks();
        eResult result = tables_tmp.Allocate(memory_manager, service.config);
        if (result != eResult::success)
        {
            return result;
        }
    }
    service.tables.CopyFrom(tables_tmp);

    if (service.config.rate_limit.size > 0)
    {
        if (tables_tmp.rate_limit.NeedReallocate(service.config.rate_limit.size))
        {
            tables_tmp.rate_limit.ClearIfNotEqual(tables_work.rate_limit, memory_manager);
            tables_tmp.rate_limit.ClearLinks();
            if (!tables_tmp.rate_limit.Init(service.config.rate_limit.mode, service.config.rate_limit.size, service.config.rate_limit.rate, service.config.rate_limit.burst,
                                           memory_manager, service.config.socket_id, "tcp_proxy.rate_limit." + std::to_string(service.config.service_id) + ".socket." + std::to_string(service.config.socket_id)))
            {
                YANET_LOG_ERROR("Error initialization TcpProxy.RateLimit, service: %d\n", service.config.service_id);
                return eResult::errorAllocatingMemory;
            }
        }
        tables_tmp.rate_limit.Update(service.config.rate_limit.rate, service.config.rate_limit.burst);
        service.rate_limit_table.CopyFrom(tables_tmp.rate_limit);
    }
    else
    {
        tables_tmp.rate_limit.ClearLinks();
        service.rate_limit_table.CopyFrom(tables_tmp.rate_limit);
    }

    if (service.config.connection_limit.size > 0)
    {
        if (tables_tmp.connection_limit.NeedReallocate(service.config.connection_limit.size))
        {
            tables_tmp.connection_limit.ClearIfNotEqual(tables_work.connection_limit, memory_manager);
            tables_tmp.connection_limit.ClearLinks();
            if (!tables_tmp.connection_limit.Init(service.config.connection_limit.mode, service.config.connection_limit.size, service.config.connection_limit.timeout,
                                                 memory_manager, service.config.socket_id, "tcp_proxy.connection_limit." + std::to_string(service.config.service_id) + ".socket." + std::to_string(service.config.socket_id)))
            {
                YANET_LOG_ERROR("Error initialization TcpProxy.ConnectionLimit, service: %d\n", service.config.service_id);
                return eResult::errorAllocatingMemory;
            }
        }
        tables_tmp.connection_limit.Update(service.config.connection_limit.timeout);
        service.connection_limit_table.CopyFrom(tables_tmp.connection_limit);
    }
    else
    {
        tables_tmp.connection_limit.ClearLinks();
        service.connection_limit_table.CopyFrom(tables_tmp.connection_limit);
    }

    config = service.config;
    enabled = true;

    return eResult::success;
}

void proxy_service_on_socket_t::UpdateSecondStage(dataplane::proxy::proxy_service_t& service, dataplane::memory_manager* memory_manager)
{
    tables_work.ClearIfNotEqual(tables_tmp, memory_manager);
    tables_work.CopyFrom(tables_tmp);
	service.tables.CopyFrom(tables_work);

    tables_work.rate_limit.ClearIfNotEqual(tables_tmp.rate_limit, memory_manager);
    tables_work.rate_limit.CopyFrom(tables_tmp.rate_limit);
    service.rate_limit_table.CopyFrom(tables_work.rate_limit);

    tables_work.connection_limit.ClearIfNotEqual(tables_tmp.connection_limit, memory_manager);
    tables_work.connection_limit.CopyFrom(tables_tmp.connection_limit);
    service.connection_limit_table.CopyFrom(tables_work.connection_limit);
}

eResult TcpConnectionStore::ServiceUpdateOnSocket(dataplane::proxy::proxy_service_t& service, bool first_state_update_global_base, dataplane::memory_manager* memory_manager)
{
	auto iter_data_on_socket = data_on_sockets_.find(service.config.socket_id);
	if (iter_data_on_socket == data_on_sockets_.end())
	{
		YADECAP_LOG_ERROR("not found proxy service config for socketId: '%u' in ServiceUpdateOnSocket\n", service.config.socket_id);
		return eResult::invalidId;
	}

    dataplane::proxy::proxy_service_on_socket_t& service_on_socket = iter_data_on_socket->second.proxy_services[service.config.service_id];
	std::unique_lock lock(service_on_socket.mutex);
    // YANET_LOG_WARNING("\tservice_main service_connections: %p\n", &service_on_socket.tables.service_connections);

	// initialize proxy header structure
	service.UpdateProxyHeader();

    // Update tables
	if (first_state_update_global_base)
	{
        return service_on_socket.UpdateFirstStage(service, memory_manager);
	}
	else
	{
		service_on_socket.UpdateSecondStage(service, memory_manager);
    	return eResult::success;
	}
}

void TcpConnectionStore::ServiceRemoveOnSocket(dataplane::proxy::proxy_service_t& service, bool first_state_update_global_base, dataplane::memory_manager* memory_manager)
{
    auto iter_data_on_socket = data_on_sockets_.find(service.config.socket_id);
	if (iter_data_on_socket == data_on_sockets_.end())
	{
		YADECAP_LOG_ERROR("not found proxy service config for socketId: '%u' in ServiceRemoveOnSocket\n", service.config.socket_id);
		return;
	}

    service.tables.ClearLinks();

	dataplane::proxy::proxy_service_on_socket_t& service_on_socket = iter_data_on_socket->second.proxy_services[service.config.service_id];
	std::unique_lock lock(service_on_socket.mutex);

    service_on_socket.enabled = false;
    if (first_state_update_global_base)
    {
        service_on_socket.tables_tmp.ClearIfNotEqual(service_on_socket.tables_work, memory_manager);
    }
    else
    {
        service_on_socket.tables_work.Clear(memory_manager);
    }
}

void TcpConnectionStore::ClearAllServices(dataplane::memory_manager* memory_manager)
{
    for (proxy_service_id_t service_id = 0; service_id <= YANET_CONFIG_PROXY_SERVICES_SIZE; service_id++)
    {
        for (auto& iter_data_on_socket : data_on_sockets_)
        {
            dataplane::proxy::proxy_service_on_socket_t& service_on_socket = iter_data_on_socket.second.proxy_services[service_id];
            std::unique_lock lock(service_on_socket.mutex);
            service_on_socket.tables_work.ClearLinks();
            service_on_socket.tables_tmp.ClearLinks();
        }
    }
}

void TcpConnectionStore::CollectGarbage(dataplane::proxy::WorkerGCInfo& worker_gc_info)
{
    // YANET_LOG_WARNING("TcpConnectionStore::CollectGarbage: current_time=%d\n", current_time);
    auto iter_data_on_socket = data_on_sockets_.find(worker_gc_info.socket_id);
	if (iter_data_on_socket == data_on_sockets_.end())
	{
		YADECAP_LOG_ERROR("not found proxy service config for socketId: '%u' in CollectGarbage\n", worker_gc_info.socket_id);
		return;
	}
    ConnectionStoreOnSocket& data_on_socket = iter_data_on_socket->second;

    bool was_overflow_ring_retransmit = false;
    for (proxy_service_id_t index = 0; index <= YANET_CONFIG_PROXY_SERVICES_SIZE; index++)
    {
        proxy_service_on_socket_t& service = data_on_socket.proxy_services[index];
        if (!service.enabled) continue;
        if (service.mutex.try_lock())
        {
            {
                // Clear in table Connections
                uint64_t time_to_clear = worker_gc_info.current_time_ms - service.config.timeouts.established;
                auto condition = [time_to_clear] (uint32_t address, tPortId port, uint64_t last_time, const Connection& connection) {
                    return (last_time < time_to_clear) || ((connection.service_flags & TCP_RST_FLAG) != 0);
                };

                auto action = [&service](uint32_t conn_idx, auto& bucket) {
                    service.tables_work.local_pool.Free(LocalPool::max_workers, bucket.connections[conn_idx].local);
                    bucket.Clear(conn_idx);
                };

                service.tables_work.service_connections.ProcessAllConnectionsWithLocking(condition, action);
            }

            {
                // Clear in table SynConnections
                uint64_t time_to_clear = worker_gc_info.current_time_ms - service.config.timeouts.syn_recv;
                auto condition = [time_to_clear] (uint32_t address, tPortId port, uint64_t last_time, const SynConnection& connection) {
                    return last_time < time_to_clear;
                };

                auto action = [&service](uint32_t conn_idx, auto& bucket) {
                    service.tables_work.local_pool.Free(LocalPool::max_workers, bucket.connections[conn_idx].local);
                    bucket.Clear(conn_idx);
                };

                service.tables_work.syn_connections.ProcessAllConnectionsWithLocking(condition, action);
            }

            if (service.tables_work.rate_limit.Mode() != common::proxy::limit_mode::off)
            {
                // Work RateLimit
                uint64_t time_to_clear = worker_gc_info.current_time_ms - RateLimitTable::timeout_ms;
                auto condition = [time_to_clear] (uint32_t address, uint64_t last_time) {
                    return last_time < time_to_clear;
                };

                auto action = [&service](uint32_t conn_idx, auto& bucket) {
                    bucket.Clear(conn_idx);
                };

                service.tables_work.rate_limit.ProcessAllConnectionsWithLocking(condition, action);
            }

            if (service.tables_work.connection_limit.Mode() != common::proxy::limit_mode::off)
            {
                // Work ConnectionLimit
                for (auto& iter : service.tables_work.connection_limit.GC(0, service.config.connection_limit.size))
                {
                    iter.lock();
                    if (!iter.is_valid())
                    {
                        iter.unlock();
                        continue;
                    }
    
                    if (*iter.value() < worker_gc_info.current_time_ms)
                    {
                        iter.unset_valid();
                        worker_gc_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::connection_limiter_remove]++;
                    }
    
                    iter.unlock();
                }
            }

            constexpr static uint32_t whitelist_bit = 1u << 31;
            std::string name = "tcp_proxy.gc.count_connections." + std::to_string(service.config.service_id) + ".socket." + std::to_string(service.config.socket_id);
            if(service.connection_counter.Init(worker_gc_info.memory_manager, name, worker_gc_info.socket_id, service.config.size_connections_table))
            {
                auto count_connections = [&service](uint32_t address, tPortId port, uint64_t last_time, const Connection& connection) {
                    uint32_t init_value = whitelist_bit * connection.FlagEnabled(Connection::flag_whitelist) + 1;
                    service.connection_counter.Add(address, init_value);
                };
                service.tables_work.service_connections.ProcessAllConnectionsWithoutLocking(count_connections);
    
                std::array<uint32_t, common::proxy::conn_count_tresholds.size() + 1> counts{};
                uint32_t max_count{};
                service.connection_counter.ForEach([&service, &max_count, &counts, &worker_gc_info](uint32_t address, uint32_t count) {
                    if (count & whitelist_bit) return;
                    count = count & ~whitelist_bit;
                    if (service.tables_work.connection_limit.Mode() != common::proxy::limit_mode::off
                        && count >= service.config.connection_limit.limit)
                    {
                        if(service.tables_work.connection_limit.Add(address, worker_gc_info.current_time_ms))
                            worker_gc_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::connection_limiter_new]++;
                        else
                            worker_gc_info.counters[service.config.counter_id + (tCounterId)::proxy::service_counter::connection_limiter_overflow]++;
                    }
    
                    if (max_count < count) max_count = count;
                    for (uint32_t i = 0; i < common::proxy::conn_count_tresholds.size(); i++)
                    {
                        if (count < common::proxy::conn_count_tresholds[i])
                        {
                            counts[i]++;
                            break;
                        }
                    }
                    if (count >= common::proxy::conn_count_tresholds[common::proxy::conn_count_tresholds.size()-1])
                        counts[common::proxy::conn_count_tresholds.size()]++;
                });
                service.tables_work.connection_limit.AddConnCountStats(counts, max_count, worker_gc_info.current_time_ms);
                service.connection_counter.Clear();
            }

            if (!was_overflow_ring_retransmit && index >= worker_gc_info.start_proxy_retransmit_service)
            {
                // Check retransmits
                uint64_t time_to_retransmit = worker_gc_info.current_time_ms - service.config.timeouts.syn_rto;
                auto condition = [time_to_retransmit, was_overflow_ring_retransmit] (uint32_t address, tPortId port, uint64_t last_time, const Connection& connection) {
                    return !was_overflow_ring_retransmit && (last_time < time_to_retransmit) && connection.NeedRetransmit();
                };

                auto action = [&data_on_socket, &service, &was_overflow_ring_retransmit](uint32_t conn_idx, auto& bucket) {
                    Connection& connection = bucket.connections[conn_idx];

                    // Get free structure for data retransmit
                    DataForRetransmit* data;
                    if (rte_ring_dequeue(data_on_socket.ring_retransmit_free, (void**)&data) != 0)
                    {
                        was_overflow_ring_retransmit = true;
                        return;
                    }

                    // Fill data for retransmit
                    TcpOptions tcp_options = SynCookies::UnpackData(connection.cookie_data);
                    tcp_options.timestamp_value = connection.timestamp_client_last;
                    tcp_options.timestamp_echo = 0;
                    data->tcp_options_len = tcp_options.WriteBuffer(data->tcp_options_data);

                    #if TCP_PROXY_FULL_DEBUG == 1
                    YANET_LOG_WARNING("Add to retransmit, cookie_data=%d, tcp_options=%s, flags=%u\n", connection.cookie_data, tcp_options.DebugInfo().c_str(), connection.flags);
                    #endif

                    data->service_id = service.config.service_id;
                    ServiceConnections::Unpack(connection.local, data->src, data->sport);
                    data->dst = service.config.upstream_addr;
                    data->dport = service.config.upstream_port;
                    data->client_start_seq = connection.client_start_seq;
                    data->flow = service.config.proxy_flow;
                    data->counter_id = service.config.counter_id + (tCounterId)::proxy::service_counter::syn_retransmits_count;

                    // Enqueue data to ring
                    if (rte_ring_enqueue(data_on_socket.ring_retransmit_send, (void*)data) != 0)
                    {
                        was_overflow_ring_retransmit = true;
                        return;
                    }

                    bucket.connections[conn_idx].SetSentRetransmit();
                };

                service.tables_work.service_connections.ProcessAllConnectionsWithLocking(condition, action);
                if (was_overflow_ring_retransmit)
                {
                    worker_gc_info.start_proxy_retransmit_service = index;
                }
            }

            service.mutex.unlock();
        }
    }

    if (!was_overflow_ring_retransmit)
    {
        worker_gc_info.start_proxy_retransmit_service = 0;
    }
}

// Info

common::idp::proxy_connections::response TcpConnectionStore::GetConnections(proxy_service_id_t service_id, std::optional<common::ipv4_prefix_t> client_prefix)
{
    common::idp::proxy_connections::response response;
    if (service_id <= YANET_CONFIG_PROXY_SERVICES_SIZE)
    {
        for (auto& [socket_id, data_on_socket] : data_on_sockets_)
        {
            proxy_service_on_socket_t& service = data_on_socket.proxy_services[service_id];
            std::shared_lock lock(service.mutex);
            
            auto get_connections = [&response, socket_id, &client_prefix] (uint32_t address, tPortId port, uint64_t last_time, const Connection& connection) {
                uint32_t local_addr;
                uint16_t local_port;
                ServiceConnections::Unpack(connection.local, local_addr, local_port);
                if (!client_prefix.has_value() || client_prefix->subnetFor(rte_cpu_to_be_32(address)))
                {
                    response.emplace_back(address, port, local_addr, local_port, socket_id);
                }
            };

            service.tables_work.service_connections.ProcessAllConnectionsWithoutLocking(get_connections);
        }
    }
    return response;
}

common::idp::proxy_syn::response TcpConnectionStore::GetSyn(proxy_service_id_t service_id, std::optional<common::ipv4_prefix_t> client_prefix)
{
    common::idp::proxy_syn::response response;
    if (service_id <= YANET_CONFIG_PROXY_SERVICES_SIZE)
    {
        for (auto& [socket_id, data_on_socket] : data_on_sockets_)
        {
            proxy_service_on_socket_t& service = data_on_socket.proxy_services[service_id];
            std::shared_lock lock(service.mutex);

            auto get_connections = [&response, socket_id, &client_prefix] (uint32_t address, tPortId port, uint64_t last_time, const SynConnection& connection) {
                uint32_t local_addr;
                uint16_t local_port;
                ServiceConnections::Unpack(connection.local, local_addr, local_port);
                if (!client_prefix.has_value() || client_prefix->subnetFor(rte_cpu_to_be_32(address)))
                {
                    response.emplace_back(address, port, local_addr, local_port, socket_id);
                }
            };

            service.tables_work.syn_connections.ProcessAllConnectionsWithoutLocking(get_connections);
        }
    }
    return response;
}

common::idp::proxy_tables::response TcpConnectionStore::GetTables(const common::idp::proxy_tables::request& services)
{
    common::idp::proxy_tables::response response;

    for (const auto& service_info : services)
    {
        if (service_info.service_id <= YANET_CONFIG_PROXY_SERVICES_SIZE)
        {
            for (auto& [service_socket_id, data_on_socket] : data_on_sockets_)
            {
                if (service_socket_id == service_info.socket_id)
                {
                    proxy_service_on_socket_t& service = data_on_socket.proxy_services[service_info.service_id];
                    std::shared_lock lock(service.mutex);
                    const ProxyTables& current = service.tables_work;

                    common::proxy::AllTablesInfo info;
                    info.header = service_info;

                    current.service_connections.FillStat(info.connections);
                    current.syn_connections.FillStat(info.syn_connections);

                    LocalPoolStat stat = current.local_pool.GetStat();
                    info.local_pool.size = stat.total_addresses;
                    info.local_pool.count = stat.used_addresses;

                    current.rate_limit.FillStat(info.rate_limiter);
                    current.connection_limit.FillStat(info.connection_limiter);

                    response.push_back(info);
                }
            }
        }
    }

    return response;
}

common::idp::proxy_buckets::response TcpConnectionStore::GetBuckets(const common::idp::proxy_buckets::request& services)
{
    common::idp::proxy_buckets::response response;

    for (const auto& service_info : services)
    {
        if (service_info.service_id <= YANET_CONFIG_PROXY_SERVICES_SIZE)
        {
            for (auto& [service_socket_id, data_on_socket] : data_on_sockets_)
            {
                if (service_socket_id == service_info.socket_id)
                {
                    proxy_service_on_socket_t& service = data_on_socket.proxy_services[service_info.service_id];
                    std::shared_lock lock(service.mutex);
                    const ProxyTables& current = service.tables_work;

                    response.push_back({service_info, "connections", current.service_connections.BucketsStat()});
                    response.push_back({service_info, "syn_connections", current.syn_connections.BucketsStat()});
                    response.push_back({service_info, "rate_limit", current.rate_limit.BucketsStat()});
                    response.push_back({service_info, "connection_limit", current.connection_limit.BucketsStat()});
                }
            }
        }
    }

    return response;
}

common::idp::proxy_bins::response TcpConnectionStore::GetConnCountBins(const common::idp::proxy_bins::request& services)
{
    common::idp::proxy_bins::response response;

    for (const auto& service_info : services)
    {
        if (service_info.service_id <= YANET_CONFIG_PROXY_SERVICES_SIZE)
        {
            for (auto& [service_socket_id, data_on_socket] : data_on_sockets_)
            {
                if (service_socket_id == service_info.socket_id)
                {
                    proxy_service_on_socket_t& service = data_on_socket.proxy_services[service_info.service_id];
                    std::shared_lock lock(service.mutex);

                    common::proxy::ConnCountInfo info = service.tables_work.connection_limit.GetConnCountStats();
                    info.header = service_info;
                    response.push_back(info);
                }
            }
        }
    }

    return response;
}

common::idp::proxy_blacklist::response TcpConnectionStore::GetBlacklist(proxy_service_id_t service_id)
{
    common::idp::proxy_blacklist::response response;
    if (service_id <= YANET_CONFIG_PROXY_SERVICES_SIZE)
    {
        for (auto& [socket_id, data_on_socket] : data_on_sockets_)
        {
            proxy_service_on_socket_t& service = data_on_socket.proxy_services[service_id];
            if (service.config.connection_limit.size == 0) continue;
            std::shared_lock lock(service.mutex);

            for (auto& iter : service.tables_work.connection_limit.Range(0, service.config.connection_limit.size))
            {
                if (!iter.is_valid()) continue;
                response.emplace_back(common::ipv4_address_t(rte_be_to_cpu_32(*iter.key())).toString(), *iter.value());
            }
        }
    }
    return response;
}

common::idp::proxy_blacklist_add::response TcpConnectionStore::AddBlacklist(proxy_service_id_t service_id, const std::string& address, uint32_t timeout)
{
    common::ipv4_address_t address_ipv4(address);
    uint32_t address_be = rte_cpu_to_be_32(address_ipv4);
    uint64_t current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    common::idp::proxy_blacklist_add::response response;
    if (service_id <= YANET_CONFIG_PROXY_SERVICES_SIZE)
    {
        for (auto& [socket_id, data_on_socket] : data_on_sockets_)
        {
            proxy_service_on_socket_t& service = data_on_socket.proxy_services[service_id];
            if (service.config.connection_limit.size == 0) continue;
            std::unique_lock lock(service.mutex);
            if(!service.tables_work.connection_limit.Add(address_be, current_time_ms, (uint64_t)timeout * 1000))
            {
                YANET_LOG_ERROR("Failed to add address to blacklist\n");
            }
        }
    }
    return response;
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

bool NonEmptyTcpData(rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    size_t tcp_header_len = (tcp_header->data_off >> 4) << 2;
    return (rte_be_to_cpu_16(ipv4_header->total_length) != sizeof(rte_ipv4_hdr) + tcp_header_len);
}

uint32_t CheckSumBeforeUpdate(rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header)
{
    uint32_t chksum_work = tcp_header->cksum + rte_ipv4_phdr_cksum(ipv4_header, 0);
    tcp_header->cksum = 0;
    chksum_work += rte_raw_cksum(tcp_header, (tcp_header->data_off >> 4) << 2);
    return chksum_work;
}

void CheckSumAfterUpdate(const dataplane::proxy::proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header, uint32_t chksum_work, uint32_t size_data)
{
    if ((service.config.debug_flags & proxy_service_config_t::flag_ignore_optimize_checksum) != 0)
    {
        UpdateCheckSums(ipv4_header, tcp_header);
        return;
    }

    ipv4_header->hdr_checksum = 0;
    ipv4_header->hdr_checksum = rte_ipv4_cksum(ipv4_header);

    uint32_t chksum_plus = rte_ipv4_phdr_cksum(ipv4_header, 0) + rte_raw_cksum(tcp_header, ((tcp_header->data_off >> 4) << 2) + size_data);

    chksum_work = __rte_raw_cksum_reduce(chksum_work);
    chksum_plus = __rte_raw_cksum_reduce(chksum_plus);
    uint16_t chksum = chksum_work - chksum_plus;
    if (chksum_work < chksum_plus)
    {
        chksum--;
    }

    tcp_header->cksum = chksum;
}

void PrepareSynAckToClient(const proxy_service_t& service,
                                            rte_mbuf* mbuf, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header, uint64_t* counters, uint32_t current_time_sec)
{
    TcpOptions tcp_options;
    memset(&tcp_options, 0, sizeof(tcp_options));
    if (!tcp_options.Read(tcp_header)) {
        counters[service.config.counter_id + (tCounterId)::proxy::service_counter::pkts_with_corrupted_tcp_opts_client]++;
        // DebugFullHeader(mbuf, "PrepareSynAckToClient");
    }
    tcp_options.sack_permitted &= service.config.tcp_options.use_sack;
    tcp_options.mss = std::min(tcp_options.mss, (uint16_t)service.config.tcp_options.mss);

    uint32_t cookie_data = SynCookies::PackData(tcp_options);
    uint32_t cookie = service.syn_cookie.GetCookie(ipv4_header->src_addr, tcp_header->src_port, tcp_header->sent_seq, cookie_data);
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
    tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);

    SwapAddresses(ipv4_header);
    ipv4_header->time_to_live = 64;
    tcp_header->recv_ack = add_cpu_32(tcp_header->sent_seq, 1);
    tcp_header->sent_seq = rte_cpu_to_be_32(cookie);
    tcp_header->tcp_flags = TCP_SYN_FLAG | TCP_ACK_FLAG;
    tcp_header->rx_win = 0;
    SwapPorts(tcp_header);
}

void PrepareSynToService(const proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header, uint64_t local)
{
    LocalPool::UnpackTupleSrc(local, ipv4_header, tcp_header);
    if (service.config.send_proxy_header)
    {
        // При использовании ProxyHeader уменьшаем значение SEQ полученное от клиента
        tcp_header->sent_seq = sub_cpu_32(tcp_header->sent_seq, sizeof(proxy_v2_ipv4_hdr));
    }

    ipv4_header->dst_addr = service.config.upstream_addr;
    tcp_header->dst_port = service.config.upstream_port;
}

// Action from worker
bool ActionClientOnSyn(rte_mbuf* mbuf, dataplane::proxy::WorkerInfo& worker_info)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
	
    proxy_service_id_t service_id = metadata->flow.data.proxy_service.id;
    dataplane::proxy::proxy_service_t& service = worker_info.globalBase->proxy_services[service_id];

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
                    ServiceConnectionData& service_connection_data,
                    uint32_t flags,
                    bool reuse_connection)
{
	// try check cookie
	// todo - check time overflow
	uint32_t cookie_data = CheckSynCookie(service, ipv4_header, tcp_header);
	if (cookie_data == 0)
	{
		DebugPacket("!CheckSynCookie", service_id, ipv4_header, tcp_header);

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
            DebugPacket("!local_pool.Allocate", service_id, ipv4_header, tcp_header);

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
    service_connection_data.connection->local = ServiceSynConnections::Pack(ipv4_header->src_addr, tcp_header->src_port);
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

bool ActionClientOnAck(rte_mbuf* mbuf, dataplane::proxy::WorkerInfo& worker_info)
{
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    proxy_service_id_t service_id = metadata->flow.data.proxy_service.id;
    dataplane::proxy::proxy_service_t& service = worker_info.globalBase->proxy_services[service_id];

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

bool ActionServiceOnSynAck(rte_mbuf* mbuf, dataplane::proxy::WorkerInfo& worker_info)
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

bool ActionServiceOnAck(rte_mbuf* mbuf, dataplane::proxy::WorkerInfo& worker_info)
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

bool ProxyTables::NeedUpdate(const proxy_service_config_t& service_config)
{
    // YANET_LOG_WARNING("NeedUpdate %d check: con=(%d, %ld), syn=(%d, %ld) need=(%d, %d, %d)\n", service_config.service_id,
    //     service_config.size_connections_table, service_connections.Capacity(), service_config.size_syn_table, syn_connections.Capacity(),
    //     service_connections.NeedUpdate(service_config.size_connections_table), syn_connections.NeedUpdate(service_config.size_syn_table), local_pool.NeedUpdate(service_config.pool_prefix));
    return service_connections.NeedUpdate(service_config.size_connections_table)
            || syn_connections.NeedUpdate(service_config.size_syn_table)
            || local_pool.NeedUpdate(service_config.pool_prefix);
}

void ProxyTables::ClearIfNotEqual(const ProxyTables& other, dataplane::memory_manager* memory_manager)
{
    service_connections.ClearIfNotEqual(other.service_connections, memory_manager);
    syn_connections.ClearIfNotEqual(other.syn_connections, memory_manager);
    local_pool.ClearIfNotEqual(other.local_pool, memory_manager);
}

eResult ProxyTables::Allocate(dataplane::memory_manager* memory_manager, const proxy_service_config_t& service_config)
{
    if (!service_connections.Init(service_config.service_id, service_config.size_connections_table, memory_manager, service_config.socket_id, "tcp_proxy.connections." + std::to_string(service_config.service_id) + ".socket." + std::to_string(service_config.socket_id)))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.ServiceConnections, service: %d\n", service_config.service_id);
        return eResult::errorAllocatingMemory;
    }

    if (!syn_connections.Init(service_config.service_id, service_config.size_syn_table, memory_manager, service_config.socket_id, "tcp_proxy.syn_connections." + std::to_string(service_config.service_id) + ".socket." + std::to_string(service_config.socket_id)))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.SynConnections, service: %d\n", service_config.service_id);
        return eResult::errorAllocatingMemory;
    }

    bool rotate_addresses_first = (service_config.debug_flags & proxy_service_config_t::flag_local_pool_rotate_addresses_second) == 0;
    if (!local_pool.Init(service_config.service_id, service_config.pool_prefix, memory_manager, service_config.socket_id, false, rotate_addresses_first))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.LocalPool, service: %d\n", service_config.service_id);
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

void ProxyTables::Clear(dataplane::memory_manager* memory_manager)
{
    service_connections.Clear(memory_manager);
    syn_connections.Clear(memory_manager);
    local_pool.Clear(memory_manager);
}

void proxy_service_t::Debug() const
{
    YANET_LOG_WARNING("service_id=%d, counter_id=%d, size_con=%d, size_syn=%d, proxy_header=%d, debug_flags=%ld\n", config.service_id, config.counter_id, config.size_connections_table, config.size_syn_table, config.send_proxy_header, config.debug_flags);
    YANET_LOG_WARNING("\tproxy=%s:%d, service=%s:%d, pool=%s\n",
        common::ipv4_address_t(rte_cpu_to_be_32(config.proxy_addr)).toString().c_str(), rte_cpu_to_be_16(config.proxy_port),
        common::ipv4_address_t(rte_cpu_to_be_32(config.upstream_addr)).toString().c_str(), rte_cpu_to_be_16(config.upstream_port),
        common::ipv4_prefix_t(config.pool_prefix.address.address, config.pool_prefix.mask).toString().c_str());
    config.tcp_options.Debug();
    config.timeouts.Debug();
	YANET_LOG_WARNING("\tservice=[%s], syn=[%s], local=[%s]\n", tables.service_connections.Debug().c_str(), tables.syn_connections.Debug().c_str(), tables.local_pool.Debug().c_str());
}

bool proxy_service_config_t::EnabledFlag(uint8_t flag) const
{
    return (debug_flags & flag) != 0;
}

void proxy_service_t::UpdateProxyHeader()
{
    proxy::proxy_v2_ipv4_hdr proxy_header_tmp;

	rte_memcpy(proxy_header_tmp.signature, dataplane::proxy::PROXY_V2_SIGNATURE, 12);
	proxy_header_tmp.version_cmd = (dataplane::proxy::PROXY_VERSION_V2 << 4) + dataplane::proxy::PROXY_CMD_LOCAL;
	proxy_header_tmp.af_proto = (dataplane::proxy::PROXY_AF_INET << 4) + dataplane::proxy::PROXY_PROTO_STREAM;
	proxy_header_tmp.addr_len = rte_cpu_to_be_16(4 + 4 + 4);
	proxy_header_tmp.dst_addr = config.proxy_addr;
	proxy_header_tmp.dst_port = config.proxy_port;

    rte_memcpy(proxy_header.signature, proxy_header_tmp.signature, sizeof(proxy::proxy_v2_ipv4_hdr));
}

}
