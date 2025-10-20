#include <sstream>

#include "common/counters.h"

#include "proxy.h"

namespace dataplane::proxy
{

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

bool proxy_service_config_t::ReadConfig(const controlplane::proxy::service_t& service_info, tCounterId service_counter_id, memory_manager* memory_manager)
{
	service_id = service_info.service_id;
    socket_id = service_info.socket_id;
	counter_id = service_counter_id;
    proxy_flow = service_info.flow;

    if (service_info.proxy_addr.is_ipv4())
        ip_ver = ProxyServiceIPVer::IPv4;
    else if (service_info.proxy_addr.is_ipv6())
        ip_ver = ProxyServiceIPVer::IPv6; 

	// proxy and service address, port
    if (ip_ver == ProxyServiceIPVer::IPv6)
    {
        ipv6_address_t addr = ipv6_address_t::convert(service_info.proxy_addr.get_ipv6());
        for (size_t i = 0, shift = 0; i < sizeof(proxy_addr6); i++, shift += 8)
            proxy_addr6 += (common::uint128_t)addr.bytes[i] << shift;
        addr = ipv6_address_t::convert(service_info.upstream_addr.get_ipv6());
        for (size_t i = 0, shift = 0; i < sizeof(proxy_addr6); i++, shift += 8)
            upstream_addr6 += (common::uint128_t)addr.bytes[i] << shift;
    }
    else
    {
        proxy_addr4 = ipv4_address_t::convert(service_info.proxy_addr.get_ipv4()).address;
        upstream_addr4 = ipv4_address_t::convert(service_info.upstream_addr.get_ipv4()).address;
    }
	proxy_port = rte_cpu_to_be_16(service_info.proxy_port);
	upstream_port = rte_cpu_to_be_16(service_info.upstream_port);

	// pool_prefix
	if (service_info.proxy_addr.is_ipv4() && service_info.ipv4_upstream_nets.empty())
	{
		YADECAP_LOG_ERROR("ipv4_upstream_nets empty\n");
		return false;
	}
    else if (service_info.proxy_addr.is_ipv6() && !service_info.ipv6_upstream_net.isValid())
	{
		YADECAP_LOG_ERROR("No IPv6 upstream net\n");
		return false;
	}

    ipv4_pool_prefixes = service_info.ipv4_upstream_nets;
    ipv6_pool_prefix = service_info.ipv6_upstream_net;
    if (ip_ver == ProxyServiceIPVer::IPv6)
    {
        // Making offset from base 96 bits
        pool_prefixes.clear();
        pool_prefixes.emplace_back(0, ipv6_pool_prefix.mask() - 96);
    }
    else
    {
        pool_prefixes = ipv4_pool_prefixes;
    }

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

                service.tables_work.service_connections4.ProcessAllConnectionsWithLocking(condition, action);
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

                service.tables_work.syn_connections4.ProcessAllConnectionsWithLocking(condition, action);
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
                service.tables_work.service_connections4.ProcessAllConnectionsWithoutLocking(count_connections);
    
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
                    LocalPool::UnpackTuple(connection.local, data->src, data->sport);
                    data->dst = service.config.upstream_addr4;
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

                service.tables_work.service_connections4.ProcessAllConnectionsWithLocking(condition, action);
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
                LocalPool::UnpackTuple(connection.local, local_addr, local_port);
                if (!client_prefix.has_value() || client_prefix->subnetFor(rte_cpu_to_be_32(address)))
                {
                    response.emplace_back(address, port, local_addr, local_port, socket_id);
                }
            };

            service.tables_work.service_connections4.ProcessAllConnectionsWithoutLocking(get_connections);
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
                LocalPool::UnpackTuple(connection.local, local_addr, local_port);
                if (!client_prefix.has_value() || client_prefix->subnetFor(rte_cpu_to_be_32(address)))
                {
                    response.emplace_back(address, port, local_addr, local_port, socket_id);
                }
            };

            service.tables_work.syn_connections4.ProcessAllConnectionsWithoutLocking(get_connections);
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

                    current.service_connections4.FillStat(info.connections);
                    current.syn_connections4.FillStat(info.syn_connections);

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

                    response.push_back({service_info, "connections", current.service_connections4.BucketsStat()});
                    response.push_back({service_info, "syn_connections", current.syn_connections4.BucketsStat()});
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

bool ProxyTables::NeedUpdate(const proxy_service_config_t& service_config)
{
    // YANET_LOG_WARNING("NeedUpdate %d check: con=(%d, %ld), syn=(%d, %ld) need=(%d, %d, %d)\n", service_config.service_id,
    //     service_config.size_connections_table, service_connections.Capacity(), service_config.size_syn_table, syn_connections.Capacity(),
    //     service_connections.NeedUpdate(service_config.size_connections_table), syn_connections.NeedUpdate(service_config.size_syn_table), local_pool.NeedUpdate(service_config.pool_prefixes));
    switch (service_config.ip_ver)
    {
    case ProxyServiceIPVer::IPv4:
        return service_connections4.NeedUpdate(service_config.size_connections_table)
                || syn_connections4.NeedUpdate(service_config.size_syn_table)
                || local_pool.NeedUpdate(service_config.pool_prefixes);
    case ProxyServiceIPVer::IPv6:
        return service_connections6.NeedUpdate(service_config.size_connections_table)
                || syn_connections6.NeedUpdate(service_config.size_syn_table)
                || local_pool.NeedUpdate(service_config.pool_prefixes);
    }
    return false;
}

void ProxyTables::ClearIfNotEqual(const ProxyTables& other, dataplane::memory_manager* memory_manager)
{
    service_connections4.ClearIfNotEqual(other.service_connections4, memory_manager);
    service_connections6.ClearIfNotEqual(other.service_connections6, memory_manager);
    syn_connections4.ClearIfNotEqual(other.syn_connections4, memory_manager);
    syn_connections6.ClearIfNotEqual(other.syn_connections6, memory_manager);
    local_pool.ClearIfNotEqual(other.local_pool, memory_manager);
}

eResult ProxyTables::Allocate(dataplane::memory_manager* memory_manager, const proxy_service_config_t& service_config)
{
    if (service_config.ip_ver == ProxyServiceIPVer::IPv4)
    {
        if (!service_connections4.Init(service_config.service_id, service_config.size_connections_table, memory_manager, service_config.socket_id, "tcp_proxy.connections." + std::to_string(service_config.service_id) + ".socket." + std::to_string(service_config.socket_id)))
        {
            YANET_LOG_ERROR("Error initialization TcpProxy.ServiceConnections, service: %d\n", service_config.service_id);
            return eResult::errorAllocatingMemory;
        }
        if (!syn_connections4.Init(service_config.service_id, service_config.size_syn_table, memory_manager, service_config.socket_id, "tcp_proxy.syn_connections." + std::to_string(service_config.service_id) + ".socket." + std::to_string(service_config.socket_id)))
        {
            YANET_LOG_ERROR("Error initialization TcpProxy.SynConnections, service: %d\n", service_config.service_id);
            return eResult::errorAllocatingMemory;
        }
    }
    else if (service_config.ip_ver == ProxyServiceIPVer::IPv6)
    {
        if (!service_connections6.Init(service_config.service_id, service_config.size_connections_table, memory_manager, service_config.socket_id, "tcp_proxy.connections6." + std::to_string(service_config.service_id) + ".socket." + std::to_string(service_config.socket_id)))
        {
            YANET_LOG_ERROR("Error initialization TcpProxy.ServiceConnections6, service: %d\n", service_config.service_id);
            return eResult::errorAllocatingMemory;
        }
        if (!syn_connections6.Init(service_config.service_id, service_config.size_syn_table, memory_manager, service_config.socket_id, "tcp_proxy.syn_connections6." + std::to_string(service_config.service_id) + ".socket." + std::to_string(service_config.socket_id)))
        {
            YANET_LOG_ERROR("Error initialization TcpProxy.SynConnections6, service: %d\n", service_config.service_id);
            return eResult::errorAllocatingMemory;
        }
    }

    bool rotate_addresses_first = (service_config.debug_flags & proxy_service_config_t::flag_local_pool_rotate_addresses_second) == 0;
    if (!local_pool.Init(service_config.service_id, service_config.pool_prefixes, memory_manager, service_config.socket_id, rotate_addresses_first))
    {
        YANET_LOG_ERROR("Error initialization TcpProxy.LocalPool, service: %d\n", service_config.service_id);
        return eResult::errorAllocatingMemory;
    }

    return eResult::success;
}

void ProxyTables::CopyFrom(const ProxyTables& other)
{
    service_connections4.CopyFrom(other.service_connections4);
    service_connections6.CopyFrom(other.service_connections6);
    syn_connections4.CopyFrom(other.syn_connections4);
    syn_connections6.CopyFrom(other.syn_connections6);
    local_pool.CopyFrom(other.local_pool);
}

void ProxyTables::ClearLinks()
{
    service_connections4.ClearLinks();
    service_connections6.ClearLinks();
    syn_connections4.ClearLinks();
    syn_connections6.ClearLinks();
    local_pool.ClearLinks();
}

void ProxyTables::Clear(dataplane::memory_manager* memory_manager)
{
    service_connections4.Clear(memory_manager);
    service_connections6.Clear(memory_manager);
    syn_connections4.Clear(memory_manager);
    syn_connections6.Clear(memory_manager);
    local_pool.Clear(memory_manager);
}

void proxy_service_t::Debug() const
{
    YANET_LOG_WARNING("service_id=%d, counter_id=%d, size_con=%d, size_syn=%d, proxy_header=%d, debug_flags=%ld\n", config.service_id, config.counter_id, config.size_connections_table, config.size_syn_table, config.send_proxy_header, config.debug_flags);
    std::stringstream ss;
    for (uint32_t i = 0; i < config.pool_prefixes.size(); i++)
    {
        ss << config.pool_prefixes[i].toString().c_str();
        if (i < config.pool_prefixes.size() - 1) ss << ", ";
    }
    YANET_LOG_WARNING("\tproxy4=%s:%u, proxy6=%s:%u, service4=%s:%u, service6=%s:%u, pool=[%s]\n",
        common::ipv4_address_t(rte_cpu_to_be_32(config.proxy_addr4)).toString().c_str(), rte_cpu_to_be_16(config.proxy_port),
        common::ipv6_address_t(config.proxy_addr6).toString().c_str(), rte_cpu_to_be_16(config.proxy_port),
        common::ipv4_address_t(rte_cpu_to_be_32(config.upstream_addr4)).toString().c_str(), rte_cpu_to_be_16(config.upstream_port),
        common::ipv6_address_t(config.upstream_addr6).toString().c_str(), rte_cpu_to_be_16(config.upstream_port),
        ss.str().c_str());
    config.tcp_options.Debug();
    config.timeouts.Debug();
	YANET_LOG_WARNING("\tservice=[%s], syn=[%s], local=[%s]\n", tables.service_connections4.Debug().c_str(), tables.syn_connections4.Debug().c_str(), tables.local_pool.Debug().c_str());
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
	proxy_header_tmp.dst_addr = config.proxy_addr4;
	proxy_header_tmp.dst_port = config.proxy_port;

    rte_memcpy(proxy_header.signature, proxy_header_tmp.signature, sizeof(proxy::proxy_v2_ipv4_hdr));
}

}
