#include "local_pool.h"

namespace dataplane::proxy
{

void LocalPool::Add(const ipv4_prefix_t& prefix)
{
    prefix_ = prefix;
}

bool LocalPool::Init(proxy_service_id_t service_id, dataplane::memory_manager* memory_manager)
{
    if (initialized_)
    {
        return true;
    }
    if (prefix_.mask == 0)
    {
        return false;
    }
    num_connections_ = ((1u << (32u - prefix_.mask)) - 2) * num_ports;

    tSocketId socket_id = 0; // todo !!!
    std::string name = "tcp_proxy.local_pools." + std::to_string(service_id);
    connection_queue_ = memory_manager->create_static_array<ConnectionInfo>(name.data(), num_connections_, socket_id);
    if (connection_queue_ == nullptr)
    {
        num_connections_ = 0;
        return false;
    }

    for(uint32_t i = 0; i < (1u << (32u - prefix_.mask)) - 2; i++)
    {
        for(uint16_t j = 0; j < num_ports; j++)
        {
            connection_queue_[i*num_ports + j] = ConnectionInfo{
                .is_used = 0,
                .next_idx = i * num_ports + j + 1
            };
        }
    }
    connection_queue_[num_connections_ - 1].next_idx = 0xffffffff;

    initialized_ = true;

    return true;
}

bool LocalPool::_TestInit()
{
    if (initialized_)
    {
        return true;
    }
    if (prefix_.mask == 0)
    {
        return false;
    }
    num_connections_ = ((1u << (32u - prefix_.mask)) - 2) * num_ports;

    connection_queue_ = new ConnectionInfo[num_connections_];

    for(uint32_t i = 0; i < (1u << (32u - prefix_.mask)) - 2; i++)
    {
        for(uint16_t j = 0; j < num_ports; j++)
        {
            connection_queue_[i*num_ports + j] = ConnectionInfo{
                .is_used = 0,
                .next_idx = i * num_ports + j + 1
            };
        }
    }
    connection_queue_[num_connections_ - 1].next_idx = 0xffffffff;

    initialized_ = true;

    return true;
}

bool LocalPool::_TestFree()
{
    if (initialized_)
    {
        delete[] connection_queue_;
        initialized_ = false;
    }
    return true;
}

std::optional<std::pair<uint32_t, tPortId>> LocalPool::Allocate(uint32_t client_addr, tPortId client_port)
{
    std::lock_guard<std::shared_mutex> lock(mutex_);
    if (unlikely(!initialized_) || first_connection_idx_ == 0xffffffff)
    {
        return std::nullopt;
    }

    std::pair<uint32_t, tPortId> res = index_to_tuple(first_connection_idx_);
    res.first = rte_cpu_to_be_32(res.first);
    res.second = rte_cpu_to_be_16(res.second);
    
    ConnectionInfo& info = connection_queue_[first_connection_idx_];
    first_connection_idx_ = info.next_idx;

    info.is_used = 1;
    info.address = client_addr;
    info.port = client_port;

    return res;
}

void LocalPool::Free(uint32_t address, tPortId port)
{
    if (unlikely(!initialized_))
    {
        return;
    }
    std::lock_guard<std::shared_mutex> lock(mutex_);
    uint32_t idx = tuple_to_index(rte_be_to_cpu_32(address), rte_be_to_cpu_16(port));
    if (unlikely(idx > num_connections_ - 1))
    {
        return;
    }

    ConnectionInfo& info = connection_queue_[idx];
    info.is_used = 0;
    info.next_idx = first_connection_idx_;
    first_connection_idx_ = idx;
}

std::optional<std::pair<uint32_t, tPortId>> LocalPool::FindClientByLocal(uint32_t local_addr, tPortId local_port) const
{
    if (unlikely(!initialized_))
    {
        return std::nullopt;
    }
    local_addr = rte_be_to_cpu_32(local_addr);
    local_port = rte_be_to_cpu_16(local_port);
    std::shared_lock<std::shared_mutex> lock(mutex_);
    uint32_t idx = tuple_to_index(local_addr, local_port);
    if (unlikely(idx > num_connections_ - 1))
    {
        YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: out of range, local_addr=%s local_port=%d idx=%d num_connections_=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx, num_connections_);
        return std::nullopt;
    }

    const ConnectionInfo& info = connection_queue_[idx];
    if (info.is_used == 0)
    {
        YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: not used, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
        return std::nullopt;
    }
    YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: found, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
    return std::make_pair(info.address, info.port);
}

inline std::pair<uint32_t, tPortId> LocalPool::index_to_tuple(uint32_t index) const
{
    return std::make_pair(
        prefix_.address.address + 1 + index / num_ports,
        index % num_ports + min_port
    );
}

inline uint32_t LocalPool::tuple_to_index(uint32_t address, tPortId port) const
{
    return (port - min_port) + (address - prefix_.address.address - 1) * num_ports;
}

}