#include "local_pool.h"

namespace dataplane::proxy
{

void LocalPool::Add(proxy_id_t proxy_id, const ipv4_prefix_t& prefix)
{
    std::lock_guard<std::mutex> lock(mutex_);
    prefixes_[proxy_id].push_back(prefix);
}

std::optional<std::pair<uint32_t, tPortId>> LocalPool::Allocate(proxy_id_t proxy_id, proxy_service_id_t service_id, uint32_t client_addr, tPortId client_port)
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool queue_exists = connection_queues_.find(service_id) != connection_queues_.end();
    if (queue_exists && connection_queues_[service_id].empty()) 
    {
        return std::nullopt;
    }
    if (!queue_exists)
    {
        if (prefixes_.find(proxy_id) == prefixes_.end()) 
        {
            return std::nullopt;
        }
        connection_queues_[service_id] = make_connection_queue(proxy_id);
    }

    ConnectionInfo info = connection_queues_[service_id].front();
    connection_queues_[service_id].pop();

    local_to_clients_[{rte_cpu_to_be_32(info.address), rte_cpu_to_be_16(info.port)}] = {client_addr, client_port};

    return std::make_pair(rte_cpu_to_be_32(info.address), rte_cpu_to_be_16(info.port));
}

void LocalPool::Free(proxy_service_id_t service_id, uint32_t address, tPortId port)
{
    std::lock_guard<std::mutex> lock(mutex_);
    connection_queues_[service_id].push(ConnectionInfo{address, port});
}

std::queue<LocalPool::ConnectionInfo> LocalPool::make_connection_queue(proxy_id_t proxy_id)
{
	std::queue<ConnectionInfo> queue;
    for(const ipv4_prefix_t& prefix : prefixes_[proxy_id]) {
        for(uint32_t i = 1; i < (1u << (32u - prefix.mask)) - 1; i++) {
            for(uint16_t port = min_port; port < max_port; port++) {
                queue.push(ConnectionInfo{prefix.address.address + i, port});
            }
        }
    }
    return queue;
}

std::optional<std::pair<uint32_t, tPortId>> LocalPool::FindClientByLocal(uint32_t local_addr, tPortId local_port)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = local_to_clients_.find({local_addr, local_port});
    if (iter == local_to_clients_.end())
    {
        return std::nullopt;
    }
    return iter->second;
}

LocalPool2::LocalPool2(const ipv4_prefix_t& prefix) 
    : prefix_(prefix),
    connection_queue_(((1u << (32u - prefix_.mask)) - 2) * num_ports),
    first_connection_idx_(0)
{
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
    connection_queue_[connection_queue_.size() - 1].next_idx = 0xffffffff;
}

std::optional<std::pair<uint32_t, tPortId>> LocalPool2::Allocate(uint32_t client_addr, tPortId client_port)
{
    std::lock_guard<std::shared_mutex> lock(mutex_);
    if (first_connection_idx_ == 0xffffffff)
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

void LocalPool2::Free(uint32_t address, tPortId port)
{
    std::lock_guard<std::shared_mutex> lock(mutex_);
    uint32_t idx = tuple_to_index(address, port);
    if (unlikely(idx > connection_queue_.size() - 1))
    {
        return;
    }

    ConnectionInfo& info = connection_queue_[idx];
    info.is_used = 0;
    info.next_idx = first_connection_idx_;
    first_connection_idx_ = idx;
}

std::optional<std::pair<uint32_t, tPortId>> LocalPool2::FindClientByLocal(uint32_t local_addr, tPortId local_port)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    uint32_t idx = tuple_to_index(local_addr, local_port);
    if (unlikely(idx > connection_queue_.size() - 1))
    {
        return std::nullopt;
    }

    ConnectionInfo& info = connection_queue_[idx];
    if (info.is_used == 0)
    {
        return std::nullopt;
    }
    return std::make_pair(info.address, info.port);
}

inline std::pair<uint32_t, tPortId> LocalPool2::index_to_tuple(uint32_t index)
{
    return std::make_pair(
        prefix_.address.address + 1 + index / num_ports,
        index % num_ports + min_port
    );
}

inline uint32_t LocalPool2::tuple_to_index(uint32_t address, tPortId port)
{
    return (port - min_port) + (address - prefix_.address.address - 1) * num_ports;
}

}