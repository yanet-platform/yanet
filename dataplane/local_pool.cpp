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

}
