#include "local_pool.h"

namespace dataplane::proxy
{

bool LocalPool::Init(proxy_service_id_t service_id, const ipv4_prefix_t& prefix, dataplane::memory_manager* memory_manager)
{
    if (initialized_)
    {
        return true;
    }
    if (prefix.mask == 0)
    {
        return false;
    }
    prefix_ = prefix;

    num_connections_ = ((1u << (32u - prefix_.mask)) - 2) * num_ports;

    tSocketId socket_id = 0; // todo !!!
    std::string name = "tcp_proxy.local_pools." + std::to_string(service_id);
    if (memory_manager != nullptr)
    {
        connection_queue_ = memory_manager->create_static_array<ConnectionInfo>(name.data(), num_connections_, socket_id);
    }
    else
    {
        connection_queue_ = (ConnectionInfo*)malloc(num_connections_ * sizeof(ConnectionInfo));
    }
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

    first_ = 0;
    last_ = num_connections_ - 1;
    free_addresses_ = num_connections_;
    used_addresses_ = 0;

    initialized_ = true;

    return true;
}

bool LocalPool::_TestInit(const ipv4_prefix_t& prefix)
{
    if (initialized_)
    {
        return true;
    }
    if (prefix.mask == 0)
    {
        return false;
    }
    prefix_ = prefix;

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

    first_ = 0;
    last_ = num_connections_ - 1;
    free_addresses_ = num_connections_;
    used_addresses_ = 0;

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

uint64_t LocalPool::Allocate(uint32_t worker_id, uint32_t client_addr, tPortId client_port)
{
    while(!mutex_.try_lock());
    if (unlikely(!initialized_) || first_ == 0xffffffff)
    {
        mutex_.unlock();
        return 0;
    }

    uint64_t res = index_to_tuple(first_);
    
    ConnectionInfo& info = connection_queue_[first_];
    first_ = info.next_idx;
    if (first_ == 0xffffffff)
        last_ = 0xffffffff;

    info.is_used = 1;
    info.address = client_addr;
    info.port = client_port;

    free_addresses_--;
    used_addresses_++;

    mutex_.unlock();
    return res;
}

void LocalPool::Free(uint32_t worker_id, uint64_t tuple)
{
    if (unlikely(!initialized_))
    {
        return;
    }
    while(!mutex_.try_lock());

    uint32_t idx = tuple_to_index(tuple);
    if (unlikely(idx > num_connections_ - 1))
    {
        mutex_.unlock();
        return;
    }

    if (last_ != 0xffffffff)
        connection_queue_[last_].next_idx = idx;
    last_ = idx;
    if (first_ == 0xffffffff)
        first_ = idx;

    ConnectionInfo& info = connection_queue_[last_];
    info.is_used = 0;
    info.next_idx = 0xffffffff;

    free_addresses_++;
    used_addresses_--;

    mutex_.unlock();
}

uint64_t LocalPool::FindClientByLocal(uint32_t local_addr, tPortId local_port) const
{
    if (unlikely(!initialized_))
    {
        return 0;
    }
    while(!mutex_.try_lock_shared());

    uint32_t idx = tuple_to_index(PackTuple(local_addr, local_port));
    local_addr = rte_be_to_cpu_32(local_addr);
    local_port = rte_be_to_cpu_16(local_port);
    if (unlikely(idx > num_connections_ - 1))
    {
        mutex_.unlock();
        // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: out of range, local_addr=%s local_port=%d idx=%d num_connections_=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx, num_connections_);
        return 0;
    }

    const ConnectionInfo& info = connection_queue_[idx];
    if (info.is_used == 0)
    {
        mutex_.unlock();
        // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: not used, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
        return 0;
    }

    mutex_.unlock();
    // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: found, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
    return PackTuple(info.address, info.port);
}

void LocalPool::GetLocalPool(proxy_service_id_t service_id, common::idp::proxy_local_pool::response& response) const {
    if (unlikely(!initialized_))
    {
        return;
    }

    response.emplace_back(service_id, common::ipv4_prefix_t{prefix_.address.address, prefix_.mask}, num_connections_, free_addresses_, used_addresses_);
}

inline uint64_t LocalPool::index_to_tuple(uint32_t index) const
{
    return PackTuple(rte_cpu_to_be_32(prefix_.address.address + 1 + index / num_ports),
                     rte_cpu_to_be_16(index % num_ports + min_port));
}

inline uint32_t LocalPool::tuple_to_index(uint64_t tuple) const
{
    return (rte_be_to_cpu_16((uint16_t)(tuple & 0xffff)) - min_port) + 
           (rte_be_to_cpu_32((uint32_t)(tuple >> 16)) - prefix_.address.address - 1) * num_ports;
}

LocalPool2::LocalPool2() 
    : initialized_(false)
{}

bool LocalPool2::Init(proxy_service_id_t service_id, const ipv4_prefix_t& prefix, dataplane::memory_manager* memory_manager)
{
    if (initialized_)
    {
        return true;
    }
    if (prefix.mask == 0)
    {
        return false;
    }
    prefix_ = prefix;

    uint32_t num_connections = ((1u << (32u - prefix_.mask)) - 2) * num_ports;
    num_free_chunks_ = max_workers * 2;
    num_chunks_ = num_connections / chunk_size;
    
    tSocketId socket_id = 0; // todo !!!
    std::string name = "tcp_proxy.local_pools." + std::to_string(service_id);
    chunk_queue_ = memory_manager->create_static_array<ConnectionsChunk>(name.data(), num_free_chunks_ + num_chunks_, socket_id);
    if (chunk_queue_ == nullptr)
    {
        num_chunks_ = 0;
        return false;
    }
    name = "tcp_proxy.local_pools." + std::to_string(service_id) + ".local_to_client";
    local_to_client_ = memory_manager->create_static_array<uint64_t>(name.data(), num_chunks_ * chunk_size, socket_id);
    if (local_to_client_ == nullptr)
    {
        num_chunks_ = 0;
        return false;
    }

    free_first_ = 0;
    first_ = num_free_chunks_;
    last_ = first_ + num_chunks_ - 1;

    for(uint32_t i = 0; i < num_free_chunks_; i++)
    {
        chunk_queue_[i] = ConnectionsChunk{
            .next_idx = i+1,
            .connections = {}
        };
    }
    chunk_queue_[num_free_chunks_ - 1].next_idx = 0xffffffff;

    for(uint32_t i = first_; i < last_ + 1; i++)
    {
        chunk_queue_[i] = ConnectionsChunk{
            .next_idx = i+1,
            .connections = {}
        };
        for (uint32_t j = 0; j < chunk_size; j++)
        {
            chunk_queue_[i].connections[j] = (i - first_) * chunk_size + j;
        }
    }
    chunk_queue_[last_].next_idx = 0xffffffff;

    for (uint32_t i = 0; i < max_workers; i++)
    {
        worker_chunks_[i] = 0xffffffff;
        gc_chunks_[i] = 0xffffffff;
    }
    gc_chunks_[max_workers] = 0xffffffff;

    free_addresses_ = num_chunks_ * chunk_size;
    used_addresses_ = 0;

    initialized_ = true;

    return true;
}

bool LocalPool2::_TestInit(const ipv4_prefix_t& prefix)
{
    if (initialized_)
    {
        return true;
    }
    if (prefix.mask == 0)
    {
        YANET_LOG_ERROR("Invalid prefix\n");
        return false;
    }
    prefix_ = prefix;
    
    uint32_t num_connections = ((1u << (32u - prefix_.mask)) - 2) * num_ports;
    num_free_chunks_ = max_workers * 2;
    num_chunks_ = num_connections / chunk_size;
    
    free_first_ = 0;
    first_ = num_free_chunks_;
    last_ = first_ + num_chunks_ - 1;

    chunk_queue_ = new ConnectionsChunk[num_free_chunks_ + num_chunks_];
    local_to_client_ = new uint64_t[num_chunks_ * chunk_size];
    for(uint32_t i = 0; i < num_free_chunks_; i++)
    {
        chunk_queue_[i] = ConnectionsChunk{
            .next_idx = i+1,
            .connections = {}
        };
    }
    chunk_queue_[num_free_chunks_ - 1].next_idx = 0xffffffff;

    for(uint32_t i = first_; i < last_ + 1; i++)
    {
        chunk_queue_[i] = ConnectionsChunk{
            .next_idx = i+1,
            .connections = {}
        };
        for (uint32_t j = 0; j < chunk_size; j++)
        {
            chunk_queue_[i].connections[j] = (i - first_) * chunk_size + j;
        }
    }
    chunk_queue_[last_].next_idx = 0xffffffff;

    for (uint32_t i = 0; i < max_workers; i++)
    {
        worker_chunks_[i] = 0xffffffff;
        gc_chunks_[i] = 0xffffffff;
    }
    gc_chunks_[max_workers] = 0xffffffff;

    free_addresses_ = num_chunks_ * chunk_size;
    used_addresses_ = 0;

    initialized_ = true;

    return true;
}

bool LocalPool2::_TestFree()
{
    if (initialized_)
    {
        delete[] chunk_queue_;
        chunk_queue_ = nullptr;
        initialized_ = false;
    }
    return true;
}

uint64_t LocalPool2::Allocate(uint32_t worker_id, uint32_t client_addr, tPortId client_port)
{
    if (unlikely(!initialized_)) return 0;

    uint32_t idx = worker_chunks_[worker_id];
    if (idx == 0xffffffff)
    {
        while(!mutex_.try_lock());
        if (first_ == 0xffffffff)
        {
            mutex_.unlock();
            return 0;
        }

        idx = first_;
        first_ = chunk_queue_[idx].next_idx;
        if (first_ == 0xffffffff)
            last_ = 0xffffffff;

        worker_chunks_[worker_id] = idx;
        chunk_queue_[idx].offset = 0;    
        mutex_.unlock();
    }
    
    ConnectionsChunk& chunk = chunk_queue_[idx];
    uint32_t local = chunk.connections[chunk.offset];
    uint64_t res = index_to_tuple(local);
    chunk.offset++;
    
    if (chunk.offset == chunk_size)
    {
        while(!mutex_.try_lock());
        chunk.next_idx = free_first_;
        free_first_ = idx;
        worker_chunks_[worker_id] = 0xffffffff;
        mutex_.unlock();
    }
    local_to_client_[local] = PackTuple(client_addr, client_port); 

    free_addresses_--;
    used_addresses_++;

    return res;
}

void LocalPool2::Free(uint32_t worker_id, uint64_t tuple)
{
    if (unlikely(!initialized_)) return;
    
    uint32_t idx = tuple_to_index(tuple);
    if (unlikely(idx > num_chunks_ * chunk_size - 1)) return;
    if (unlikely(local_to_client_[idx] == 0))
    {
        YANET_LOG_ERROR("Trying to free tuple %s:%d which is not in use\n",
            common::ip_address_t(rte_be_to_cpu_32(uint32_t(tuple >> 16))).toString().c_str(), rte_be_to_cpu_16(uint16_t(tuple & 0xffff)));
        return;
    }

    uint32_t gc_chunk = gc_chunks_[worker_id];
    if (gc_chunk == 0xffffffff)
    {
        while(!mutex_.try_lock());
        if (unlikely(free_first_ == 0xffffffff))
        {
            mutex_.unlock();
            YANET_LOG_ERROR("No free chunks available\n");
            return;
        }

        gc_chunk = free_first_;
        gc_chunks_[worker_id] = free_first_;
        free_first_ = chunk_queue_[gc_chunk].next_idx;
        chunk_queue_[gc_chunk].offset = 0;
        mutex_.unlock();
    }

    ConnectionsChunk& chunk = chunk_queue_[gc_chunk];
    chunk.connections[chunk.offset] = idx;
    chunk.offset++;

    if (chunk.offset == chunk_size)
    {
        while(!mutex_.try_lock());
        if (last_ != 0xffffffff)
            chunk_queue_[last_].next_idx = gc_chunk;
        last_ = gc_chunk;
        if (first_ == 0xffffffff)
            first_ = gc_chunk;
        gc_chunks_[worker_id] = 0xffffffff;
        chunk_queue_[last_].next_idx = 0xffffffff;
        mutex_.unlock();
    }

    local_to_client_[idx] = 0;

    free_addresses_++;
    used_addresses_--;
}

uint64_t LocalPool2::FindClientByLocal(uint32_t local_addr, tPortId local_port) const
{
    if (unlikely(!initialized_))
    {
        return 0;
    }
    uint32_t idx = tuple_to_index(PackTuple(local_addr, local_port));
    local_addr = rte_be_to_cpu_32(local_addr);
    local_port = rte_be_to_cpu_16(local_port);
    if (unlikely(idx > num_chunks_ * chunk_size))
    {
        YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: out of range, local_addr=%s local_port=%d idx=%d num_connections_=%lu\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx, num_chunks_ * chunk_size);
        return 0;
    }
    
    uint64_t client = local_to_client_[idx];
    if (client == 0)
    {
        YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: not used, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
        return 0;
    }
    
    // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: found, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
    return client;
}

void LocalPool2::GetLocalPool(proxy_service_id_t service_id, common::idp::proxy_local_pool::response& response) const {
    if (unlikely(!initialized_))
    {
        return;
    }

    response.emplace_back(service_id, common::ipv4_prefix_t{prefix_.address.address, prefix_.mask}, num_chunks_ * chunk_size, free_addresses_, used_addresses_);
}

inline uint64_t LocalPool2::index_to_tuple(uint32_t index) const
{
    return PackTuple(rte_cpu_to_be_32(prefix_.address.address + 1 + index / num_ports),
                      rte_cpu_to_be_16(index % num_ports + min_port));
}

inline uint32_t LocalPool2::tuple_to_index(uint64_t tuple) const
{
    return (rte_be_to_cpu_16((uint16_t)(tuple & 0xffff)) - min_port) + 
           (rte_be_to_cpu_32((uint32_t)(tuple >> 16)) - prefix_.address.address - 1) * num_ports;
}

}