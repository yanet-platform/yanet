#include "local_pool.h"

namespace dataplane::proxy
{

constexpr uint32_t NULL_CHUNK = 0xffffffff;

LocalPool::~LocalPool()
{
    if(destroy) destroy();
}

bool LocalPool::Init(proxy_service_id_t service_id, const ipv4_prefix_t& prefix,
                     dataplane::memory_manager* memory_manager, bool include_edge_addresses)
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

    uint32_t num_addresses = 1u << (32u - prefix_.mask);
    if (!include_edge_addresses && num_addresses > 2) num_addresses -= 2;
    uint32_t num_connections = num_addresses * num_ports;
    uint32_t num_free_chunks = max_workers * 2;
    uint32_t num_chunks = num_connections / chunk_size;
    
    if (memory_manager != nullptr)
    {
        tSocketId socket_id = 0; // todo !!!
        std::string name = "tcp_proxy.local_pools." + std::to_string(service_id) + ".local_info";
        local_info_ = (LocalInfo*)memory_manager->alloc(name.data(), socket_id, sizeof(LocalInfo));
        name = "tcp_proxy.local_pools." + std::to_string(service_id) + ".chunk_queue";
        chunk_queue_ = memory_manager->create_static_array<ConnectionsChunk>(name.data(), num_free_chunks + num_chunks, socket_id);
        name = "tcp_proxy.local_pools." + std::to_string(service_id) + ".local_to_client";
        local_to_client_ = memory_manager->create_static_array<uint64_t>(name.data(), num_chunks * chunk_size, socket_id);
    }
    else
    {
        local_info_ = new LocalInfo();
        chunk_queue_ = new ConnectionsChunk[num_free_chunks + num_chunks];
        local_to_client_ = new uint64_t[num_chunks * chunk_size];
        destroy = [this]() {
            delete[] local_info_;
            delete[] chunk_queue_;
            delete[] local_to_client_;
        };
    }
    if (local_info_ == nullptr || chunk_queue_ == nullptr || local_to_client_ == nullptr)
    {
        return false;
    }

    local_info_->free_first = 0;
    local_info_->first = num_free_chunks;
    local_info_->last = local_info_->first + num_chunks - 1;
    local_info_->num_free_chunks = num_free_chunks;
    local_info_->num_chunks = num_chunks;

    for(uint32_t i = 0; i < local_info_->num_free_chunks; i++)
    {
        chunk_queue_[i] = ConnectionsChunk{
            .next_idx = i+1,
            .connections = {}
        };
    }
    chunk_queue_[local_info_->num_free_chunks - 1].next_idx = NULL_CHUNK;

    for(uint32_t i = local_info_->first; i < local_info_->last + 1; i++)
    {
        chunk_queue_[i] = ConnectionsChunk{
            .next_idx = i+1,
            .connections = {}
        };
        for (uint32_t j = 0; j < chunk_size; j++)
        {
            chunk_queue_[i].connections[j] = (i - local_info_->first) * chunk_size + j;
        }
    }
    chunk_queue_[local_info_->last].next_idx = NULL_CHUNK;

    for (uint32_t i = 0; i < max_workers; i++)
    {
        local_info_->worker_chunks[i] = NULL_CHUNK;
        local_info_->gc_chunks[i] = NULL_CHUNK;
    }
    local_info_->gc_chunks[max_workers] = NULL_CHUNK;

    local_info_->free_addresses = local_info_->num_chunks * chunk_size;
    local_info_->used_addresses = 0;

    rte_spinlock_init(&local_info_->spinlock);

    initialized_ = true;

    return true;
}

uint64_t LocalPool::Allocate(uint32_t worker_id, uint32_t client_addr, tPortId client_port)
{
    if (unlikely(!initialized_)) return 0;

    uint32_t idx = local_info_->worker_chunks[worker_id];
    if (idx == NULL_CHUNK)
    {
        rte_spinlock_lock(&local_info_->spinlock);
        if (local_info_->first == NULL_CHUNK)
        {
            rte_spinlock_unlock(&local_info_->spinlock);
            return 0;
        }

        idx = local_info_->first;
        local_info_->first = chunk_queue_[idx].next_idx;
        if (local_info_->first == NULL_CHUNK)
            local_info_->last = NULL_CHUNK;

        local_info_->worker_chunks[worker_id] = idx;
        chunk_queue_[idx].offset = 0;    
        rte_spinlock_unlock(&local_info_->spinlock);
    }
    
    ConnectionsChunk& chunk = chunk_queue_[idx];
    uint32_t local = chunk.connections[chunk.offset];
    uint64_t res = index_to_tuple(local);
    chunk.offset++;
    
    if (chunk.offset == chunk_size)
    {
        rte_spinlock_lock(&local_info_->spinlock);
        chunk.next_idx = local_info_->free_first;
        local_info_->free_first = idx;
        local_info_->worker_chunks[worker_id] = NULL_CHUNK;
        rte_spinlock_unlock(&local_info_->spinlock);
    }
    local_to_client_[local] = PackTuple(client_addr, client_port); 

    local_info_->free_addresses--;
    local_info_->used_addresses++;

    return res;
}

void LocalPool::Free(uint32_t worker_id, uint64_t tuple)
{
    if (unlikely(!initialized_)) return;
    
    uint32_t idx = tuple_to_index(tuple);
    if (unlikely(idx > local_info_->num_chunks * chunk_size - 1)) return;
    if (unlikely(local_to_client_[idx] == 0))
    {
        YANET_LOG_ERROR("Trying to free tuple %s:%d which is not in use\n",
            common::ip_address_t(rte_be_to_cpu_32(uint32_t(tuple >> 16))).toString().c_str(), rte_be_to_cpu_16(uint16_t(tuple & 0xffff)));
        return;
    }

    uint32_t gc_chunk = local_info_->gc_chunks[worker_id];
    if (gc_chunk == NULL_CHUNK)
    {
        rte_spinlock_lock(&local_info_->spinlock);
        if (unlikely(local_info_->free_first == NULL_CHUNK))
        {
            rte_spinlock_unlock(&local_info_->spinlock);
            YANET_LOG_ERROR("No free chunks available\n");
            return;
        }

        gc_chunk = local_info_->free_first;
        local_info_->gc_chunks[worker_id] = local_info_->free_first;
        local_info_->free_first = chunk_queue_[gc_chunk].next_idx;
        chunk_queue_[gc_chunk].offset = 0;
        rte_spinlock_unlock(&local_info_->spinlock);
    }

    ConnectionsChunk& chunk = chunk_queue_[gc_chunk];
    chunk.connections[chunk.offset] = idx;
    chunk.offset++;

    if (chunk.offset == chunk_size)
    {
        rte_spinlock_lock(&local_info_->spinlock);
        if (local_info_->last != NULL_CHUNK)
            chunk_queue_[local_info_->last].next_idx = gc_chunk;
        local_info_->last = gc_chunk;
        if (local_info_->first == NULL_CHUNK)
            local_info_->first = gc_chunk;
        local_info_->gc_chunks[worker_id] = NULL_CHUNK;
        chunk_queue_[local_info_->last].next_idx = NULL_CHUNK;
        rte_spinlock_unlock(&local_info_->spinlock);
    }

    local_to_client_[idx] = 0;

    local_info_->free_addresses++;
    local_info_->used_addresses--;
}

uint64_t LocalPool::FindClientByLocal(uint32_t local_addr, tPortId local_port) const
{
    if (unlikely(!initialized_))
    {
        return 0;
    }
    uint32_t idx = tuple_to_index(PackTuple(local_addr, local_port));
    local_addr = rte_be_to_cpu_32(local_addr);
    local_port = rte_be_to_cpu_16(local_port);
    if (unlikely(idx > local_info_->num_chunks * chunk_size - 1))
    {
        // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: out of range, local_addr=%s local_port=%d idx=%d num_connections_=%lu\n",
        //     common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx, local_info_->num_chunks * chunk_size);
        return 0;
    }
    
    uint64_t client = local_to_client_[idx];
    if (client == 0)
    {
        // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: not used, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
        return 0;
    }
    
    // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: found, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
    return client;
}

LocalPoolStat LocalPool::GetStat() const {
    LocalPoolStat stat;
    if (unlikely(!initialized_))
    {
        return stat;
    }

    stat.prefix = common::ipv4_prefix_t{prefix_.address.address, prefix_.mask};
    stat.total_addresses = local_info_->num_chunks * chunk_size;
    stat.free_addresses = local_info_->free_addresses;
    stat.used_addresses = local_info_->used_addresses;
    return stat;
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

bool LocalPool::NeedUpdate(const ipv4_prefix_t& prefix)
{
    return (prefix_.address != prefix.address) || (prefix_.mask != prefix.mask) || !initialized_;
}

void LocalPool::ClearIfNotEqual(const LocalPool& other, dataplane::memory_manager* memory_manager)
{
    if (chunk_queue_ != other.chunk_queue_ && chunk_queue_ != nullptr)
    {
        Clear(memory_manager);
        ClearLinks();
    }

    initialized_ = false;
}

void LocalPool::Clear(dataplane::memory_manager* memory_manager)
{
    if (memory_manager != nullptr)
    {
        memory_manager->destroy(chunk_queue_);
        memory_manager->destroy(local_to_client_);
        memory_manager->destroy(local_info_);
    }
    else
    {
        delete chunk_queue_;
        delete local_to_client_;
        delete local_info_;
    }
}

void LocalPool::CopyFrom(const LocalPool& other)
{
    prefix_ = other.prefix_;
    chunk_queue_ = other.chunk_queue_;
    local_to_client_ = other.local_to_client_;
    local_info_ = other.local_info_;
    initialized_ = other.initialized_;
}

void LocalPool::ClearLinks()
{
    chunk_queue_ = nullptr;
    local_to_client_ = nullptr;
    local_info_ = nullptr;
    initialized_ = false;
}

std::string LocalPool::Debug() const
{
    if (!initialized_)
    {
        return "not initialized";
    }

    char loc_buf[256];
    snprintf(loc_buf, sizeof(loc_buf), "chunk_queue=%p, local_to_client=%p, local_info=%p", chunk_queue_, local_to_client_, local_info_);
    return std::string(loc_buf);
}

}