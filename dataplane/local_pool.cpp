#include "local_pool.h"

namespace dataplane::proxy
{

constexpr uint32_t NULL_CHUNK = 0xffffffff;

bool LocalPool::Init(proxy_service_id_t service_id, const std::vector<common::ipv4_prefix_t>& prefixes,
                     dataplane::memory_manager* memory_manager, tSocketId socket_id,
                     bool rotate_addresses_first)
{
    if (initialized_) return true;
    if (prefixes.size() == 0)
    {
        YANET_LOG_ERROR("Empty prefixes array\n");
        return false;
    }

    for (auto upstream_net : prefixes)
    {
        ipv4_prefix_t prefix;
        prefix.address.address = upstream_net.address();
        prefix.mask = upstream_net.mask();
        prefixes_.push_back(prefix);
    }
    prefix_first_index_.resize(prefixes_.size());

    for (const auto& prefix : prefixes)
        num_addrs_ += 1u << (32u - prefix.mask());
    
    #ifdef CONFIG_YADECAP_UNITTEST
    index_to_prefix_ = new uint32_t[num_addrs_];
    #else
    std::string name = "tcp_proxy.local_pools." + std::to_string(service_id) + ".index_to_prefix";
    index_to_prefix_ = memory_manager->create_static_array<uint32_t>(name.c_str(), num_addrs_, socket_id);
    #endif

    uint32_t prefix_idx = 0, idx = 0;
    for (const auto& prefix : prefixes_)
    {
        prefix_first_index_[prefix_idx] = idx;
        for (uint32_t i = 0; i < (1u << (32u - prefix.mask)); i++, idx++)
        {
            index_to_prefix_[idx] = prefix_idx;
        }
        prefix_idx++;
    }

    rotate_addr_first_ = rotate_addresses_first;

    // if (!include_edge_addresses && num_addrs_ > 2) 
    // {
    //     num_addrs_ -= 2;
    //     addr_offset_ = 1;
    // }
    uint32_t num_connections = num_addrs_ * num_ports;
    uint32_t num_free_chunks = max_workers * 2;
    uint32_t num_chunks = num_connections / chunk_size;
    
#ifdef CONFIG_YADECAP_UNITTEST
    local_info_ = new LocalInfo();
    chunk_queue_ = new ConnectionsChunk[num_free_chunks + num_chunks];
    local_to_client_ = new uint64_t[num_chunks * chunk_size];
#else
    name = "tcp_proxy.local_pools." + std::to_string(service_id) + ".local_info";
    local_info_ = (LocalInfo*)memory_manager->alloc(name.data(), socket_id, sizeof(LocalInfo));
    name = "tcp_proxy.local_pools." + std::to_string(service_id) + ".chunk_queue";
    chunk_queue_ = memory_manager->create_static_array<ConnectionsChunk>(name.data(), num_free_chunks + num_chunks, socket_id);
    name = "tcp_proxy.local_pools." + std::to_string(service_id) + ".local_to_client.addresses";
    local_to_client_.addresses = memory_manager->create_static_array<common::uint128_t>(name.data(), num_chunks * chunk_size, socket_id);
    name = "tcp_proxy.local_pools." + std::to_string(service_id) + ".local_to_client.ports";
    local_to_client_.ports = memory_manager->create_static_array<uint16_t>(name.data(), num_chunks * chunk_size, socket_id);
#endif
    if (local_info_ == nullptr || chunk_queue_ == nullptr || local_to_client_.addresses == nullptr || local_to_client_.ports == nullptr)
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

uint64_t LocalPool::Allocate(uint32_t worker_id, common::uint128_t client_addr, tPortId client_port)
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
        local_info_->free_addresses -= chunk_size;
        local_info_->used_addresses += chunk_size;
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
    local_to_client_.addresses[local] = client_addr;
    local_to_client_.addresses[local] = client_port; 

    return res;
}

void LocalPool::Free(uint32_t worker_id, uint64_t tuple)
{
    if (unlikely(!initialized_)) return;
    
    uint32_t idx = tuple_to_index(tuple);
    if (unlikely(idx > local_info_->num_chunks * chunk_size - 1)) return;
    if (unlikely(local_to_client_.addresses[idx] == 0))
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
        local_info_->free_addresses += chunk_size;
        local_info_->used_addresses -= chunk_size;
        rte_spinlock_unlock(&local_info_->spinlock);
    }

    local_to_client_.addresses[idx] = 0;
    local_to_client_.ports[idx] = 0;
}

LocalPool::Client LocalPool::FindClientByLocal(uint32_t local_addr, tPortId local_port) const
{
    Client result{};
    if (unlikely(!initialized_))
    {
        return result;
    }
    uint32_t idx = tuple_to_index(PackTuple(local_addr, local_port));
    // local_addr = rte_be_to_cpu_32(local_addr);
    // local_port = rte_be_to_cpu_16(local_port);
    if (unlikely(idx > local_info_->num_chunks * chunk_size - 1))
    {
        // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: out of range, local_addr=%s local_port=%d idx=%d num_connections_=%lu\n",
        //     common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx, local_info_->num_chunks * chunk_size);
        return result;
    }
    
    if (local_to_client_.addresses[idx] == 0)
    {
        // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: not used, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
        return result;
    }
    result.address = local_to_client_.addresses[idx];
    result.port = local_to_client_.ports[idx];
    
    // YANET_LOG_WARNING("\tLocalPool.FindClientByLocal: found, local_addr=%s local_port=%d idx=%d\n", common::ipv4_address_t(local_addr).toString().c_str(), local_port, idx);
    return result;
}

LocalPoolStat LocalPool::GetStat() const {
    LocalPoolStat stat;
    if (unlikely(!initialized_))
    {
        return stat;
    }

    for (const ipv4_prefix_t& prefix : prefixes_)
    {
        stat.prefixes.emplace_back(prefix.address.address, prefix.mask);
    }
    stat.total_addresses = local_info_->num_chunks * chunk_size;
    stat.free_addresses = local_info_->free_addresses;
    stat.used_addresses = local_info_->used_addresses;
    return stat;
}

inline uint32_t LocalPool::index_to_prefix(uint32_t index) const
{
    index = rotate_addr_first_ ? index % num_addrs_ : index / num_ports;
    return index_to_prefix_[index];
}

inline uint32_t LocalPool::tuple_to_prefix(uint64_t tuple) const
{
    common::ipv4_address_t addr(rte_be_to_cpu_32(tuple >> 16));
    uint32_t index = 0;
    for (const auto& prefix : prefixes_)
    {
        if (common::ipv4_prefix_t(prefix.address.address, prefix.mask).subnetFor(addr))
            return index;
        index++;
    }
    return 0;
}

inline uint64_t LocalPool::index_to_tuple(uint32_t index) const
{
    uint32_t prefix_idx = index_to_prefix(index);
    ipv4_prefix_t prefix = prefixes_[prefix_idx];
    uint32_t start_idx = prefix_first_index_[prefix_idx];
    if (rotate_addr_first_)
    {
        return PackTuple(rte_cpu_to_be_32(prefix.address.address + addr_offset_ + (index - start_idx) % num_addrs_),
                    rte_cpu_to_be_16(min_port + index / num_addrs_));
    }
    return PackTuple(rte_cpu_to_be_32(prefix.address.address + addr_offset_ + index / num_ports - start_idx),
                      rte_cpu_to_be_16(min_port + index % num_ports));
}

inline uint32_t LocalPool::tuple_to_index(uint64_t tuple) const
{
    uint32_t prefix_idx = tuple_to_prefix(tuple);
    ipv4_prefix_t prefix = prefixes_[prefix_idx];
    uint32_t start_idx = prefix_first_index_[prefix_idx];
    if (rotate_addr_first_)
    {
        return (rte_be_to_cpu_16((uint16_t)(tuple & 0xffff)) - min_port) * num_addrs_ + 
               (rte_be_to_cpu_32((uint32_t)(tuple >> 16)) - prefix.address.address - addr_offset_ + start_idx);
    }
    return (rte_be_to_cpu_16((uint16_t)(tuple & 0xffff)) - min_port) + 
           (rte_be_to_cpu_32((uint32_t)(tuple >> 16)) - prefix.address.address - addr_offset_ + start_idx) * num_ports;
}

bool LocalPool::NeedUpdate(const std::vector<common::ipv4_prefix_t>& prefixes)
{
    if (!initialized_  || prefixes_.size() != prefixes.size())
    {
        return true;
    }
    for (uint32_t i = 0; i < prefixes_.size(); i++)
    {
        if (prefixes_[i].address.address != prefixes[i].address() || prefixes_[i].mask != prefixes[i].mask())
        {
            return true;
        }
    }
    return false;
}

void LocalPool::ClearIfNotEqual(const LocalPool& other, dataplane::memory_manager* memory_manager)
{
    if (chunk_queue_ != other.chunk_queue_ && chunk_queue_ != nullptr)
    {
        Clear(memory_manager);
        ClearLinks();
    }
}

void LocalPool::Clear(dataplane::memory_manager* memory_manager)
{
#ifdef CONFIG_YADECAP_UNITTEST
        delete chunk_queue_;
        delete local_to_client_;
        delete local_info_;
        delete index_to_prefix_;
#else
    if (chunk_queue_ != nullptr)
    {
        memory_manager->destroy(chunk_queue_);
    }
    if (local_to_client_.addresses != nullptr)
    {
        memory_manager->destroy(local_to_client_.addresses);
    }
    if (local_to_client_.ports != nullptr)
    {
        memory_manager->destroy(local_to_client_.ports);
    }
    if (local_info_ != nullptr)
    {
        memory_manager->destroy(local_info_);
    }
    if (index_to_prefix_ != nullptr)
    {
        memory_manager->destroy(index_to_prefix_);
    }
#endif
    prefixes_.clear();
    prefix_first_index_.clear();
    ClearLinks();
}

void LocalPool::CopyFrom(const LocalPool& other)
{
    prefixes_ = other.prefixes_;
    index_to_prefix_ = other.index_to_prefix_;
    prefix_first_index_ = other.prefix_first_index_;
    addr_offset_ = other.addr_offset_;
    rotate_addr_first_ = other.rotate_addr_first_;
    num_addrs_ = other.num_addrs_;
    chunk_queue_ = other.chunk_queue_;
    local_to_client_ = other.local_to_client_;
    local_info_ = other.local_info_;
    initialized_ = other.initialized_;
}

void LocalPool::ClearLinks()
{
    index_to_prefix_ = nullptr;
    chunk_queue_ = nullptr;
    local_to_client_.addresses = nullptr;
    local_to_client_.ports = nullptr;
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
    snprintf(loc_buf, sizeof(loc_buf), "chunk_queue=%p, local_to_client.addresses=%p, local_to_client.ports=%p, local_info=%p",
             chunk_queue_, local_to_client_.addresses, local_to_client_.ports, local_info_);
    return std::string(loc_buf);
}

}