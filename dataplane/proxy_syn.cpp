#include "proxy_syn.h"

#define TIMEOUT_SYN 3 // todo - to config

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

bool ServiceSynConnections::Initialize(proxy_service_id_t service_id, uint32_t number_buckets, dataplane::memory_manager* memory_manager)
{
    if (initialized_)
    {
        return true;
    }
    else if (number_buckets == 0)
    {
        number_buckets_ = 0;
        return true;
    }

    size_t mem_size = number_buckets * sizeof(SynBucket);
    YANET_LOG_WARNING("ServiceSynConnections::Initialize number_buckets=%d, mem_size=%ld\n", number_buckets, mem_size);

    tSocketId socket_id = 0; // todo !!!
    std::string name = "tcp_proxy.syn_connections." + std::to_string(service_id);
    buckets_ = memory_manager->create_static_array<SynBucket>(name.data(), number_buckets, socket_id);
    if (buckets_ == nullptr)
    {
        return false;
    }

    number_buckets_ = number_buckets;
    initialized_ = true;
    return true;    
}

bool ServiceSynConnections::TryInsert(uint32_t client_addr, uint16_t client_port,
                                        uint32_t local_addr, uint16_t local_port,
                                        uint32_t seq, uint32_t current_time)
{
    if (number_buckets_ == 0)
    {
        return false;
    }

    uint64_t key = KeyConnection(client_addr, client_port);
    uint32_t bucket_index = key & (number_buckets_ - 1);
    uint32_t record_index = SynBucket::bucket_size;
    SynBucket& bucket = buckets_[bucket_index];

    std::lock_guard<std::mutex> guard(bucket.mutex);
    for (uint32_t index = 0; index < SynBucket::bucket_size; index++)
    {
        if (!bucket.connections[index].IsExpired(current_time))
        {
            // time ok
            if (bucket.connections[index].client == key)
            {
                return true;
            }
        }
        else if (bucket.connections[index].local == 0 && record_index == SynBucket::bucket_size)
        {
            record_index = index;
        }
    }

    if (record_index == SynBucket::bucket_size)
    {
        return false;
    }

    bucket.connections[record_index].client = key;
    bucket.connections[record_index].local = KeyConnection(local_addr, local_port);
    bucket.connections[record_index].last_time = current_time;
    bucket.connections[record_index].recv_seq = seq;
    return true;
}

ServiceSynConnections::LockPointer ServiceSynConnections::FindAndLock(uint32_t addr, uint16_t port, uint32_t current_time)
{
    if (number_buckets_ == 0)
    {
        return LockPointer{};
    }

    uint64_t key = KeyConnection(addr, port);
    SynBucket* bucket = &buckets_[key & (number_buckets_ - 1)];

    LockPointer ptr = std::make_shared<_LockPointer>(bucket, nullptr);

    for (uint32_t index = 0; index < SynBucket::bucket_size; index++)
    {
        OneSynConnection* connection = &bucket->connections[index];
        if (key == connection->client && !connection->IsExpired(current_time))
        {
            connection->last_time = current_time;
            ptr->connection = connection;
            return ptr;
        }
    }

    return LockPointer{};
}

void ServiceSynConnections::Remove(LockPointer ptr)
{
    if (number_buckets_ == 0 || !ptr)
    {
        return;
    }

    ptr->connection->Clear();
}

void ServiceSynConnections::GetSyn(proxy_service_id_t service_id, uint32_t current_time, common::idp::proxy_syn::response& response)
{
    for (uint32_t bucket_index = 0; bucket_index < number_buckets_; bucket_index++)
    {
        SynBucket& bucket = buckets_[bucket_index];
        std::lock_guard<std::mutex> guard(bucket.mutex);
        for (uint32_t index = 0; index < SynBucket::bucket_size; index++)
        {
            OneSynConnection& connection = bucket.connections[index];
            if (connection.last_time + TIMEOUT_SYN >= current_time)
            {
                uint32_t src_addr;
                uint16_t src_port;
                UnpackKeyConnection(connection.client, src_addr, src_port);
                response.emplace_back(service_id, src_addr, src_port);
            }
        }
    }
}

void ServiceSynConnections::CollectGarbage(uint32_t current_time, LocalPool& local_pool)
{
    for (uint32_t bucket_index = 0; bucket_index < number_buckets_; bucket_index++)
    {
        SynBucket& bucket = buckets_[bucket_index];
        std::lock_guard<std::mutex> guard(bucket.mutex);
        for (uint32_t index = 0; index < SynBucket::bucket_size; index++)
        {
            OneSynConnection& connection = bucket.connections[index];
            if (connection.IsExpired(current_time))
            {
                uint32_t src_addr;
                uint16_t src_port;
                UnpackKeyConnection(connection.client, src_addr, src_port);
                local_pool.Free(src_addr, src_port);
                connection.Clear();
            }
        }
    }
}

SynBucket::SynBucket()
{
    // YANET_LOG_WARNING("SynBucket::SynBucket()\n");
    time_overflow = 0;
    for (uint32_t index = 0; index < bucket_size; index++)
    {
        connections[index].Clear();
    }
}

void OneSynConnection::Clear()
{
    last_time = 0;
    server_answer = false;
    local = 0;
}

bool OneSynConnection::IsExpired(uint32_t current_time)
{
    return last_time + TIMEOUT_SYN < current_time;
}

}
