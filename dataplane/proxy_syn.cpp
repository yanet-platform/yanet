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

SynInsertResult ServiceSynConnections::TryInsertClient(uint32_t addr, uint16_t port, uint32_t seq, uint32_t current_time, SynOperationData& operation_data)
{
    if (number_buckets_ == 0)
    {
        return SynInsertResult::overflow;
    }

    uint64_t key = KeyConnection(addr, port);
    operation_data.bucket_index = key & (number_buckets_ - 1);
    operation_data.record_index = SynBucket::bucket_size;
    SynBucket& bucket = buckets_[operation_data.bucket_index];

    std::lock_guard<std::mutex> guard(bucket.mutex);
    for (uint32_t index = 0; index < SynBucket::bucket_size; index++)
    {
        if (bucket.connections[index].last_time + TIMEOUT_SYN >= current_time)
        {
            // time ok
            if (bucket.connections[index].client == key)
            {
                operation_data.record_index = index;
                UnpackKeyConnection(bucket.connections[index].local, operation_data.local_addr, operation_data.local_port);
                operation_data.recv_seq = bucket.connections[index].recv_seq;
                bucket.connections[index].last_time = current_time;
                bucket.connections[index].recv_seq = seq;
                return SynInsertResult::exists;
            }
        }
        else if (bucket.connections[index].local == 0 && operation_data.record_index == SynBucket::bucket_size)
        {
            operation_data.record_index = index;
        }
    }

    if (operation_data.record_index == SynBucket::bucket_size)
    {
        return SynInsertResult::overflow;
    }

    bucket.connections[operation_data.record_index].client = key;
    bucket.connections[operation_data.record_index].last_time = current_time;
    bucket.connections[operation_data.record_index].recv_seq = seq;
    return SynInsertResult::new_record;
}

void ServiceSynConnections::UpdateLocal(uint32_t addr, uint16_t port, uint32_t current_time, const SynOperationData& operation_data)
{
    SynBucket& bucket = buckets_[operation_data.bucket_index];
    OneSynConnection& connection = bucket.connections[operation_data.record_index];

    std::lock_guard<std::mutex> guard(bucket.mutex);
    if (connection.client == KeyConnection(addr, port) && connection.last_time + TIMEOUT_SYN >= current_time)
    {
        connection.local = KeyConnection(operation_data.local_addr, operation_data.local_port);
    }
    else
    {
        YANET_LOG_ERROR("UpdateLocal bad record\n");
    }
}

void ServiceSynConnections::Remove(uint32_t addr, uint16_t port, uint32_t current_time, const SynOperationData& operation_data)
{
    SynBucket& bucket = buckets_[operation_data.bucket_index];
    OneSynConnection& connection = bucket.connections[operation_data.record_index];

    std::lock_guard<std::mutex> guard(bucket.mutex);
    if (connection.client == KeyConnection(addr, port) && connection.last_time + TIMEOUT_SYN >= current_time)
    {
        connection.Clear();
    }
    else
    {
        YANET_LOG_ERROR("Remove bad record\n");
    }
}

bool ServiceSynConnections::UpdateTimeFromServerAnswer(uint32_t addr, uint16_t port, uint32_t current_time)
{
    if (number_buckets_ == 0)
    {
        return false;
    }

    uint64_t key = KeyConnection(addr, port);
    SynBucket& bucket = buckets_[key & (number_buckets_ - 1)];

    std::lock_guard<std::mutex> guard(bucket.mutex);
    for (uint32_t index = 0; index < SynBucket::bucket_size; index++)
    {
        OneSynConnection& connection = bucket.connections[index];
        if (connection.last_time + TIMEOUT_SYN >= current_time && connection.client == key)
        {
            connection.last_time = current_time;
            connection.server_answer = true;
            return true;
        }
    }

    return false;
}

bool ServiceSynConnections::SearchAndRemove(uint32_t addr, uint16_t port, uint32_t current_time, SynOperationData& operation_data)
{
    if (number_buckets_ == 0)
    {
        return false;
    }

    uint64_t key = KeyConnection(addr, port);
    SynBucket& bucket = buckets_[key & (number_buckets_ - 1)];

    std::lock_guard<std::mutex> guard(bucket.mutex);
    for (uint32_t index = 0; index < SynBucket::bucket_size; index++)
    {
        OneSynConnection& connection = bucket.connections[index];
        if (connection.last_time + TIMEOUT_SYN >= current_time && connection.client == key && connection.server_answer) // todo - check seq
        {
            UnpackKeyConnection(connection.local, operation_data.local_addr, operation_data.local_port);
            connection.Clear();
            return true;
        }
    }

    return false;
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

}
