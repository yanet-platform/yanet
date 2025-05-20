#pragma once

#include "memory_manager.h"
#include "type.h"
#include "local_pool.h"

#include <mutex>

namespace dataplane::proxy
{

struct OneSynConnection
{
    uint64_t client;    // client ip + port
    uint64_t local;     // local ip + port
    uint32_t recv_seq;  // seq received from client
    uint32_t last_time; // time of last packet
    bool server_answer; // was received answer from server
    
    void Clear();
    bool IsExpired(uint32_t current_time);
};

struct SynBucket
{
    static constexpr uint32_t bucket_size = 16;

    OneSynConnection connections[bucket_size];
    std::mutex mutex;
    uint32_t time_overflow;

    SynBucket();
};

struct SynOperationData
{
    uint32_t bucket_index;
    uint32_t record_index;
    uint32_t local_addr;
    uint16_t local_port;
    uint32_t recv_seq;
};

class ServiceSynConnections
{
public:
    bool Initialize(proxy_service_id_t service_id, uint32_t number_buckets, dataplane::memory_manager* memory_manager);
    bool TryInsert(uint32_t client_addr, uint16_t client_port,
                uint32_t local_addr, uint16_t local_port,
                uint32_t seq, uint32_t current_time);
    void GetSyn(proxy_service_id_t service_id, uint32_t current_time, common::idp::proxy_syn::response& response);

    void CollectGarbage(uint32_t current_time, LocalPool& local_pool);

private:
    struct _Pointer {
        SynBucket* bucket;
        OneSynConnection* connection;

        _Pointer(SynBucket* bucket, OneSynConnection* conn) : bucket(bucket), connection(conn) {
            if (bucket) bucket->mutex.lock();
        }
        ~_Pointer() {
            if (bucket) bucket->mutex.unlock();
        }

        operator bool() const {
            return bucket != nullptr && connection != nullptr;
        }

        bool operator==(const _Pointer& other) const {
            return bucket == other.bucket && connection == other.connection;
        }
    };
    
public:
    using Pointer = std::shared_ptr<_Pointer>;
    Pointer FindAndLock(uint32_t addr, uint16_t port, uint32_t current_time);
    void Remove(Pointer ptr);   // todo - error result

private:
    SynBucket* buckets_ = nullptr;
    uint32_t number_buckets_ = 0;
    bool initialized_ = false;
};

}
