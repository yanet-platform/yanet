#include "type.h"
#include "local_pool.h"
#include "memory_manager.h"
#include "syncookies.h"

#include <mutex>

namespace dataplane::proxy
{

#define TIMEOUT_ACK 10000 // todo
#define TIMEOUT_SYN 3000 // todo - to config

template<typename ConnectionInfo>
struct ConnectionBucket
{
    static constexpr uint32_t bucket_size = 16;

    ConnectionBucket()
    {
        time_overflow = 0;
        for (uint32_t index = 0; index < bucket_size; index++)
        {
            Clear(index);
        }
    }

    uint32_t addresses[bucket_size];
    uint16_t ports[bucket_size];
    uint64_t last_times[bucket_size];

    ConnectionInfo connections[bucket_size];
    std::mutex mutex;
    uint32_t time_overflow;

    void Clear(uint32_t idx)
    {
        connections[idx].Clear();
        addresses[idx] = 0;
        ports[idx] = 0;
        last_times[idx] = 0;
    }

    bool IsExpired(uint32_t idx, uint64_t current_time, uint64_t timeout = TIMEOUT_ACK)
    {
        return last_times[idx] + timeout < current_time;
    }

    void Lock()
    {
        while(!mutex.try_lock());
    }

    void Unlock()
    {
        mutex.unlock();
    }
};

template<typename ConnectionInfo>
struct ConnectionData {
    ConnectionBucket<ConnectionInfo>* bucket;
    ConnectionInfo* connection;
    uint32_t idx;    
    
    void Init(uint32_t ip, uint16_t port, uint64_t time)
    {
        bucket->addresses[idx] = ip;
        bucket->ports[idx] = port;
        bucket->last_times[idx] = time;
        memset(connection, 0, sizeof(ConnectionInfo));
    }
    
    void Unlock()
    {
        if (bucket != nullptr)
        {
            bucket->Unlock();
        }
    }

    operator bool() const {
        return bucket != nullptr;
    }
    
    bool operator==(const ConnectionData& other) const {
        return bucket == other.bucket && idx == other.idx;
    }
};

enum class TableSearchResult : uint32_t
{
    Overflow = 0,
    Found,
    NotFound
};

struct Connection
{
    uint64_t local;     // ip + port from local pool

    // SEQ values
    uint32_t client_start_seq; // SEQ received from client in first SYN packet
    uint32_t proxy_start_seq; // SEQ sent from proxy to client in SYN+ACK packet (= our syn-cookie)
    uint32_t shift_server;
    uint32_t cookie_data;    // used for sent retransmits syn packets to service

    // Timestamps
    uint32_t timestamp_proxy_first;
    uint32_t timestamp_client_last;    // used for sent retransmits syn packets to service
    uint32_t timestamp_shift;

    int32_t window_size_shift;
    uint32_t flags;

    static constexpr uint32_t flag_from_synkookie = 1u << 0;
    static constexpr uint32_t flag_answer_from_server = 1u << 1;
    static constexpr uint32_t flag_nonempty_ack_from_client = 1u << 2;
    static constexpr uint32_t flag_sent_rentransmit_syn_to_server = 1u << 3;
    static constexpr uint32_t flag_clear_sack = 1u << 4;
    static constexpr uint32_t flag_no_timestamps = 1u << 5;
    static constexpr uint32_t flag_timestamp_fail = 1u << 6;

    void Clear() {
        local = 0;
        shift_server = 0;
        timestamp_shift = 0;
        flags = 0;
        window_size_shift = 0;
    }

    bool CreatedFromSynCookie()
    {
        return (flags & flag_from_synkookie) != 0;
    }
};

struct SynConnection
{
    uint64_t local;     // ip + port from local pool
    uint32_t client_start_seq;  // SEQ received from client in first SYN packet
    bool server_answer; // was received answer from server

    void Clear()
    {
        server_answer = false;
        local = 0;
    }
};

using ServiceConnectionData = ConnectionData<Connection>;
using SynConnectionData = ConnectionData<SynConnection>;

template<typename ConnectionInfo>
class ConnectionsTable
{
public:
    using Bucket = ConnectionBucket<ConnectionInfo>;
    
    ~ConnectionsTable()
    {
        if (initialized_) destroy();
        buckets_ = nullptr;
        number_buckets_ = 0;
        initialized_ = false;
    }

    bool Init(proxy_service_id_t service_id, uint32_t number_connections, dataplane::memory_manager* memory_manager, uint32_t service_addr, uint16_t service_port)
    {
        if (initialized_)
        {
            return true;
        }
        if constexpr (std::is_same_v<ConnectionInfo, SynConnection>) {
            if (number_connections == 0) {
                number_buckets_ = 0;
                initialized_ = true;
                service_id_ = service_id;
                service_key_ = Pack(service_addr, rte_cpu_to_be_16(service_port));
                return true;
            }
        }

        uint32_t number_buckets = number_connections / Bucket::bucket_size;
        
        tSocketId socket_id = 0; // todo !!!
        std::string name;
        if constexpr (std::is_same_v<ConnectionInfo, Connection>)
        name = "tcp_proxy.connections." + std::to_string(service_id);
        else if constexpr (std::is_same_v<ConnectionInfo, SynConnection>)
        name = "tcp_proxy.syn_connections." + std::to_string(service_id);
        if (memory_manager != nullptr)
        {
            size_t mem_size = number_buckets * sizeof(Bucket);
            YANET_LOG_WARNING("ConnectionsTable::Initialize number_connections=%d, number_buckets=%d, mem_size=%ld\n", number_connections, number_buckets, mem_size);
            buckets_ = memory_manager->create_static_array<Bucket>(name.data(), number_buckets, socket_id);
            destroy = [this, memory_manager](){
                memory_manager->destroy(buckets_);
            };
        }
        else
        {
            buckets_ = new Bucket[number_buckets];
            destroy = [this](){
                delete[] buckets_;
            };
        }
        if (buckets_ == nullptr)
        {
            return false;
        }
        else if (memory_manager == nullptr)
        {
            for (uint32_t index = 0; index < number_buckets; index++)
            {
                new (&(buckets_[index])) Bucket();
            }
        }

        number_buckets_ = number_buckets;
        initialized_ = true;
        service_id_ = service_id;
        service_key_ = Pack(service_addr, rte_cpu_to_be_16(service_port));

        return true;
    }

    void GetConnections(std::function<void(Bucket&, uint32_t)> func)
    {
        if (unlikely(!initialized_)) return;

        for (uint32_t index = 0; index < number_buckets_; index++)
        {
            Bucket& bucket = buckets_[index];
            bucket.Lock();
            for (uint32_t i = 0; i < Bucket::bucket_size; i++)
            {
                func(bucket, i);
            }
            bucket.Unlock();
        }
    }

    void CollectGarbage(uint64_t current_time, LocalPool& local_pool)
    {
        for (uint32_t index = 0; index < number_buckets_; index++)
        {
            Bucket& bucket = buckets_[index];
            bucket.Lock();
            for (uint32_t i = 0; i < Bucket::bucket_size; i++)
            {
                if (bucket.addresses[i] != 0 && bucket.IsExpired(i, current_time))
                {
                    local_pool.Free(LocalPool::max_workers, bucket.connections[i].local);
                    bucket.Clear(i);
                }
            }
            bucket.Unlock();
        }
    }

    bool IsInitialized() const
    {
        return initialized_;
    }

    size_t Size() const
    {
        if (unlikely(!initialized_)) return 0;

        size_t size = 0;
        for (uint32_t index = 0; index < number_buckets_; index++)
        {
            const Bucket& bucket = buckets_[index];
            for (uint32_t i = 0; i < Bucket::bucket_size; i++)
            {
                if (bucket.addresses[i] != 0)
                {
                    size++;
                }
            }
        }

        return size;
    }

    size_t Capacity() const {
        return number_buckets_ * Bucket::bucket_size;
    }

    uint32_t GetDataForRetramsits(std::function<bool(Bucket&, uint32_t, uint64_t)> func)
    {
        uint32_t count = 0;
        bool stop = false;
        for (uint32_t index = 0; (index < number_buckets_) && !stop; index++)
        {
            Bucket& bucket = buckets_[index];
            bucket.Lock();
            for (uint32_t i = 0; i < Bucket::bucket_size; i++)
            {
                if (func(bucket, i, service_key_)) 
                    break;
            }
            bucket.Unlock();
        }

        return count;
    }

    TableSearchResult FindAndLock(uint32_t addr, uint16_t port, uint64_t current_time, ConnectionData<ConnectionInfo>& data)
    {
        data.bucket = nullptr;
        data.connection = nullptr;
        if (number_buckets_ == 0)
        {
            return TableSearchResult::Overflow;
        }

        uint64_t key = Hash(addr, port);
        Bucket* bucket = &buckets_[key & (number_buckets_ - 1)];

        data.bucket = bucket;
        data.idx = Bucket::bucket_size;
        bucket->Lock();

        for (uint32_t index = 0; index < Bucket::bucket_size; index++)
        {
            if (!bucket->IsExpired(index, current_time))
            {
                if (addr == bucket->addresses[index] && port == bucket->ports[index])
                {
                    bucket->last_times[index] = current_time;
                    data.connection = &bucket->connections[index];
                    data.idx = index;
                    return TableSearchResult::Found;
                }
            }
            else if(data.idx == Bucket::bucket_size)
            {
                data.connection = &bucket->connections[index];
                data.idx = index;
            }
        }

        if (data.idx == Bucket::bucket_size)
        {
            bucket->Unlock();
            data.bucket = nullptr;
            data.connection = nullptr;
            return TableSearchResult::Overflow;
        }

        return TableSearchResult::NotFound;
    }

    inline static uint64_t Hash(uint32_t addr, tPortId port)
    {
        return addr ^ port;
    }

    inline static uint64_t Pack(uint32_t addr, tPortId port)
    {
        return (((uint64_t)addr) << 16) | (uint64_t)port;
    }

    inline static void Unpack(uint64_t key, uint32_t& addr, uint16_t& port)
    {
        port = key & 0xffff;
        addr = key >> 16;
    }

private:
    Bucket* buckets_ = nullptr;
    uint32_t number_buckets_ = 0;
    bool initialized_ = false;
    proxy_service_id_t service_id_;
    uint64_t service_key_;

    std::function<void()> destroy;
};

using ServiceConnections = ConnectionsTable<Connection>;
using ServiceSynConnections = ConnectionsTable<SynConnection>;

}