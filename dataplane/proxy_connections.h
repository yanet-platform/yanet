#include "type.h"
#include "local_pool.h"
#include "memory_manager.h"
#include "syncookies.h"

#include <mutex>

namespace dataplane::proxy
{

#define TIMEOUT_BUCKET_OVERFLOW 1000

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
    uint16_t client_flags;
    uint16_t service_flags;

    static constexpr uint32_t flag_from_synkookie = 1u << 0;
    static constexpr uint32_t flag_answer_from_server = 1u << 1;
    static constexpr uint32_t flag_nonempty_ack_from_client = 1u << 2;
    static constexpr uint32_t flag_sent_rentransmit_syn_to_server = 1u << 3;
    static constexpr uint32_t flag_clear_sack = 1u << 4;
    static constexpr uint32_t flag_no_timestamps = 1u << 5;
    static constexpr uint32_t flag_timestamp_fail = 1u << 6;

    void Clear() {
        local = 0;
        client_start_seq = 0;
        proxy_start_seq = 0;
        shift_server = 0;
        cookie_data = 0;
        timestamp_proxy_first = 0;
        timestamp_client_last = 0;
        timestamp_shift = 0;
        window_size_shift = 0;
        flags = 0;
        client_flags = 0;
        service_flags = 0;
    }

    bool FlagEnabled(uint32_t flag)
    {
        return (flags & flag) != 0;
    }

    void SetFlag(uint32_t flag)
    {
        flags |= flag;
    }

    bool CreatedFromSynCookie()
    {
        return FlagEnabled(flag_from_synkookie);
    }

    bool NeedRetransmit()
    {
        return CreatedFromSynCookie() && !FlagEnabled(flag_sent_rentransmit_syn_to_server | flag_nonempty_ack_from_client);
    }

    void SetSentRetransmit()
    {
        SetFlag(flag_sent_rentransmit_syn_to_server);
    }
} __rte_aligned(64);

struct SynConnection
{
    uint64_t local;     // ip + port from local pool
    uint32_t client_start_seq;  // SEQ received from client in first SYN packet
    uint32_t server_seq; // SEQ received from server in SYNACK packet
    bool server_answer; // was received answer from server

    void Clear()
    {
        local = 0;
        client_start_seq = 0;
        server_seq = 0;
        server_answer = false;
    }
} __rte_aligned(32);

template<typename ConnectionInfo>
struct ConnectionBucket
{
    static constexpr uint32_t bucket_size = 16;

    ConnectionBucket()
    {
        rte_spinlock_init(&spinlock);
        time_overflow = 0;
        for (uint32_t index = 0; index < bucket_size; index++)
        {
            Clear(index);
        }
        num_allocated = 0;
    }

    // 128 bytes = 2 cache lines
    uint64_t last_times[bucket_size];

    // 108 bytes = 2 cache lines
    uint32_t addresses[bucket_size];
    tPortId ports[bucket_size];
    uint32_t time_overflow;
    uint32_t num_allocated;
    rte_spinlock_t spinlock;

    ConnectionInfo connections[bucket_size];

    void Clear(uint32_t idx)
    {
        connections[idx].Clear();
        addresses[idx] = 0;
        ports[idx] = 0;
        last_times[idx] = 0;
        num_allocated--;
    }

    void Lock()
    {
        rte_spinlock_lock(&spinlock);
    }

    void Unlock()
    {
        rte_spinlock_unlock(&spinlock);
    }

    class Iterator
    {
    public:
        Iterator(const ConnectionBucket<ConnectionInfo>* bucket, uint32_t conn_idx) 
            : bucket_(bucket), conn_idx_(conn_idx) 
        {
            while (conn_idx_ < bucket_size && bucket_->addresses[conn_idx_] == 0) conn_idx_++;
        }

        uint32_t& operator*()
        {
            return conn_idx_;
        }

        Iterator& operator++()
        {
            conn_idx_++;
            while (conn_idx_ < bucket_size && bucket_->addresses[conn_idx_] == 0) conn_idx_++;
            return *this;
        }
        Iterator operator++(int)
        {
            Iterator tmp = *this;
            operator++();
            return tmp;
        }

        friend bool operator==(const Iterator& lhs, const Iterator& rhs)
        {
            return lhs.bucket_ == rhs.bucket_ && lhs.conn_idx_ == rhs.conn_idx_;
        }
        friend bool operator!=(const Iterator& lhs, const Iterator& rhs)
        {
            return lhs.bucket_ != rhs.bucket_ || lhs.conn_idx_ != rhs.conn_idx_;
        }

    private:
        const ConnectionBucket<ConnectionInfo>* bucket_;
        uint32_t conn_idx_;
    };

    using iterator_type = Iterator;

    iterator_type begin() { return Iterator(this, 0); }
    iterator_type end() { return Iterator(this, bucket_size); }
    iterator_type begin() const { return Iterator(this, 0); }
    iterator_type end() const { return Iterator(this, bucket_size); }
} __rte_cache_aligned;

template<typename ConnectionInfo>
struct ConnectionData {
    ConnectionBucket<ConnectionInfo>* bucket;
    ConnectionInfo* connection;
    uint32_t idx;
    
    void Init(uint32_t ip, tPortId port, uint64_t time)
    {
        bucket->addresses[idx] = ip;
        bucket->ports[idx] = port;
        bucket->last_times[idx] = time;
        memset(connection, 0, sizeof(ConnectionInfo));
        bucket->num_allocated++;
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

using ServiceConnectionData = ConnectionData<Connection>;
using SynConnectionData = ConnectionData<SynConnection>;

template<typename ConnectionInfo>
class ConnectionsTable
{
public:
    using Bucket = ConnectionBucket<ConnectionInfo>;

    bool Init(proxy_service_id_t service_id, uint32_t number_connections, dataplane::memory_manager* memory_manager, tSocketId socket_id, const std::string& name)
    {
        if (initialized_)
        {
            return true;
        }
        if constexpr (std::is_same_v<ConnectionInfo, SynConnection>) {
            if (number_connections == 0) {
                number_buckets_ = 0;
                initialized_ = true;
                return true;
            }
        }

        uint32_t number_buckets = number_connections / Bucket::bucket_size;        
#ifdef CONFIG_YADECAP_UNITTEST
        buckets_ = new Bucket[number_buckets]{};
#else
        buckets_ = memory_manager->create_static_array<Bucket>(name.data(), number_buckets, socket_id);
#endif

        if (buckets_ == nullptr)
        {
            return false;
        }

        number_buckets_ = number_buckets;
        initialized_ = true;

        return true;
    }

    template<typename T>
    class Iterator
    {
    public:
        Iterator(const ConnectionsTable<ConnectionInfo>* table, uint32_t bucket_idx) 
            : table_(table), bucket_idx_(bucket_idx)
        {
            if (unlikely(!table_->initialized_)) {
                bucket_idx_ = table_->number_buckets_;
                return;
            }
            while (bucket_idx_ < table_->number_buckets_ &&
                   table_->buckets_[bucket_idx_].num_allocated == 0) 
                bucket_idx_++;
            if (bucket_idx_ < table_->number_buckets_) 
                bucket_ = &table_->buckets_[bucket_idx_];
        }

        T& operator*()
        {
            return *bucket_;
        }
        T* operator->() 
        {
            return bucket_;
        }

        Iterator& operator++()
        {
            bucket_idx_++;
            while (bucket_idx_ < table_->number_buckets_ &&
                   table_->buckets_[bucket_idx_].num_allocated == 0) 
                bucket_idx_++;
            if (bucket_idx_ < table_->number_buckets_) 
                bucket_ = &table_->buckets_[bucket_idx_];
            return *this;
        }
        Iterator operator++(int)
        {
            Iterator tmp = *this;
            operator++();
            return tmp;
        }

        friend bool operator==(const Iterator& lhs, const Iterator& rhs)
        {
            return lhs.table_ == rhs.table_ && lhs.bucket_idx_ == rhs.bucket_idx_;
        }
        friend bool operator!=(const Iterator& lhs, const Iterator& rhs)
        {
            return lhs.table_ != rhs.table_ || lhs.bucket_idx_ != rhs.bucket_idx_;
        }

    private:
        const ConnectionsTable<ConnectionInfo>* table_;
        uint32_t bucket_idx_;
        T* bucket_;
    };

    template <typename Function>
    void ProcessAllConnectionsWithoutLocking(Function func)
    {
        for (auto& bucket : *this)
        {
            for (uint32_t idx : bucket)
            {
                func(bucket.addresses[idx], bucket.ports[idx], bucket.last_times[idx], bucket.connections[idx]);
            }
        }
    }

    template <typename FunctionCondition, typename FunctionAction>
    void ProcessAllConnectionsWithLocking(FunctionCondition condition, FunctionAction action)
    {
        for (auto& bucket : *this)
        {
            bool fulfilled = false;
            for (uint32_t idx : bucket)
            {
                if (condition(bucket.addresses[idx], bucket.ports[idx], bucket.last_times[idx], bucket.connections[idx]))
                {
                    fulfilled = true;
                    break;
                }
            }

            if (fulfilled)
            {
                bucket.Lock();
                for (uint32_t idx : bucket)
                {
                    if (condition(bucket.addresses[idx], bucket.ports[idx], bucket.last_times[idx], bucket.connections[idx]))
                    {
                        action(idx, bucket);
                    }
                }
                bucket.Unlock();
            }
        }
    }

    using iterator_type = Iterator<Bucket>;
    using const_iterator_type = Iterator<const Bucket>;

    iterator_type begin() { return Iterator<Bucket>(this, 0); }
    iterator_type end() { return Iterator<Bucket>(this, number_buckets_); }
    const_iterator_type begin() const { return Iterator<const Bucket>(this, 0); }
    const_iterator_type end() const { return Iterator<const Bucket>(this, number_buckets_); }

    size_t Size() const
    {
        size_t size = 0;
        for (const Bucket& bucket : *this)
        {
            size += bucket.num_allocated;
        }
        return size;
    }

    size_t Capacity() const {
        return number_buckets_ * Bucket::bucket_size;
    }

    TableSearchResult FindAndLock(uint32_t addr, tPortId port, uint64_t current_time, ConnectionData<ConnectionInfo>& data, bool first_overflow_check)
    {
        data.bucket = nullptr;
        data.connection = nullptr;
        if (number_buckets_ == 0)
        {
            return TableSearchResult::Overflow;
        }
        
        uint64_t key = Hash(addr, port);
        Bucket* bucket = &buckets_[key & (number_buckets_ - 1)];

        if (first_overflow_check)
        {
            if (current_time - bucket->time_overflow < TIMEOUT_BUCKET_OVERFLOW)
                return TableSearchResult::Overflow;
        }

        data.bucket = bucket;
        data.idx = Bucket::bucket_size;
        bucket->Lock();

        for (uint32_t index = 0; index < Bucket::bucket_size; index++)
        {
            if (addr == bucket->addresses[index] && port == bucket->ports[index])
            {
                bucket->last_times[index] = current_time;
                data.connection = &bucket->connections[index];
                data.idx = index;
                return TableSearchResult::Found;
            }
            else if ((data.idx == Bucket::bucket_size) && (bucket->addresses[index] == 0))
            {
                data.connection = &bucket->connections[index];
                data.idx = index;
            }
        }

        if (data.idx == Bucket::bucket_size)
        {
            bucket->time_overflow = current_time;
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

    inline static void Unpack(uint64_t key, uint32_t& addr, tPortId& port)
    {
        port = key & 0xffff;
        addr = key >> 16;
    }

    bool NeedUpdate(uint32_t number_connections)
    {
        return (number_buckets_ != number_connections / Bucket::bucket_size) || !initialized_;
    }

    void ClearIfNotEqual(const ConnectionsTable& other, dataplane::memory_manager* memory_manager)
    {
        if (buckets_ != other.buckets_ && buckets_ != nullptr)
        {
            Clear(memory_manager);
        }
    }

    void Clear(dataplane::memory_manager* memory_manager)
    {
        if (buckets_ != nullptr)
        {
#ifdef CONFIG_YADECAP_UNITTEST
            delete buckets_;
#else
            memory_manager->destroy(buckets_);
#endif
        }
        ClearLinks();
    }

    void CopyFrom(const ConnectionsTable& other)
    {
        buckets_ = other.buckets_;
        number_buckets_ = other.number_buckets_;
        initialized_ = other.initialized_;
    }

    void ClearLinks()
    {
        buckets_ = nullptr;
        number_buckets_ = 0;
        initialized_ = false;
    }

    std::string Debug() const
    {
        if (!initialized_)
        {
            return "not initialized";
        }

        char loc_buf[256];
        snprintf(loc_buf, sizeof(loc_buf), "initialized_=%d, number_buckets_=%d, buckets_=%p", initialized_, number_buckets_, buckets_);
        return std::string(loc_buf);
    }

private:
    Bucket* buckets_ = nullptr;
    uint32_t number_buckets_ = 0;
    bool initialized_ = false;
};

using ServiceConnections = ConnectionsTable<Connection>;
using ServiceSynConnections = ConnectionsTable<SynConnection>;

}