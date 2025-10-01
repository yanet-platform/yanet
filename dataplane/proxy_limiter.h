#pragma once

#include "type.h"
#include "memory_manager.h"
#include "syncookies.h"
#include "rte_hash_crc.h"
#include "hashtable.h"

#include <atomic>
#include <random>

namespace dataplane::proxy
{

struct RateLimitBucket
{
    static constexpr uint32_t bucket_size = 16;

    RateLimitBucket()
    {
        rte_spinlock_init(&spinlock);
    }

    bool Check(uint32_t i, uint64_t current_time_ms, uint32_t rate, uint32_t cost, uint32_t capacity)
    {
        uint32_t elapsed = current_time_ms - last_times[i];
        tokens[i] = std::min(capacity, tokens[i] + (elapsed * rate));
        last_times[i] = current_time_ms;
        return tokens[i] >= cost;
    }

    bool Consume(uint32_t i, uint64_t current_time_ms, uint32_t rate, uint32_t cost, uint32_t capacity)
    {
        uint32_t elapsed = current_time_ms - last_times[i];
        tokens[i] = std::min(capacity, tokens[i] + (elapsed * rate));
        last_times[i] = current_time_ms;

        if (tokens[i] >= cost)
        {
            tokens[i] -= cost;
            return true;
        }
        return false;
    }

    void Clear(uint32_t idx)
    {
        last_times[idx] = 0;
        tokens[idx] = 0;
        addresses[idx] = 0;
        num_allocated--;
    }

    uint64_t last_times[bucket_size]{};
    
    uint32_t tokens[bucket_size]{};
    uint32_t addresses[bucket_size]{};
    uint32_t num_allocated{};
    rte_spinlock_t spinlock;

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
        Iterator(const RateLimitBucket* bucket, uint32_t conn_idx) 
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
        const RateLimitBucket* bucket_;
        uint32_t conn_idx_;
    };

    using iterator_type = Iterator;

    iterator_type begin() { return Iterator(this, 0); }
    iterator_type end() { return Iterator(this, bucket_size); }
    iterator_type begin() const { return Iterator(this, 0); }
    iterator_type end() const { return Iterator(this, bucket_size); }
} __rte_cache_aligned;

class RateLimitTable
{
public:
    constexpr static uint64_t timeout_ms = 1000;

    bool Init(common::proxy::limit_mode mode, uint32_t number_connections, uint32_t max_connection_rate, uint32_t burst_capacity,
              dataplane::memory_manager* memory_manager, tSocketId socket_id, const std::string& name)
    {
        if (initialized_) return true;
        if (max_connection_rate == 0)
        {
            YANET_LOG_ERROR("max_connection_rate must not be 0\n");
            return false;
        }
        
        uint32_t number_buckets = number_connections / RateLimitBucket::bucket_size;     
        rate_ = std::max(max_connection_rate / 1000, 1u);   
        cost_ = std::max(1000 / max_connection_rate, 1u);
        capacity_ = std::max(burst_capacity * cost_, cost_);
#ifdef CONFIG_YADECAP_UNITTEST
        buckets_ = new RateLimitBucket[number_buckets]{};
#else
        buckets_ = memory_manager->create_static_array<RateLimitBucket>(name.data(), number_buckets, socket_id);
#endif

        if (buckets_ == nullptr)
        {
            return false;
        }

        number_buckets_ = number_buckets;
#ifdef CONFIG_YADECAP_UNITTEST
        hash_init_ = 0;
#else
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(0, std::numeric_limits<uint32_t>::max());
        hash_init_ = dist(gen);
#endif

        mode_ = mode;
        initialized_ = true;

        return true;
    }

    void Update(uint32_t max_connection_rate, uint32_t burst_capacity)
    {
        rate_ = std::max(max_connection_rate / 1000, 1u);   
        cost_ = std::max(1000 / max_connection_rate, 1u);
        capacity_ = std::max(burst_capacity * cost_, cost_);
    }

    bool Check(uint32_t addr, uint64_t current_time_ms)
    {
        if (mode_ == common::proxy::limit_mode::off) return true;

        uint64_t key = Hash(addr);
        RateLimitBucket* bucket = &buckets_[key & (number_buckets_ - 1)];
        for (uint32_t i = 0; i < RateLimitBucket::bucket_size; i++)
        {
            if (bucket->addresses[i] == addr)
            {
                return bucket->Check(i, current_time_ms, rate_, cost_, capacity_);
            }
        }

        return true;
    }

    bool CheckAndConsume(uint32_t addr, uint64_t current_time_ms)
    {
        if (mode_ == common::proxy::limit_mode::off) return true;

        uint64_t key = Hash(addr);
        RateLimitBucket* bucket = &buckets_[key & (number_buckets_ - 1)];
        uint32_t free_idx = 0xFFFFFFFF;
        bucket->Lock();
        for (uint32_t i = 0; i < RateLimitBucket::bucket_size; i++)
        {
            if (bucket->addresses[i] == addr)
            {
                bool result = bucket->Consume(i, current_time_ms, rate_, cost_, capacity_);
                bucket->Unlock();
                return result;
            }
            else if (bucket->addresses[i] == 0 || bucket->last_times[i] + timeout_ms < current_time_ms)
            {
                free_idx = i;
            }
        }

        if (free_idx != 0xFFFFFFFF)
        {
            bucket->addresses[free_idx] = addr;
            bucket->tokens[free_idx] = capacity_ - (cost_ * rate_);
            bucket->last_times[free_idx] = current_time_ms;
            bucket->Unlock();
            return true;
        }
        bucket->Unlock();
        return false;
    }

    inline uint32_t Hash(uint32_t addr)
    {
        return rte_hash_crc_4byte(addr, hash_init_);
    }

    bool NeedReallocate(uint32_t number_connections)
    {
        return (number_buckets_ != number_connections / RateLimitBucket::bucket_size) || !initialized_;
    }

    void ClearIfNotEqual(const RateLimitTable& other, dataplane::memory_manager* memory_manager)
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

    void CopyFrom(const RateLimitTable& other)
    {
        buckets_ = other.buckets_;
        number_buckets_ = other.number_buckets_;
        hash_init_ = other.hash_init_;
        rate_ = other.rate_;
        cost_ = other.cost_;
        capacity_ = other.capacity_;
        initialized_ = other.initialized_;
        mode_ = other.mode_;
    }

    void ClearLinks()
    {
        buckets_ = nullptr;
        number_buckets_ = 0;
        hash_init_ = 0;
        rate_ = 0;
        cost_ = 0;
        capacity_ = 0;
        initialized_ = false;
        mode_ = common::proxy::limit_mode::off;
    }

    bool IsInitialized() const {
        return initialized_;
    }

    common::proxy::limit_mode Mode() const
    {
        return mode_;
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

    template<typename T>
    class Iterator
    {
    public:
        Iterator(const RateLimitTable* table, uint32_t bucket_idx) 
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
        const RateLimitTable* table_;
        uint32_t bucket_idx_;
        T* bucket_;
    };

    using iterator_type = Iterator<RateLimitBucket>;
    using const_iterator_type = Iterator<const RateLimitBucket>;

    iterator_type begin() { return Iterator<RateLimitBucket>(this, 0); }
    iterator_type end() { return Iterator<RateLimitBucket>(this, number_buckets_); }
    const_iterator_type begin() const { return Iterator<const RateLimitBucket>(this, 0); }
    const_iterator_type end() const { return Iterator<const RateLimitBucket>(this, number_buckets_); }

    template <typename Function>
    void ProcessAllConnectionsWithoutLocking(Function func)
    {
        for (auto& bucket : *this)
        {
            for (uint32_t idx : bucket)
            {
                func(bucket.addresses[idx], bucket.last_times[idx]);
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
                if (condition(bucket.addresses[idx], bucket.last_times[idx]))
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
                    if (condition(bucket.addresses[idx], bucket.last_times[idx]))
                    {
                        action(idx, bucket);
                    }
                }
                bucket.Unlock();
            }
        }
    }

    void FillStat(common::proxy::OneTableInfo& stat) const
    {
        if (unlikely(!initialized_)) return;

        stat.size = number_buckets_ * RateLimitBucket::bucket_size;
        stat.count = 0;
        stat.max_bucket_size = 0;
        for (const RateLimitBucket& bucket : *this)
        {
            stat.count += bucket.num_allocated;
            stat.max_bucket_size = (bucket.num_allocated < stat.max_bucket_size ? stat.max_bucket_size : bucket.num_allocated);
        }
    }

    std::vector<size_t> BucketsStat() const
    {  
        uint32_t size = RateLimitBucket::bucket_size + 1;
        std::vector<size_t> result(size, 0);
        if (unlikely(!initialized_)) return result;

        for (const RateLimitBucket& bucket: *this)
        {
            uint32_t count = bucket.num_allocated;
            result[(count > size ? size : count)]++;
        }
        return result;
    }

private:
    RateLimitBucket* buckets_ = nullptr;
    uint32_t number_buckets_ = 0;
    uint32_t hash_init_ = 0;
    uint32_t rate_ = 0;
    uint32_t cost_ = 0;
    uint32_t capacity_ = 0;
    bool initialized_ = false;
    common::proxy::limit_mode mode_{};
};

class ConnectionLimitTable
{
public:
    using hashtable_t = ::dataplane::hashtable_mod_spinlock_dynamic<uint32_t, uint64_t, 16>;

    bool Init(common::proxy::limit_mode mode, uint32_t number_connections, uint64_t timeout_ms,
              dataplane::memory_manager* memory_manager, tSocketId socket_id, const std::string& name)
    {
        if (initialized_) return true;

        if (timeout_ms == 0)
        {
            YANET_LOG_ERROR("timeout_ms must be greater than 0\n");
            return false;
        }
        
#ifdef CONFIG_YADECAP_UNITTEST
        void* pointer = malloc(hashtable_t::calculate_sizeof(number_connections));
        if (pointer == nullptr)
        {
            return false;
        }
        memset(pointer, 0, hashtable_t::calculate_sizeof(number_connections));
        table_ = new (reinterpret_cast<hashtable_t*>(pointer)) hashtable_t();
        table_updater_ = new hashtable_t::updater();
#else
        table_ = memory_manager->create<hashtable_t>(name.data(), socket_id, hashtable_t::calculate_sizeof(number_connections));
        table_updater_ = memory_manager->create_static<hashtable_t::updater>((name + ".updater").data(), socket_id);
#endif
        if (table_ == nullptr || table_updater_ == nullptr)
        {
            return false;
        }

        table_updater_->update_pointer(table_, socket_id, number_connections);

        number_connections_ = number_connections;
        timeout_ = timeout_ms;
        mode_ = mode;
        initialized_ = true;

        return true;
    }

    void Update(uint64_t timeout_ms)
    {
        timeout_ = timeout_ms;
    }

    bool Exists(uint32_t addr, uint64_t current_time_ms)
    {
        if (mode_ == common::proxy::limit_mode::off) return false;

        uint64_t* until = nullptr;
        ::dataplane::spinlock_nonrecursive_t* lock = nullptr;
        table_->lookup(addr, until, lock);
        if (until && *until > current_time_ms)
        {
            lock->unlock();
            return true;
        }
        lock->unlock();
        return false;
    }

    bool Add(uint32_t addr, uint64_t current_time_ms)
    {
        return Add(addr, current_time_ms, timeout_);
    }

    bool Add(uint32_t addr, uint64_t current_time_ms, uint64_t timeout_ms)
    {
        if (mode_ == common::proxy::limit_mode::off) return true;

        constexpr static uint64_t min_timeout_dist = 3000;
        static thread_local std::random_device rd;
        static thread_local std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> dist(timeout_ms, timeout_ms + std::max(min_timeout_dist, timeout_ms / 5));
        uint64_t time_until_ms = current_time_ms + dist(gen);

        uint64_t* value;
        spinlock_nonrecursive_t* locker;
        uint32_t hash = table_->lookup(addr, value, locker);
        bool result = true;
        if (value == nullptr)
        {
            result = table_->insert(hash, addr, time_until_ms);
        }
        locker->unlock();
        return result;
    }

    void Remove(uint32_t addr)
    {
        if (mode_ == common::proxy::limit_mode::off) return;
        table_->remove(addr);
    }

    uint32_t Size() const
    {
        return table_updater_->get_stats().keys_count;
    }

    hashtable_t::range_t Range(uint32_t offset, uint32_t step)
    {
        return table_updater_->range(offset, step);
    }

    hashtable_t::range_t GC(uint32_t offset, uint32_t step)
    {
        return table_updater_->gc(offset, step);
    }

    bool NeedReallocate(uint32_t number_connections)
    {
        return (number_connections_ != number_connections) || !initialized_;
    }

    void ClearIfNotEqual(const ConnectionLimitTable& other, dataplane::memory_manager* memory_manager)
    {
        if (table_ != other.table_ && table_ != nullptr)
        {
            Clear(memory_manager);
        }
    }

    void Clear(dataplane::memory_manager* memory_manager)
    {
        if (table_ != nullptr)
        {
#ifdef CONFIG_YADECAP_UNITTEST
            delete table_;
#else
            memory_manager->destroy(table_);
#endif
        }
        ClearLinks();
    }

    void CopyFrom(const ConnectionLimitTable& other)
    {
        table_ = other.table_;
        table_updater_ = other.table_updater_;
        number_connections_ = other.number_connections_;
        timeout_ = other.timeout_;
        initialized_ = other.initialized_;
        mode_ = other.mode_;
    }

    void ClearLinks()
    {
        table_ = nullptr;
        table_updater_ = nullptr;
        number_connections_ = 0;
        timeout_ = 0;
        initialized_ = false;
        mode_ = common::proxy::limit_mode::off;
    }

    bool IsInitialized() const {
        return initialized_;
    }

    common::proxy::limit_mode Mode() const
    {
        return mode_;
    }

    std::string Debug() const
    {
        if (!initialized_)
        {
            return "not initialized";
        }

        char loc_buf[256];
        snprintf(loc_buf, sizeof(loc_buf), "initialized_=%d, number_connections_=%d, table_=%p", initialized_, number_connections_, table_);
        return std::string(loc_buf);
    }

    void FillStat(common::proxy::OneTableInfo& stat) const
    {
        if (unlikely(!initialized_)) return;

        const hashtable_t::stats_t& stats = table_updater_->get_stats();
        stat.size = number_connections_;
        stat.count =  stats.keys_count;
        stat.max_bucket_size = stats.longest_chain;
    }

    std::vector<size_t> BucketsStat() const
    {
        std::vector<size_t> result(hashtable_t::keys_in_chunk_size + 1, 0);
        if (unlikely(!initialized_)) return result;
        
        const hashtable_t::stats_t& stats = table_updater_->get_stats();
        for (uint32_t i = 0; i < result.size(); i++)
        {
            result[i] = stats.keys_in_chunks[i];
        }
        return result;
    }

    void AddConnCountStats(std::array<uint32_t, common::proxy::conn_count_tresholds.size() + 1> counts, uint32_t max_count, uint64_t current_time_ms)
    {
        bool next_period = false;
        if (current_time_ms - conn_stats_.period_start >= conn_stats_.period)
        {
            conn_stats_.index ^= 1;
            next_period = true;
            conn_stats_.period_start = current_time_ms;
        }
        for (uint32_t i = 0; i < conn_stats_.bins[conn_stats_.index].size(); i++)
        {
            if (next_period)
            {
                conn_stats_.bins[conn_stats_.index][i] = 0;
                conn_stats_.max_conn_count[conn_stats_.index] = 0;
            }
            if (conn_stats_.bins[conn_stats_.index][i] < counts[i])
                conn_stats_.bins[conn_stats_.index][i] = counts[i];
            if (conn_stats_.max_conn_count[conn_stats_.index] < max_count)
                conn_stats_.max_conn_count[conn_stats_.index] = max_count;
        }
    }
    
    common::proxy::ConnCountInfo GetConnCountStats()
    {
        common::proxy::ConnCountInfo result{};
        for (uint32_t i = 0; i < conn_stats_.bins[0].size(); i++)
            result.counts[i] = std::max(conn_stats_.bins[0][i], conn_stats_.bins[1][i]);
        result.max_conn_count = std::max(conn_stats_.max_conn_count[0], conn_stats_.max_conn_count[1]);
        return result;
    }

private:
    hashtable_t* table_;
    hashtable_t::updater* table_updater_;
    uint32_t number_connections_ = 0;
    uint64_t timeout_ = 0;
    bool initialized_ = false;
    common::proxy::limit_mode mode_{};
    
    struct
    {
        const uint64_t period = 60000;
        uint64_t period_start{};
        uint32_t index{};
        std::array<uint32_t, common::proxy::conn_count_tresholds.size() + 1> bins[2]{};
        uint32_t max_conn_count[2]{};
    } conn_stats_;
};

class ConnectionCounter
{
public:
    using hashtable_t = hashtable_mod_dynamic<uint32_t, uint32_t, 16>;

    bool Init(memory_manager* memory_manager, const std::string& name, tSocketId socket_id, size_t max_size)
    {
        if (insert_fail_)
        {
            insert_fail_ = false;
            connection_count_size_ = std::min(connection_count_size_ * 2, max_size);
            memory_manager->destroy(table_);
            table_ = nullptr;
        }
        if (table_ != nullptr) return true;

        table_ = memory_manager->create<hashtable_t>(name.c_str(), socket_id, hashtable_t::calculate_sizeof(connection_count_size_));
        if (table_ == nullptr)
            return false;
        table_updater_.update_pointer(table_, socket_id, connection_count_size_);

        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(0, std::numeric_limits<uint32_t>::max());
        salt_ = dist(gen);

        return true;
    }

    void Add(uint32_t address, uint32_t init_val)
    {
        if (unlikely(table_ == nullptr)) return;

        uint32_t* count = nullptr;
        uint32_t hash = table_->lookup(address + salt_, count);
        if (count)
        {
            (*count)++;
        }
        else if (!table_->insert(hash, address + salt_, init_val))
        {
            insert_fail_ = true;
        }
    }

    void Clear()
    {
        if (unlikely(table_ == nullptr)) return;

        table_->clear();
    }

    void ForEach(std::function<void(uint32_t, uint32_t)> func)
    {
        if (unlikely(table_ == nullptr)) return;

        for (auto& iter : table_updater_.range())
        {
            if (!iter.is_valid()) continue;
            func(*iter.key() - salt_, *iter.value());
        }
    }

private:
    hashtable_t* table_ = nullptr;
    hashtable_t::updater table_updater_{};
    size_t connection_count_size_ = 1024;
    bool insert_fail_ = false;
    uint32_t salt_ = 0;
};

}