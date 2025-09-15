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

    bool Check(uint32_t i, uint64_t current_time_ms, uint32_t cost, uint32_t capacity)
    {
        last_times[i] = current_time_ms;
        if (current_time_ms > edts[i])
        {
            return true;
        }
        else if (capacity == 0 || edts[i] - current_time_ms > (capacity - cost))
        {
            return false;
        }
        return true;
    }

    bool Consume(uint32_t i, uint64_t current_time_ms, uint32_t cost, uint32_t capacity)
    {
        last_times[i] = current_time_ms;
        if (current_time_ms > edts[i])
        {
            edts[i] = current_time_ms + cost;
            return true;
        }
        else if (capacity == 0 || edts[i] - current_time_ms > (capacity - cost))
        {
            return false;
        }
        edts[i] += cost;
        return true;
    }

    uint64_t edts[bucket_size]{};
    uint64_t last_times[bucket_size]{};

    uint32_t addresses[bucket_size]{};
    rte_spinlock_t spinlock;

    void Lock()
    {
        rte_spinlock_lock(&spinlock);
    }

    void Unlock()
    {
        rte_spinlock_unlock(&spinlock);
    }

} __rte_cache_aligned;

class RateLimitTable
{
public:
    constexpr static uint64_t timeout_ms = 1000;

    bool Init(uint32_t number_connections, uint32_t max_connection_rate, uint32_t burst_capacity,
              dataplane::memory_manager* memory_manager, tSocketId socket_id, const std::string& name)
    {
        if (initialized_) return true;
        if (max_connection_rate == 0 || max_connection_rate > 1000)
        {
            YANET_LOG_ERROR("max_connection_rate must be between 1 and 1000");
            return false;
        }
        
        uint32_t number_buckets = number_connections / RateLimitBucket::bucket_size;        
        cost_ = 1000 / max_connection_rate;
        capacity_ = burst_capacity * cost_;
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

        initialized_ = true;

        return true;
    }

    void Update(uint32_t max_connection_rate, uint32_t burst_capacity)
    {
        cost_ = 1000 / max_connection_rate;
        capacity_ = burst_capacity * cost_;
    }

    bool Check(uint32_t addr, uint64_t current_time_ms)
    {
        if (unlikely(!initialized_)) return true;

        uint64_t key = Hash(addr);
        RateLimitBucket* bucket = &buckets_[key & (number_buckets_ - 1)];
        for (uint32_t i = 0; i < RateLimitBucket::bucket_size; i++)
        {
            if (bucket->addresses[i] == addr)
            {
                return bucket->Check(i, current_time_ms, cost_, capacity_);
            }
        }

        return true;
    }

    bool CheckAndConsume(uint32_t addr, uint64_t current_time_ms)
    {
        if (unlikely(!initialized_)) return true;

        uint64_t key = Hash(addr);
        RateLimitBucket* bucket = &buckets_[key & (number_buckets_ - 1)];
        uint32_t free_idx = 0xFFFFFFFF;
        bucket->Lock();
        for (uint32_t i = 0; i < RateLimitBucket::bucket_size; i++)
        {
            if (bucket->addresses[i] == addr)
            {
                bool result = bucket->Consume(i, current_time_ms, cost_, capacity_);
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
            bucket->edts[free_idx] = current_time_ms + cost_;
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
        cost_ = other.cost_;
        capacity_ = other.capacity_;
        initialized_ = other.initialized_;
    }

    void ClearLinks()
    {
        buckets_ = nullptr;
        number_buckets_ = 0;
        hash_init_ = 0;
        cost_ = 0;
        capacity_ = 0;
        initialized_ = false;
    }

    bool IsInitialized() const {
        return initialized_;
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
    RateLimitBucket* buckets_ = nullptr;
    uint32_t number_buckets_ = 0;
    uint32_t hash_init_ = 0;
    uint32_t cost_ = 0;
    uint32_t capacity_ = 0;
    bool initialized_ = false;
};

class ConnectionLimitTable
{
public:
    using hashtable_t = ::dataplane::hashtable_mod_spinlock_dynamic<uint32_t, uint64_t, 16>;

    bool Init(uint32_t number_connections, uint64_t timeout_ms,
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
        initialized_ = true;

        return true;
    }

    void Update(uint64_t timeout_ms)
    {
        timeout_ = timeout_ms;
    }

    bool Exists(uint32_t addr, uint64_t current_time_ms)
    {
        if (unlikely(!initialized_)) return false;

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
        if (unlikely(!initialized_)) return true;

        constexpr static uint64_t min_timeout_dist = 3000;
        static thread_local std::random_device rd;
        static thread_local std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> dist(timeout_ms, timeout_ms + std::max(min_timeout_dist, timeout_ms / 5));
        uint64_t time_until_ms = current_time_ms + dist(gen);
        return table_->insert_or_update(addr, time_until_ms);
    }

    void Remove(uint32_t addr)
    {
        if (unlikely(!initialized_)) return;
        table_->remove(addr);
    }

    uint32_t Size()
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
    }

    void ClearLinks()
    {
        table_ = nullptr;
        table_updater_ = nullptr;
        number_connections_ = 0;
        timeout_ = 0;
        initialized_ = false;
    }

    bool IsInitialized() const {
        return initialized_;
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

private:
    hashtable_t* table_;
    hashtable_t::updater* table_updater_;
    uint32_t number_connections_ = 0;
    uint64_t timeout_ = 0;
    bool initialized_ = false;
};

}