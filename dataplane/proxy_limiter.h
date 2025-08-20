#pragma once

#include "type.h"
#include "memory_manager.h"
#include "syncookies.h"

#include <atomic>

namespace dataplane::proxy
{

struct RateLimitBucket
{
    static constexpr uint32_t bucket_size = 16;

    RateLimitBucket()
    {
        rte_spinlock_init(&spinlock);
    }

    bool Consume(uint32_t i, uint64_t current_time_ms)
    {
        if (current_time_ms > edts[i])
        {
            edts[i] = current_time_ms + cost;
            return true;
        }
        else if (edts[i] - current_time_ms > (capacity - cost))
        {
            return false;
        }
        edts[i] += cost;
        return true;
    }

    uint64_t edts[bucket_size]{};

    uint32_t addresses[bucket_size]{};
    uint64_t cost{};
    uint64_t capacity{};
    uint32_t ring_idx{};
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
    bool Init(uint32_t number_connections, uint64_t max_connection_rate, uint64_t burst_capacity,
              dataplane::memory_manager* memory_manager, tSocketId socket_id, const std::string& name)
    {
        if (initialized_) return true;
        
        uint32_t number_buckets = number_connections / RateLimitBucket::bucket_size;        
        uint64_t cost = 1000 / max_connection_rate;
#ifdef CONFIG_YADECAP_UNITTEST
        buckets_ = new RateLimitBucket[number_buckets]{};
        for (uint64_t i = 0; i < number_buckets; i++)
		{
            buckets_[i].cost = cost;
            buckets_[i].capacity = burst_capacity * cost;
		}
#else
        buckets_ = memory_manager->create_static_array<RateLimitBucket>(name.data(), number_buckets, socket_id, cost, burst_capacity * cost);
#endif

        if (buckets_ == nullptr)
        {
            return false;
        }

        number_buckets_ = number_buckets;
        initialized_ = true;

        return true;
    }

    bool Check(uint32_t addr, uint64_t current_time_ms)
    {
        uint64_t key = Hash(addr);
        RateLimitBucket* bucket = &buckets_[key & (number_buckets_ - 1)];
        bucket->Lock();
        for (uint32_t i = 0; i < RateLimitBucket::bucket_size; i++)
        {
            if (bucket->addresses[i] == addr)
            {
                bool result = bucket->Consume(i, current_time_ms);
                bucket->Unlock();
                return result;
            }
        }

        bucket->addresses[bucket->ring_idx] = addr;
        bucket->edts[bucket->ring_idx] = current_time_ms + bucket->cost;
        bucket->ring_idx = (bucket->ring_idx + 1) % RateLimitBucket::bucket_size;
        bucket->Unlock();
        return true;
    }

    inline static uint32_t Hash(uint32_t addr)
    {
        return addr;
    }

    bool NeedUpdate(uint32_t number_connections)
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
    RateLimitBucket* buckets_ = nullptr;
    uint32_t number_buckets_ = 0;
    bool initialized_ = false;
};

struct ConnectionLimitBucket
{
    static constexpr uint32_t bucket_size = 16;

    ConnectionLimitBucket()
    {
        rte_spinlock_init(&spinlock);
    }

    uint32_t addresses[bucket_size]{};
    uint32_t connections[bucket_size]{};
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

class ConnectionLimitTable
{
public:
    bool Init(uint32_t number_connections, uint32_t max_connections,
              dataplane::memory_manager* memory_manager, tSocketId socket_id, const std::string& name)
    {
        if (initialized_) return true;
        
        uint32_t number_buckets = number_connections / ConnectionLimitBucket::bucket_size;        
#ifdef CONFIG_YADECAP_UNITTEST
        buckets_ = new ConnectionLimitBucket[number_buckets]{};
#else
        buckets_ = memory_manager->create_static_array<ConnectionLimitBucket>(name.data(), number_buckets, socket_id);
#endif

        if (buckets_ == nullptr)
        {
            return false;
        }

        max_conns_ = max_connections;
        number_buckets_ = number_buckets;
        initialized_ = true;

        return true;
    }

    bool Add(uint32_t addr)
    {
        uint64_t key = Hash(addr);
        ConnectionLimitBucket* bucket = &buckets_[key & (number_buckets_ - 1)];
        bucket->Lock();
        uint32_t free_idx = 0xFFFFFFFF;
        for (uint32_t i = 0; i < ConnectionLimitBucket::bucket_size; i++)
        {
            if (bucket->addresses[i] == addr)
            {
                if (bucket->connections[i] < max_conns_)
                {
                    bucket->connections[i]++;
                    bucket->Unlock();
                    return true;
                }
                else
                {
                    bucket->Unlock();
                    return false;
                }
            } 
            else if (bucket->addresses[i] == 0 && free_idx == 0xFFFFFFFF)
            {
                free_idx = i;
            }
        }
        if (free_idx != 0xFFFFFFFF)
        {
            bucket->addresses[free_idx] = addr;
            bucket->connections[free_idx] = 1;
            bucket->Unlock();
            return true;
        }

        bucket->Unlock();
        return false;
    }

    void Remove(uint32_t addr, uint32_t num)
    {
        uint64_t key = Hash(addr);
        ConnectionLimitBucket* bucket = &buckets_[key & (number_buckets_ - 1)];
        bucket->Lock();
        for (uint32_t i = 0; i < ConnectionLimitBucket::bucket_size; i++)
        {
            if (bucket->addresses[i] == addr)
            {
                bucket->connections[i] -= std::min(num, bucket->connections[i]);
                bucket->Unlock();
                return;
            }
        }
        bucket->Unlock();
    }

    inline static uint32_t Hash(uint32_t addr)
    {
        return addr;
    }

    bool NeedUpdate(uint32_t number_connections)
    {
        return (number_buckets_ != number_connections / ConnectionLimitBucket::bucket_size) || !initialized_;
    }

    void ClearIfNotEqual(const ConnectionLimitTable& other, dataplane::memory_manager* memory_manager)
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

    void CopyFrom(const ConnectionLimitTable& other)
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
    ConnectionLimitBucket* buckets_ = nullptr;
    uint32_t number_buckets_ = 0;
    uint32_t max_conns_ = 0;
    bool initialized_ = false;
};

}