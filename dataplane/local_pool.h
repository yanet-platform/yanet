#pragma once

#include <rte_ip.h>
#include <rte_tcp.h>

#include "type.h"
#include "memory_manager.h"

#include <queue>
#include <mutex>
#include <shared_mutex>

namespace dataplane::proxy
{

struct LocalPoolStat
{
    std::vector<common::ipv4_prefix_t> prefixes;
    uint32_t total_addresses;
    uint32_t free_addresses;
    uint32_t used_addresses;
};

class LocalPool
{
public:
    constexpr static size_t chunk_size = 2047;
    struct ConnectionsChunk
    {
        union {
            uint32_t offset;
            uint32_t next_idx;
        };
        uint32_t connections[chunk_size];
    } __rte_cache_aligned;

    struct PrefixConfig
    {
        std::vector<ipv4_prefix_t> prefixes{};
        std::vector<uint32_t> prefix_first_index{};
        uint32_t* index_to_prefix = nullptr;

        uint32_t num_addresses = 0;

        void Init(const std::vector<common::ipv4_prefix_t>& upstream_nets,
                  memory_manager* memory_manager, tSocketId socket_id, proxy_service_id_t service_id)
        {
            prefixes.resize(upstream_nets.size());
            for (uint32_t i = 0; i < upstream_nets.size(); i++)
            {
                ipv4_prefix_t prefix;
                prefix.address.address = upstream_nets[i].address();
                prefix.mask = upstream_nets[i].mask();
                prefixes[i] = prefix;
            }
            prefix_first_index.resize(prefixes.size());

            for (const auto& prefix : prefixes)
                num_addresses += 1u << (32u - prefix.mask);
            
            #ifdef CONFIG_YADECAP_UNITTEST
            index_to_prefix = new uint32_t[num_addresses];
            #else
            if (index_to_prefix != nullptr) memory_manager->destroy(index_to_prefix);
            std::string name = "tcp_proxy.local_pools." + std::to_string(service_id) + ".index_to_prefix";
            index_to_prefix = memory_manager->create_static_array<uint32_t>(name.c_str(), num_addresses, socket_id);
            #endif

            uint32_t prefix_idx = 0, idx = 0;
            for (const auto& prefix : prefixes)
            {
                prefix_first_index[prefix_idx] = idx;
                for (uint32_t i = 0; i < (1u << (32u - prefix.mask)); i++, idx++)
                {
                    index_to_prefix[idx] = prefix_idx;
                }
                prefix_idx++;
            }
        }
    };

    bool Init(proxy_service_id_t service_id, const PrefixConfig& config,
              dataplane::memory_manager* memory_manager, tSocketId socket_id,
              bool rotate_addresses_first = false);

    uint64_t Allocate(uint32_t worker_id, uint32_t client_addr, tPortId client_port);
    uint64_t FindClientByLocal(uint32_t local_addr, tPortId local_port) const;
    void Free(uint32_t worker_id, uint64_t tuple);

    LocalPoolStat GetStat() const;

    constexpr static size_t max_workers = 128;
    constexpr static uint16_t min_port = 32768;
    constexpr static uint16_t max_port = 65535;
    constexpr static uint16_t num_ports = max_port - min_port + 1;

    bool NeedUpdate(const PrefixConfig& config);
    void ClearIfNotEqual(const LocalPool& other, dataplane::memory_manager* memory_manager);
    void Clear(dataplane::memory_manager* memory_manager);
    void CopyFrom(const LocalPool& other);
    void ClearLinks();

    std::string Debug() const;

private:
    struct LocalInfo
    {
        mutable rte_spinlock_t spinlock;
        uint32_t num_chunks;
        uint32_t first;
        uint32_t last;
        uint32_t num_free_chunks;
        uint32_t free_first;

        uint32_t worker_chunks[max_workers];
        uint32_t gc_chunks[max_workers+1];

        uint32_t free_addresses;
        uint32_t used_addresses;
    } __rte_cache_aligned;

    bool initialized_{false};
    const std::vector<ipv4_prefix_t>* prefixes_;
    const std::vector<uint32_t>* prefix_first_index_;
    const uint32_t* index_to_prefix_;
    uint32_t addr_offset_{0};
    bool rotate_addr_first_{false};
    uint32_t num_addrs_{0};
    ConnectionsChunk* chunk_queue_{nullptr};
    uint64_t* local_to_client_{nullptr};
    LocalInfo* local_info_{nullptr};

    inline uint32_t index_to_prefix(uint32_t index) const;
    inline uint32_t tuple_to_prefix(uint64_t tuple) const;
    inline uint64_t index_to_tuple(uint32_t index) const;
    inline uint32_t tuple_to_index(uint64_t tuple) const;

public:
    inline static uint64_t PackTuple(uint32_t addr, uint16_t port) {
        return ((uint64_t)addr << 16) | (uint64_t)port;
    }

    inline static void UnpackTuple(uint64_t tuple, uint32_t& addr, tPortId& port) {
        addr = tuple >> 16;
        port = tuple & 0xffff;
    }

    inline static void UnpackTupleSrc(uint64_t tuple, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header) {
        ipv4_header->src_addr = tuple >> 16;
        tcp_header->src_port = tuple & 0xffff;
    }

    inline static void UnpackTupleDst(uint64_t tuple, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header) {
        ipv4_header->dst_addr = tuple >> 16;
        tcp_header->dst_port = tuple & 0xffff;
    }
};

}