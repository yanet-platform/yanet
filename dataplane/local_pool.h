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
    common::ipv4_prefix_t prefix;
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
    };

    bool Init(proxy_service_id_t service_id, const ipv4_prefix_t& prefix, dataplane::memory_manager* memory_manager);

    uint64_t Allocate(uint32_t worker_id, uint32_t client_addr, tPortId client_port);
    uint64_t FindClientByLocal(uint32_t local_addr, tPortId local_port) const;
    void Free(uint32_t worker_id, uint64_t tuple);

    LocalPoolStat GetStat() const;

    constexpr static size_t max_workers = 128;
    constexpr static uint16_t min_port = 32768;
    constexpr static uint16_t max_port = 65535;
    constexpr static uint16_t num_ports = max_port - min_port + 1;

    bool NeedUpdate(const ipv4_prefix_t& prefix);
    void ClearIfNotEqual(const LocalPool& other, dataplane::memory_manager* memory_manager);
    void CopyFrom(const LocalPool& other);
    void ClearLinks();

private:
    struct LocalInfo
    {
        mutable std::mutex mutex;
        uint32_t num_chunks;
        uint32_t first;
        uint32_t last;
        uint32_t num_free_chunks;
        uint32_t free_first;

        uint32_t worker_chunks[max_workers];
        uint32_t gc_chunks[max_workers+1];

        uint32_t free_addresses;
        uint32_t used_addresses;
    };

    bool initialized_{false};
    ipv4_prefix_t prefix_;
    ConnectionsChunk* chunk_queue_{nullptr};
    uint64_t* local_to_client_{nullptr};
    LocalInfo* local_info_{nullptr};

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