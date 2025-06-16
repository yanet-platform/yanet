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

class LocalPool
{
public:
    LocalPool() : initialized_(false) {}
    bool Init(proxy_service_id_t service_id, const ipv4_prefix_t& prefix, dataplane::memory_manager* memory_manager);
    bool _TestInit(const ipv4_prefix_t& prefix);
    bool _TestFree();

    uint64_t Allocate(uint32_t worker_id, uint32_t client_addr, tPortId client_port);
    uint64_t FindClientByLocal(uint32_t local_addr, tPortId local_port) const;
    void Free(uint32_t worker_id, uint64_t tuple);

    void GetLocalPool(proxy_service_id_t service_id, common::idp::proxy_local_pool::response& response) const;

    constexpr static size_t max_workers = 128;
    constexpr static uint16_t min_port = 32768;
    constexpr static uint16_t max_port = 65535;
    constexpr static uint16_t num_ports = max_port - min_port + 1;

private:
    bool initialized_;
    mutable std::shared_mutex mutex_;
    ipv4_prefix_t prefix_;


    struct ConnectionInfo
    {
        uint16_t is_used;
        union {
            struct {
                uint32_t address;
                tPortId port;
            };
            uint32_t next_idx;
        };
    };
    ConnectionInfo* connection_queue_;
    uint32_t num_connections_;
    uint32_t first_;
    uint32_t last_;

    uint32_t free_addresses_;
    uint32_t used_addresses_;

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

class LocalPool2
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

    LocalPool2();
    bool Init(proxy_service_id_t service_id, const ipv4_prefix_t& prefix, dataplane::memory_manager* memory_manager);
    bool _TestInit(const ipv4_prefix_t& prefix);
    bool _TestFree();

    uint64_t Allocate(uint32_t worker_id, uint32_t client_addr, tPortId client_port);
    uint64_t FindClientByLocal(uint32_t local_addr, tPortId local_port) const;
    void Free(uint32_t worker_id, uint64_t tuple);

    void GetLocalPool(proxy_service_id_t service_id, common::idp::proxy_local_pool::response& response) const;

    constexpr static size_t max_workers = 128;
    constexpr static uint16_t min_port = 32768;
    constexpr static uint16_t max_port = 65535;
    constexpr static uint16_t num_ports = max_port - min_port + 1;

private:
    bool initialized_;
    mutable std::mutex mutex_;
    ipv4_prefix_t prefix_;


    ConnectionsChunk* chunk_queue_;
    uint32_t num_chunks_;
    uint32_t first_;
    uint32_t last_;
    uint32_t num_free_chunks_;
    uint32_t free_first_;

    uint32_t worker_chunks_[max_workers];
    uint32_t gc_chunks_[max_workers+1];

    uint64_t* local_to_client_;

    uint32_t free_addresses_;
    uint32_t used_addresses_;

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
};

}