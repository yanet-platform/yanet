#pragma once

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
    void Add(const ipv4_prefix_t& prefix);
    bool Init(proxy_service_id_t service_id, dataplane::memory_manager* memory_manager);
    bool _TestInit();
    bool _TestFree();

    std::optional<std::pair<uint32_t, tPortId>> Allocate(uint32_t client_addr, tPortId client_port);
    std::optional<std::pair<uint32_t, tPortId>> FindClientByLocal(uint32_t local_addr, tPortId local_port) const;
    void Free(uint32_t address, tPortId port);

    void GetLocalPool(proxy_service_id_t service_id, common::idp::proxy_local_pool::response& response) const;

private:
    bool initialized_;
    mutable std::shared_mutex mutex_;
    ipv4_prefix_t prefix_;

    constexpr static uint16_t min_port = 1025;
    constexpr static uint16_t max_port = 65535;
    constexpr static uint16_t num_ports = max_port - min_port + 1;

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
    uint32_t first_connection_idx_;

    uint32_t free_addresses_;
    uint32_t used_addresses_;

    inline std::pair<uint32_t, tPortId> index_to_tuple(uint32_t index) const;
    inline uint32_t tuple_to_index(uint32_t address, tPortId port) const;
};

}