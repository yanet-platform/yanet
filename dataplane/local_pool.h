#pragma once

#include "type.h"

#include <queue>
#include <mutex>
#include <shared_mutex>

namespace dataplane::proxy
{

class LocalPool
{
public:
    void Add(proxy_id_t proxy_id, const ipv4_prefix_t& prefix);
    std::optional<std::pair<uint32_t, tPortId>> Allocate(proxy_id_t proxy_id, proxy_service_id_t service_id, uint32_t client_addr, tPortId client_port);
    std::optional<std::pair<uint32_t, tPortId>> FindClientByLocal(uint32_t local_addr, tPortId local_port);
    void Free(proxy_service_id_t service_id, uint32_t address, tPortId port);

private:
    std::mutex mutex_;
    std::unordered_map<proxy_id_t, std::vector<ipv4_prefix_t>> prefixes_;

    constexpr static uint16_t min_port = 1025;
    constexpr static uint16_t max_port = 65535;

    struct ConnectionInfo
    {
        uint32_t address;
        tPortId port;
    };
    std::unordered_map<proxy_service_id_t, std::queue<ConnectionInfo>> connection_queues_;

    std::map<std::pair<uint32_t, tPortId>, std::pair<uint32_t, tPortId>> local_to_clients_;

    std::queue<ConnectionInfo> make_connection_queue(proxy_id_t proxy_id);
};

class LocalPool2
{
public:
    LocalPool2(const ipv4_prefix_t& prefix);

    std::optional<std::pair<uint32_t, tPortId>> Allocate(uint32_t client_addr, tPortId client_port);
    std::optional<std::pair<uint32_t, tPortId>> FindClientByLocal(uint32_t local_addr, tPortId local_port);
    void Free(uint32_t address, tPortId port);

private:
    std::shared_mutex mutex_;
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
    std::vector<ConnectionInfo> connection_queue_;
    uint32_t first_connection_idx_;

    inline std::pair<uint32_t, tPortId> index_to_tuple(uint32_t index);
    inline uint32_t tuple_to_index(uint32_t address, tPortId port);
};

}