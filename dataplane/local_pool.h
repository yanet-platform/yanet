#pragma once

#include "type.h"

#include <queue>
#include <mutex>

namespace dataplane::proxy
{

class LocalPool
{
public:
    void Add(proxy_id_t proxy_id, const ipv4_prefix_t& prefix);
    std::optional<std::pair<uint32_t, tPortId>> Allocate(proxy_id_t proxy_id, proxy_service_id_t service_id);
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

    std::queue<ConnectionInfo> make_connection_queue(proxy_id_t proxy_id);
};

}