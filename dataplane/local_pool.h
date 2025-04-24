#pragma once

#include "type.h"

namespace dataplane::proxy
{

class LocalPool
{
public:
    void Add(proxy_id_t proxy_id, const ipv4_prefix_t& prefix);
    std::optional<std::pair<uint32_t, tPortId>> Allocate(proxy_id_t proxy_id, proxy_service_id_t service_id);
    void Free(proxy_service_id_t service_id, uint32_t address, tPortId port);

private:
    ipv4_prefix_t prefix_;
};

}