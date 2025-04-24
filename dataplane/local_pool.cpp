#include "local_pool.h"

namespace dataplane::proxy
{

void LocalPool::Add(proxy_id_t proxy_id, const ipv4_prefix_t& prefix)
{
    prefix_ = prefix;
}

std::optional<std::pair<uint32_t, tPortId>> LocalPool::Allocate(proxy_id_t proxy_id, proxy_service_id_t service_id)
{
    uint32_t address = prefix_.address.address;
    return std::make_pair(rte_cpu_to_be_32(address), rte_cpu_to_be_16(1025));
}

}
