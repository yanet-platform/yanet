#pragma once

#include <mutex>
#include <rte_tcp.h>

#include "common/idp.h"
#include "common/static_vector.h"

#include "local_pool.h"
#include "memory_manager.h"
#include "proxy_connections.h"
#include "syncookies.h"
#include "type.h"

#define MAX_SIZE_TCP_OPTIONS 40
#define TCP_OPTIONS_MAX_COUNT 12

#define TIMEOUT_RETRANSMIT 1000 // todo
#define MAX_COUNT_RETRANSMITS_PER_SERVICE (uint32_t)16 // todo
#define MAX_COUNT_RETRANSMITS_ALL_SERVICES (uint32_t)128 // todo - must be a power of 2

namespace dataplane::proxy
{

struct TcpOptions
{
    uint32_t timestamp_value;
    uint32_t timestamp_echo;
    uint16_t mss;
    uint8_t sack_permitted;
    uint8_t window_scaling;

    uint32_t sack_count;
    uint32_t sack_start[TCP_OPTIONS_MAX_SACK_COUNT];
    uint32_t sack_finish[TCP_OPTIONS_MAX_SACK_COUNT];

    bool Read(uint8_t* data, uint32_t len);
    void ReadOnlyTimestampsAndSack(rte_tcp_hdr* tcp_header);
    uint32_t Write(rte_mbuf* mbuf, rte_ipv4_hdr** ipv4_header, rte_tcp_hdr** tcp_header) const;
    uint32_t WriteBuffer(uint8_t* data) const;
    uint32_t Size() const;

    std::string DebugInfo() const;

    constexpr bool operator==(const TcpOptions& other) const {
        return timestamp_value == other.timestamp_value && timestamp_echo == other.timestamp_echo
                && mss == other.mss && sack_permitted == other.sack_permitted
                && window_scaling == other.window_scaling;
    }

    constexpr bool operator!=(const TcpOptions& other) const {
        return !(*this == other);
    }

private:
    bool CheckSize(uint32_t index, uint32_t len, uint8_t* data, uint8_t expected);
};

// ----------------------------------------------------------------------------

struct DataForRetransmit
{
    proxy_service_id_t service_id;
    uint32_t src;
    uint32_t dst;
	uint16_t sport;
    uint16_t dport;
    uint32_t client_start_seq;
    uint32_t tcp_options_len;
    uint8_t tcp_options_data[MAX_SIZE_TCP_OPTIONS];
    common::globalBase::tFlow flow;
};

class TcpConnectionStore
{
public:
    // Update
    void proxy_update(proxy_id_t proxy_id, const dataplane::globalBase::proxy_t& proxy);
    void proxy_remove(proxy_id_t proxy_id);
    eResult proxy_service_update(proxy_service_id_t service_id, const dataplane::globalBase::proxy_service_t& service, const common::ipv4_prefix_t& prefix, dataplane::memory_manager* memory_manager);
    void proxy_service_remove(proxy_service_id_t service_id);

    void CollectGarbage();

    void UpdateSynCookieKeys();

    // Info
    common::idp::proxy_connections::response GetConnections(std::optional<proxy_service_id_t> service_id);
    common::idp::proxy_syn::response GetSyn(std::optional<proxy_service_id_t> service_id);
    common::idp::proxy_local_pool::response GetLocalPool(std::optional<proxy_service_id_t> service_id);
    common::idp::proxy_tables::response GetTables(std::optional<proxy_service_id_t> service_id);

    // Actions from worker
    bool ActionClientOnSyn(proxy_service_id_t service_id,
	                   uint32_t worker_id,
	                   const dataplane::globalBase::proxy_service_t& service,
	                   rte_mbuf* mbuf,
	                   uint64_t* counters);

    bool ActionClientOnAck(proxy_service_id_t service_id,
	                   uint32_t worker_id,
	                   const dataplane::globalBase::proxy_service_t& service,
	                   rte_mbuf* mbuf,
	                   uint64_t* counters);

    bool ActionServiceOnSynAck(proxy_service_id_t service_id,
	                       const dataplane::globalBase::proxy_service_t& service,
	                       rte_mbuf* mbuf,
	                       uint64_t* counters);

    bool ActionServiceOnAck(proxy_service_id_t service_id,
	                    const dataplane::globalBase::proxy_service_t& service,
	                    rte_mbuf* mbuf,
	                    uint64_t* counters);

    uint32_t current_time_sec;
    uint64_t current_time_ms;

    void GetDataForRetramsits(uint32_t before_time, rte_ring* ring_retransmit_free, rte_ring* ring_retransmit_send);

private:
    std::mutex mutex_;
    SynCookies syn_cookies_;

    LocalPool local_pools_[YANET_CONFIG_PROXY_SERVICES_SIZE];
    ServiceConnections service_connections_[YANET_CONFIG_PROXY_SERVICES_SIZE];
    ServiceSynConnections syn_connections_[YANET_CONFIG_PROXY_SERVICES_SIZE];

    uint32_t index_start_check_retransmits_ = 0;
    common::globalBase::tFlow next_flow_;

    uint32_t BuildSynCookieAndFillTcpOptionsAnswer(const dataplane::globalBase::proxy_service_t& service, rte_mbuf* mbuf, rte_ipv4_hdr** ipv4_header, rte_tcp_hdr** tcp_header);
    uint32_t CheckSynCookie(const dataplane::globalBase::proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header);
};

}
