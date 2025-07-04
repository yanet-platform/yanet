#pragma once

#include <mutex>
#include <rte_tcp.h>

#include "common/idp.h"
#include "common/static_vector.h"

#include "base.h"
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

struct proxy_service_t;

struct ProxyTables
{
    dataplane::proxy::LocalPool local_pool;
    dataplane::proxy::ServiceConnections service_connections;
    dataplane::proxy::ServiceSynConnections syn_connections;

    bool NeedUpdate(const proxy_service_t& service);
    void ClearIfNotEqual(const ProxyTables& other, dataplane::memory_manager* memory_manager);
    eResult Allocate(dataplane::memory_manager* memory_manager, const proxy_service_t& service);
    void CopyFrom(const ProxyTables& other);    
    void ClearLinks();
};

struct UpdaterProxyTables
{
    ProxyTables tables[2];
    uint8_t active_index;
    std::mutex mutex;

    UpdaterProxyTables();
    eResult FirstUpdate(uint8_t old_index, uint8_t new_index, dataplane::memory_manager* memory_manager, const proxy_service_t& service);
    eResult SecondUpdate(uint8_t old_index, uint8_t new_index, dataplane::memory_manager* memory_manager);
    void FirstRemove(uint8_t old_index, uint8_t new_index, dataplane::memory_manager* memory_manager);
    void SecondRemove(uint8_t old_index, uint8_t new_index, dataplane::memory_manager* memory_manager);

    void FillConnections(uint64_t current_time, common::idp::proxy_connections::response& response);
    void FillSynConnections(uint64_t current_time, common::idp::proxy_syn::response& response);
    void GetTables(proxy_service_id_t service_id, common::idp::proxy_tables::response& response);

    void CollectGarbage(uint64_t current_time);
};

struct proxy_service_t
{
	proxy_service_id_t service_id;
	tCounterId counter_id;

	// proxy and service address, port
	uint32_t proxy_addr;
	tPortId proxy_port;
	uint32_t upstream_addr;
	tPortId upstream_port;

	// sizes of tables
	uint32_t size_connections_table;
	uint32_t size_syn_table;

	ipv4_prefix_t pool_prefix;
	bool send_proxy_header;
	proxy::proxy_v2_ipv4_hdr proxy_header;

	// tcp options
	bool use_sack;
	uint32_t mss;
	uint32_t winscale;
	bool timestamps;
	bool ignore_size_update_detections;

	// timeouts
	uint32_t timeout_syn_rto;
	uint32_t timeout_syn_recv;
	uint32_t timeout_established;

	ProxyTables tables;
};

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
    TcpConnectionStore();

    // Update
    eResult ServiceUpdate(proxy_service_t& service, dataplane::memory_manager* memory_manager, uint8_t currentGlobalBaseId, bool first_state_update_global_base);
    void ServiceRemove(proxy_service_t& service, dataplane::memory_manager* memory_manager, uint8_t currentGlobalBaseId, bool first_state_update_global_base);

    void CollectGarbage();

    void UpdateSynCookieKeys();

    // Info
    common::idp::proxy_connections::response GetConnections(proxy_service_id_t service_id);
    common::idp::proxy_syn::response GetSyn(proxy_service_id_t service_id);
    common::idp::proxy_tables::response GetTables(std::optional<proxy_service_id_t> service_id);

    // Actions from worker
    bool ActionClientOnSyn(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters, uint32_t worker_id);
    bool ActionClientOnAck(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters, uint32_t worker_id);
    bool ActionServiceOnSynAck(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters);
    bool ActionServiceOnAck(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters);

    uint32_t current_time_sec;
    uint64_t current_time_ms;

    void GetDataForRetramsits(uint32_t before_time, rte_ring* ring_retransmit_free, rte_ring* ring_retransmit_send);

private:
    SynCookies syn_cookies_[YANET_CONFIG_PROXY_SERVICES_SIZE];
    UpdaterProxyTables updater_proxy_tables[YANET_CONFIG_PROXY_SERVICES_SIZE];

    uint32_t index_start_check_retransmits_ = 0;
    common::globalBase::tFlow next_flow_;

    uint32_t BuildSynCookieAndFillTcpOptionsAnswer(proxy_service_id_t service_id, const proxy_service_t& service, rte_mbuf* mbuf, rte_ipv4_hdr** ipv4_header, rte_tcp_hdr** tcp_header);
    uint32_t CheckSynCookie(proxy_service_id_t service_id, const proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header);
};

}
