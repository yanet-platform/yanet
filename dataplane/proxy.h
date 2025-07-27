#pragma once

#include <mutex>
#include <rte_tcp.h>

#include "common/controlplaneconfig.h"
#include "common/idp.h"
#include "common/ringlog.h"
#include "common/static_vector.h"

#include "base.h"
#include "local_pool.h"
#include "memory_manager.h"
#include "proxy_connections.h"
#include "proxy_debug.h"
#include "syncookies.h"
#include "type.h"

#define MAX_SIZE_TCP_OPTIONS 40
#define TCP_OPTIONS_MAX_COUNT 12

#define TIMEOUT_RETRANSMIT 1000 // todo
#define MAX_COUNT_RETRANSMITS_ALL_SERVICES (uint32_t)128 // todo - must be a power of 2

namespace dataplane::proxy
{

struct proxy_service_config_t
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
    
    controlplane::proxy::tcp_options_t tcp_options;
	controlplane::proxy::timeouts_t timeouts;
    uint64_t debug_flags;

    bool EnabledFlag(uint8_t flag) const;

    static constexpr uint64_t flag_dont_use_bucket_optimization = (1ul << 0);
    static constexpr uint64_t flag_ignore_size_update_detections = (1ul << 1);
    static constexpr uint64_t flag_ignore_check_client_first_ack = (1ul << 2);
};

struct ProxyTables
{
    dataplane::proxy::LocalPool local_pool;
    dataplane::proxy::ServiceConnections service_connections;
    dataplane::proxy::ServiceSynConnections syn_connections;

    bool NeedUpdate(const proxy_service_config_t& service_config);
    void ClearIfNotEqual(const ProxyTables& other, dataplane::memory_manager* memory_manager);
    eResult Allocate(dataplane::memory_manager* memory_manager, const proxy_service_config_t& service_config);
    void CopyFrom(const ProxyTables& other);    
    void ClearLinks();
    void Clear(dataplane::memory_manager* memory_manager);
};


struct proxy_service_t
{
    proxy_service_config_t config;
	proxy::proxy_v2_ipv4_hdr proxy_header;
	ProxyTables tables;
    SynCookies syn_cookie;

    void Debug() const;
    void UpdateProxyHeader();
};

struct proxy_service_on_socket_t
{
    proxy_service_config_t config;
	ProxyTables tables;
    bool enabled;
    std::shared_mutex mutex;
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

    bool Read(rte_tcp_hdr* tcp_header);
    bool ReadOnlyTimestampsAndSack(rte_tcp_hdr* tcp_header);
    uint32_t WriteSYN(rte_mbuf* mbuf, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header) const;
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
    void ActivateSocket(tSocketId socket_id);
    eResult ServiceUpdateOnSocket(tSocketId socket_id, dataplane::proxy::proxy_service_t& service, tCounterId counter_id, const controlplane::proxy::service_t& service_info, bool first_state_update_global_base, dataplane::memory_manager* memory_manager);
    void ServiceRemoveOnSocket(tSocketId socket_id, proxy_service_id_t service_id, dataplane::memory_manager* memory_manager);

    void CollectGarbage(tSocketId socket_id, uint64_t current_time_ms);

    void UpdateSynCookieKeys();

    // Info
    common::idp::proxy_connections::response GetConnections(proxy_service_id_t service_id);
    common::idp::proxy_syn::response GetSyn(proxy_service_id_t service_id);
    common::idp::proxy_tables::response GetTables(const std::vector<std::pair<proxy_service_id_t, std::string>>& services);

    // Actions from worker
    bool ActionClientOnSyn(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters, uint32_t worker_id, common::ringlog::LogInfo& ringlog, uint32_t current_time_sec, uint64_t current_time_ms);
    bool ActionClientOnAck(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters, uint32_t worker_id, common::ringlog::LogInfo& ringlog, uint32_t current_time_sec, uint64_t current_time_ms);
    bool ActionServiceOnSynAck(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters, common::ringlog::LogInfo& ringlog, uint32_t current_time_sec, uint64_t current_time_ms);
    bool ActionServiceOnAck(rte_mbuf* mbuf, const dataplane::base::generation& base, uint64_t* counters, common::ringlog::LogInfo& ringlog, uint32_t current_time_sec, uint64_t current_time_ms);

    bool GetDataForRetramsits(const proxy_service_config_t& service_config, rte_ring* ring_retransmit_free, rte_ring* ring_retransmit_send);
    proxy_service_id_t GetIndexServiceForNextRetransmit();

private:
	std::map<tSocketId, std::array<dataplane::proxy::proxy_service_on_socket_t, YANET_CONFIG_PROXY_SERVICES_SIZE>> proxy_services;

    SynCookies syn_cookies_[YANET_CONFIG_PROXY_SERVICES_SIZE];

    proxy_service_id_t index_start_check_retransmits_ = YANET_CONFIG_PROXY_SERVICES_SIZE;
    common::globalBase::tFlow next_flow_;

    void PrepareSynToClient(proxy_service_id_t service_id, const proxy_service_t& service,
                            rte_mbuf* mbuf, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header, uint64_t* counters, uint32_t current_time_sec);
    uint32_t CheckSynCookie(proxy_service_id_t service_id, const proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header);
};

}
