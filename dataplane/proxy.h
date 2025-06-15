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

#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG		19	/* MD5 Signature (RFC2385) */
#define TCPOPT_AO		29	/* Authentication Option (RFC5925) */
#define TCPOPT_MPTCP		30	/* Multipath TCP (RFC6824) */
#define TCPOPT_FASTOPEN		34	/* Fast open (RFC7413) */
#define TCPOPT_EXP		254	/* Experimental */

#define MAX_SIZE_TCP_OPTIONS 40

#define TIMEOUT_RETRANSMIT 1 // todo
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

    bool Read(uint8_t* data, uint32_t len);
    uint32_t Write(rte_mbuf* mbuf) const;
    uint32_t WriteBuffer(uint8_t* data) const;

    std::string DebugInfo() const;

private:
    bool CheckSize(uint32_t index, uint32_t len, uint8_t* data, uint8_t expected);
};    

void ShiftTcpOptions(rte_tcp_hdr* tcp_header, uint32_t sack, uint32_t timestamp_value, uint32_t timestamp_echo);

extern const uint8_t PROXY_V2_SIGNATURE[12];

enum
{
	PROXY_VERSION_V2 = 0x2
};

enum
{
	PROXY_CMD_LOCAL = 0x1,
	PROXY_CMD_PROXY
};

enum
{
	PROXY_AF_UNSET = 0x0,
	PROXY_AF_INET,
	PROXY_AF_INET6,
	PROXY_AF_UNIX
};

enum
{
	PROXY_PROTO_STREAM = 0x1,
	PROXY_PROTO_DGRAM = 0x2
};

struct proxy_v2_ipv4_hdr
{
    uint8_t signature[12]; //  Proxy Protocol v2 Signature
    union
    {
        uint8_t version_cmd;
        struct
        {
            uint8_t version : 4; // Version
            uint8_t cmd : 4; // Command
        };
    };
    union
    {
        uint8_t af_proto;
        struct
        {
            uint8_t af : 4; // Address Family
            uint8_t proto : 4; // Transport Protocol
        };
    };
    rte_be16_t addr_len; // Address Length (Big Endian)
    uint32_t src_addr;
    uint32_t dst_addr;
    rte_be16_t src_port; // Src Port (Big Endian).
    rte_be16_t dst_port;
} __rte_packed;

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

constexpr uint32_t flag_action_drop = 1 << 8;
constexpr uint32_t flag_action_to_service = 1 << 9;
constexpr uint32_t flag_action_to_client = 1 << 10;
constexpr uint32_t mask_counter_action = flag_action_drop - 1;

class TcpConnectionStore
{
public:
    // Update
    void proxy_update(proxy_id_t proxy_id, const dataplane::globalBase::proxy_t& proxy);
    void proxy_remove(proxy_id_t proxy_id);
    void proxy_add_local_pool(proxy_service_id_t service_id, const common::ip_prefix_t& prefix);
    eResult proxy_service_update(proxy_service_id_t service_id, const dataplane::globalBase::proxy_service_t& service, dataplane::memory_manager* memory_manager);
    void proxy_service_remove(proxy_service_id_t service_id);

    void CollectGarbage(uint32_t current_time);

    void UpdateSynCookieKeys();

    // Info
    common::idp::proxy_connections::response GetConnections(std::optional<proxy_service_id_t> service_id);
    common::idp::proxy_syn::response GetSyn(std::optional<proxy_service_id_t> service_id);
    common::idp::proxy_local_pool::response GetLocalPool(std::optional<proxy_service_id_t> service_id);

    // Actions from worker
    uint32_t ActionClientOnSyn(proxy_service_id_t service_id,
	                       uint32_t worker_id,
	                       const dataplane::globalBase::proxy_service_t& service,
	                       uint32_t current_time,
	                       rte_mbuf* mbuf);

    uint32_t ActionClientOnAck(proxy_service_id_t service_id,
	                       uint32_t worker_id,
	                       const dataplane::globalBase::proxy_service_t& service,
	                       uint32_t current_time,
	                       rte_mbuf* mbuf);

    uint32_t ActionServerOnSynAck(proxy_service_id_t service_id,
	                          const dataplane::globalBase::proxy_service_t& service,
	                          uint32_t current_time,
	                          rte_mbuf* mbuf);

    uint32_t ActionServerOnAck(proxy_service_id_t service_id,
	                       const dataplane::globalBase::proxy_service_t& service,
	                       uint32_t current_time,
	                       rte_mbuf* mbuf);

    uint32_t currentTime; // todo

    void GetDataForRetramsits(uint32_t before_time, rte_ring* ring_retransmit_free, rte_ring* ring_retransmit_send);

private:
    std::mutex mutex_;
    SynCookies syn_cookies_;

    LocalPool local_pools_[YANET_CONFIG_PROXY_SERVICES_SIZE];
    ServiceConnections service_connections_[YANET_CONFIG_PROXY_SERVICES_SIZE];
    ServiceSynConnections syn_connections_[YANET_CONFIG_PROXY_SERVICES_SIZE];

    uint32_t index_start_check_retransmits_ = 0;
    common::globalBase::tFlow next_flow_;

    uint32_t BuildSynCookieAndFillTcpOptionsAnswer(const dataplane::globalBase::proxy_service_t& service, rte_mbuf* mbuf, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header);
    uint32_t CheckSynCookie(const dataplane::globalBase::proxy_service_t& service, rte_ipv4_hdr* ipv4_header, rte_tcp_hdr* tcp_header);
};

}
