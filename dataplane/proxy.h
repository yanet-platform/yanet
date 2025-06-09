#pragma once

#include <mutex>
#include <rte_tcp.h>

#include "common/idp.h"
#include "common/static_vector.h"

#include "local_pool.h"
#include "memory_manager.h"
#include "proxy_syn.h"
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

#define TIMEOUT_ACK 10 // todo
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

inline uint16_t add_cpu_16(uint16_t value, int16_t added)
{
    return rte_cpu_to_be_16(rte_be_to_cpu_16(value) + added);
}

inline uint32_t add_cpu_32(uint32_t value, int32_t added)
{
    return rte_cpu_to_be_32(rte_be_to_cpu_32(value) + added);
}

inline uint16_t shift_cpu_16(uint16_t value, int32_t shift)
{
    uint32_t result = (shift > 0 ? uint32_t(rte_be_to_cpu_16(value)) >> shift : uint32_t(rte_be_to_cpu_16(value)) << (-shift));
    return rte_cpu_to_be_16(std::min(result, 0xffffu));
}

void FillProxyHeader(proxy_v2_ipv4_hdr* proxy_header, uint32_t src_addr, tPortId src_port, uint32_t dst_addr, tPortId dst_port);

// ----------------------------------------------------------------------------

struct ActionDrop
{
    uint32_t counter_id;
};

// Client Syn

struct ActionClientOnSyn_SynToServer
{
    uint32_t seq;
    uint32_t local_addr;
    uint16_t local_port;
};

struct ActionClientOnSyn_SynAckToClient
{
    uint32_t seq;
    uint32_t ack;
};

using ActionClientOnSyn_Result = std::variant<ActionClientOnSyn_SynToServer, ActionClientOnSyn_SynAckToClient, ActionDrop>;

// Client Ack

struct ActionClientOnAck_NewServerConnection
{
    uint32_t local_addr;
    uint16_t local_port;
    uint32_t seq;
    TcpOptions tcp_options;
};

struct ActionClientOnAck_Forward
{
    uint32_t local_addr;
    uint16_t local_port;
    uint32_t shift_seq;
    uint32_t shift_ack;
    uint32_t shift_timestamp;
    bool add_proxy_header;
};

using ActionClientOnAck_Result = std::variant<ActionClientOnAck_NewServerConnection, ActionClientOnAck_Forward, ActionDrop>;

// Server Syn+Ack

struct ActionServerOnSynAck_SynAckToClient
{
    uint32_t ack;
    uint32_t client_addr;
    uint16_t client_port;
};

struct ActionServerOnSynAck_AckToClient
{
    uint32_t client_addr;
    uint16_t client_port;
    uint32_t seq;
    uint32_t ack;
    uint32_t timestamp_shift;
    int32_t window_size_shift;
};

using ActionServerOnSynAck_Result = std::variant<ActionServerOnSynAck_SynAckToClient, ActionServerOnSynAck_AckToClient, ActionDrop>;

// Server Ack

struct ActionServerOnAck_ForwardFirst
{
    uint32_t dst_addr;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    size_t tcp_options_size;
    uint8_t tcp_options[MAX_SIZE_TCP_OPTIONS];
    int32_t window_size_shift;
};

struct ActionServerOnAck_Forward
{
    uint32_t dst_addr;
    uint16_t dst_port;
    uint32_t shift_seq;
    uint32_t timestamp_shift;
    int32_t window_size_shift;
};

using ActionServerOnAck_Result = std::variant<ActionServerOnAck_ForwardFirst, ActionServerOnAck_Forward, ActionDrop>;

// ----------------------------------------------------------------------------

enum ConnectionState
{
    SENT_SYN_SERVER,
    SENT_PROXY_HEADER,
    ESTABLISHED
};

struct OneConnection
{
    uint64_t client;    // client ip + port
    uint64_t local;     // local ip + port
    uint32_t last_time; // time of last packet
    ConnectionState state;
    uint32_t sent_seq;
    uint32_t shift_server;
    uint32_t timestamp_echo;
    uint32_t timestamp_shift;

    uint32_t client_start_seq;
    uint32_t flags;
    uint32_t client_timestamp_start;    // used for sent retransmits syn packets to service
    uint32_t cookie_data;    // used for sent retransmits syn packets to service
    int32_t window_size_shift;

    static constexpr uint32_t flag_from_synkookie = 1 << 0;
    static constexpr uint32_t flag_answer_from_server = 1 << 1;
    static constexpr uint32_t flag_nonempty_ack_from_client = 1 << 2;
    static constexpr uint32_t flag_sent_rentransmit_syn_to_server = 1 << 3;
        
    void Clear();
    bool IsExpired(uint32_t current_time);
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

struct ConnectionBucket
{
    static constexpr uint32_t bucket_size = 16;

    OneConnection connections[bucket_size];
    std::mutex mutex;

    ConnectionBucket();
    void Lock();
    void Unlock();
};

class ServiceConnections
{
    public:
    bool Initialize(proxy_service_id_t service_id,uint32_t number_connections, dataplane::memory_manager* memory_manager, uint32_t service_addr, uint16_t service_port);
    bool _TestInit(proxy_service_id_t service_id, uint32_t number_connections);
    bool _TestFree();

    bool TryInsert(uint32_t client_addr, uint16_t client_port,
                    uint32_t local_addr, uint16_t local_port,
                    ConnectionState state, uint32_t sent_seq, uint32_t client_start_seq,
                    uint32_t current_time, uint32_t timestamp_echo, uint32_t flags, uint32_t client_timestamp_start, uint32_t cookie_data);

    void GetConnections(proxy_service_id_t service_id, uint32_t current_time, common::idp::proxy_connections::response& response);

    void CollectGarbage(uint32_t current_time, LocalPool& local_pool);
    uint32_t GetDataForRetramsits(uint32_t before_time, rte_ring* ring_retransmit_free, rte_ring* ring_retransmit_send, const common::globalBase::tFlow& flow);

private:
    struct _LockPointer {
        ConnectionBucket* bucket;
        OneConnection* connection;

        _LockPointer(ConnectionBucket* bucket, OneConnection* conn) : bucket(bucket), connection(conn) {
            if (bucket) bucket->mutex.lock();
        }
        ~_LockPointer() {
            if (bucket) bucket->mutex.unlock();
        }

        operator bool() const {
            return bucket != nullptr && connection != nullptr;
        }

        bool operator==(const _LockPointer& other) const {
            return bucket == other.bucket && connection == other.connection;
        }
    };

public:
    using LockPointer = std::shared_ptr<_LockPointer>;
    LockPointer FindAndLock(uint32_t addr, uint16_t port, uint32_t current_time);

private:
    ConnectionBucket* buckets_ = nullptr;
    uint32_t number_buckets_ = 0;
    bool initialized_ = false;
    proxy_service_id_t service_id_;
    uint64_t service_key_;
};

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

    // Action from worker
    ActionClientOnSyn_Result ActionClientOnSyn(proxy_service_id_t service_id,
                                           const dataplane::globalBase::proxy_service_t& service,
                                           uint32_t current_time,
	                                       uint32_t src_addr,
	                                       uint16_t src_port,
	                                       uint32_t seq,
	                                       const TcpOptions& tcp_options);

    ActionClientOnAck_Result ActionClientOnAck(proxy_service_id_t service_id,
                                           const dataplane::globalBase::proxy_service_t& service,
                                           uint32_t current_time,
	                                       uint32_t src_addr,
	                                       uint16_t src_port,
	                                       uint32_t seq,
	                                       uint32_t ack,
                                           uint32_t timestamp_echo,
                                           bool empty_tcp_data,
                                           uint32_t client_timestamp_start);

    ActionServerOnSynAck_Result ActionServerOnSynAck(proxy_service_id_t service_id,
                                                 const dataplane::globalBase::proxy_service_t& service,
                                                 uint32_t current_time,
	                                             uint32_t dst_addr,
	                                             uint16_t dst_port,
	                                             uint32_t seq,
	                                             uint32_t ack,
                                                 const TcpOptions& tcp_options);

    ActionServerOnAck_Result ActionServerOnAck(proxy_service_id_t service_id,
                                           const dataplane::globalBase::proxy_service_t& service,
                                           uint32_t current_time,
	                                       uint32_t dst_addr,
	                                       uint16_t dst_port,
	                                       uint32_t seq,
	                                       uint32_t ack);
                                           
    uint32_t currentTime;   // todo

    void GetDataForRetramsits(uint32_t before_time, rte_ring* ring_retransmit_free, rte_ring* ring_retransmit_send);

private:
    std::mutex mutex_;
    SynCookies syn_cookies_;

    LocalPool local_pools_[YANET_CONFIG_PROXY_SERVICES_SIZE];
    ServiceConnections service_connections_[YANET_CONFIG_PROXY_SERVICES_SIZE];
    ServiceSynConnections syn_connections_[YANET_CONFIG_PROXY_SERVICES_SIZE];

    uint32_t index_start_check_retransmits_ = 0;
    common::globalBase::tFlow next_flow_;
};

}
