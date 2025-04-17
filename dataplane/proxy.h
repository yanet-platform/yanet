#pragma once

#include "type.h"

#include <mutex>

#define MAX_SIZE_TCP_OPTIONS 20

namespace dataplane::proxy
{

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

struct AcceptClientSyn
{
    uint32_t seq;
    uint32_t ack;
};

struct ActionClientOnAckNewServerConnection
{
    uint32_t local_addr;
    uint16_t local_port;
    uint32_t seq;
    uint8_t tcp_options[MAX_SIZE_TCP_OPTIONS];
	size_t tcp_options_size;
};

struct ActionClientOnAckForward
{
    uint32_t local_addr;
    uint16_t local_port;
    uint32_t shift_ack;
};

struct ActionDrop
{
    uint32_t counter_id;
};

using ActionClientOnAckResult = std::variant<ActionClientOnAckNewServerConnection, ActionClientOnAckForward, ActionDrop>;

struct ActionServerOnSynAckSentProxyHeader
{
    uint32_t src_addr;
    uint16_t src_port;
    uint32_t seq;
    uint32_t ack;
};

using ActionServerOnSynAckResult = std::variant<ActionServerOnSynAckSentProxyHeader, ActionDrop>;

struct ActionServerOnAckForwardFirst
{
    uint32_t dst_addr;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    size_t tcp_options_size;
    uint8_t tcp_options[MAX_SIZE_TCP_OPTIONS];
};

struct ActionServerOnAckForward
{
    uint32_t dst_addr;
    uint16_t dst_port;
    uint32_t shift_seq;
};

using ActionServerOnAckResult = std::variant<ActionServerOnAckForwardFirst, ActionServerOnAckForward, ActionDrop>;

using connection_key = std::tuple<proxy_service_id_t, uint32_t, uint16_t>;  // service_id, src_addr, src_port

struct SynConnectionInfo
{
    uint32_t recv_seq;
    uint32_t sent_seq;
    size_t tcp_options_size;
    uint8_t tcp_options[MAX_SIZE_TCP_OPTIONS];
    // todo: time
};

enum ConnectionState
{
    SENT_SYN_SERVER,
    SENT_PROXY_HEADER,
    ESTABLISHED
};

struct ConnectionInfo
{
    uint32_t local_addr;
    uint16_t local_port;
    ConnectionState state;
    size_t tcp_options_size;
    uint8_t tcp_options[MAX_SIZE_TCP_OPTIONS];
    uint32_t sent_seq;
    uint32_t shift_seq;
};

class LocalPool
{
public:
    void Add(proxy_id_t proxy_id, const common::ip_prefix_t& prefix);
    std::optional<std::pair<uint32_t, uint16_t>> Allocate(proxy_id_t proxy_id, proxy_service_id_t service_id);

private:
    common::ip_prefix_t prefix_;
};

class SynFromClients
{
public:
	std::optional<AcceptClientSyn> ActionClientOnSyn(proxy_id_t proxy_id,
	                                                 proxy_service_id_t service_id,
	                                                 uint32_t src_addr,
	                                                 uint16_t src_port,
	                                                 uint32_t seq,
	                                                 uint8_t* tcp_options,
	                                                 size_t tcp_options_size);

    SynConnectionInfo* FindConnection(connection_key key);

private:
    

    std::mutex mutex_;
    std::map<connection_key, SynConnectionInfo> connections_;
};

class TcpConnectionStore
{
public:
    // Update
    void proxy_update(proxy_id_t proxy_id, const dataplane::globalBase::proxy_t& proxy);
    void proxy_remove(proxy_id_t proxy_id);
    void proxy_add_local_pool(proxy_id_t proxy_id, const common::ip_prefix_t& prefix);
    void proxy_service_update(proxy_service_id_t service_id, const dataplane::globalBase::proxy_service_t& service);
    void proxy_service_remove(proxy_service_id_t service_id);

    // Action from worker
    std::optional<AcceptClientSyn> ActionClientOnSyn(proxy_id_t proxy_id,
	                                             proxy_service_id_t service_id,
	                                             uint32_t src_addr,
	                                             uint16_t src_port,
	                                             uint32_t seq,
	                                             uint8_t* tcp_options,
                                                 size_t tcp_options_size);

    ActionClientOnAckResult ActionClientOnAck(proxy_id_t proxy_id,
	                                      proxy_service_id_t service_id,
	                                      uint32_t src_addr,
	                                      uint16_t src_port,
	                                      uint32_t seq,
	                                      uint32_t ack);

    ActionServerOnSynAckResult ActionServerOnSynAck(proxy_id_t proxy_id,
	                                            proxy_service_id_t service_id,
	                                            uint32_t dst_addr,
	                                            uint16_t dst_port,
	                                            uint32_t seq,
	                                            uint32_t ack,
	                                            uint8_t* tcp_options,
	                                            size_t tcp_options_size);

    ActionServerOnAckResult ActionServerOnAck(proxy_id_t proxy_id,
	                                      proxy_service_id_t service_id,
	                                      uint32_t dst_addr,
	                                      uint16_t dst_port,
	                                      uint32_t seq,
	                                      uint32_t ack);

    private:
    std::mutex mutex_;
    SynFromClients table_syn_;
    LocalPool local_pool_;
    std::map<connection_key, ConnectionInfo> connections_;
    std::map<connection_key, connection_key> server_connections_;
};

}
