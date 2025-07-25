#pragma once

#include <rte_ether.h>

#include "common/balancer.h"
#include "common/scheduler.h"
#include "common/type.h"

class cDataPlane;
class cControlPlane;
class cWorker;
class worker_gc_t;
class cBus;
struct rte_mbuf;
struct rte_mempool;

//

struct tIPv6Extension
{
	uint8_t nextHeader;
	uint8_t extensionLength;
} __attribute__((__packed__));

struct tIPv6ExtensionFragment
{
	uint8_t nextHeader;
	uint8_t reserved;
	uint16_t offsetFlagM;
	uint32_t identification;
} __attribute__((__packed__));

using ipv6_extension_t = tIPv6Extension;
using ipv6_extension_fragment_t = tIPv6ExtensionFragment;

struct icmp_header_t
{
	union
	{
		struct
		{
			uint8_t type;
			uint8_t code;
		};

		uint16_t typeCode;
	};

	uint16_t checksum;

	union
	{
		struct
		{
			uint16_t identifier;
			uint16_t sequenceNumber;
		};

		uint32_t data32[1];
		uint16_t data16[2];
		uint8_t data8[4];
	};
} __attribute__((__packed__));

using icmpv4_header_t = icmp_header_t;

struct icmpv6_header_t
{
	union
	{
		struct
		{
			uint8_t type;
			uint8_t code;
		};

		uint16_t typeCode;
	};

	uint16_t checksum;
	uint16_t identifier;
	uint16_t sequenceNumber;
} __attribute__((__packed__));

struct ipv6_header_without_addresses_t
{
	uint32_t vtc_flow;
	uint16_t payload_len;
	uint8_t proto;
	uint8_t hop_limits;
};

struct ipv4_address_t
{
	constexpr bool operator==(const ipv4_address_t& second) const
	{
		return address == second.address;
	}

	constexpr bool operator!=(const ipv4_address_t& second) const
	{
		return address != second.address;
	}

	bool operator==(const common::ip_address_t& second) const
	{
		if (!second.is_ipv4())
		{
			return false;
		}

		return rte_cpu_to_be_32(address) == second.get_ipv4();
	}

	bool operator!=(const common::ip_address_t& second) const
	{
		return !(*this == second);
	}

	static ipv4_address_t convert(const common::ipv4_address_t& address)
	{
		ipv4_address_t result;
		result.address = rte_cpu_to_be_32(address);
		return result;
	}

	static ipv4_address_t convert(const uint32_t address)
	{
		ipv4_address_t result;
		result.address = rte_cpu_to_be_32(address);
		return result;
	}

	[[nodiscard]] bool is_default() const
	{
		return address == 0;
	}

	uint32_t address;
};

struct ipv6_address_t
{
	static constexpr auto LENGTH = 16;
	static ipv6_address_t convert(const common::ipv6_address_t& address)
	{
		ipv6_address_t result;
		const std::array<uint8_t, 16>& array = address;
		memcpy(result.bytes, array.data(), 16);
		return result;
	}

	static ipv6_address_t convert(const common::ipv4_address_t& address)
	{
		ipv6_address_t result;
		memset(result.bytes, 0, 16);
		result.mapped_ipv4_address.address = rte_cpu_to_be_32(address);
		return result;
	}

	static ipv6_address_t convert(const common::ip_address_t& address)
	{
		if (address.is_ipv4())
		{
			return convert(address.get_ipv4());
		}
		else
		{
			return convert(address.get_ipv6());
		}
	}

	void SetBinary(uint8_t bytes[LENGTH])
	{
		std::copy(bytes, bytes + LENGTH, this->bytes);
	}

	bool operator==(const ipv6_address_t& second) const
	{
		return !memcmp(bytes, second.bytes, std::size(bytes));
	}

	bool operator!=(const ipv6_address_t& second) const
	{
		return memcmp(bytes, second.bytes, std::size(bytes));
	}

	bool operator==(const common::ip_address_t& second) const
	{
		if (!second.is_ipv6())
		{
			return false;
		}

		return !memcmp(bytes, second.get_ipv6().data(), 16);
	}

	bool operator!=(const common::ip_address_t& second) const
	{
		return !(*this == second);
	}

	[[nodiscard]] bool empty() const ///< @todo: is_default()
	{
		for (auto b : bytes)
		{
			if (b != 0)
			{
				return false;
			}
		}
		return true;
	}

	void reset()
	{
		memset(bytes, 0, std::size(bytes));
	}

	union
	{
		uint8_t bytes[LENGTH]; ///< @todo: rename to address

		struct
		{
			uint8_t nap[LENGTH - sizeof(ipv4_address_t)];
			ipv4_address_t mapped_ipv4_address;
		} __attribute__((__packed__));
	};
};

struct ipv4_prefix_t
{
	ipv4_address_t address;
	uint8_t mask;
};

struct ipv6_prefix_t
{
	ipv6_address_t address;
	uint8_t mask;
};

struct tcp_option_t
{
	uint8_t kind;
	uint8_t len;
	char data[0];
} __attribute__((__packed__));

namespace dataplane
{

namespace base
{
class permanently;
class generation;
}

namespace globalBase
{
class atomic;
class generation;

//

struct tLogicalPort
{
	/// @todo: uint8_t enabled;

	tPortId portId;
	uint16_t vlanId; ///< big endian
	tVrfId vrfId;
	rte_ether_addr etherAddress;
	uint8_t flags;
	common::globalBase::tFlow flow;
};

struct tDecap
{
	/// @todo: uint8_t enabled;

	uint8_t ipv4DSCPFlags;
	uint8_t flag_ipv6_enabled;
	common::globalBase::tFlow flow;
};

struct tun64_t
{
	uint8_t srcRndEnabled : 1;
	uint8_t isConfigured : 1;
	ipv6_address_t ipv6AddressSource;
	common::globalBase::tFlow flow;
	uint8_t ipv4DSCPFlags;
};

struct route_t
{
	ipv4_address_t ipv4AddressSource;
	ipv6_address_t ipv6AddressSource;
	uint16_t udpDestinationPort;
	bool randomSource;
};

struct tInterface
{
	/// @todo: uint8_t enabled;

	tAclId aclId;
	common::globalBase::tFlow flow;
};

struct nat64stateful_t
{
	nat64stateful_t()
	{
		state_timeout.tcp_syn = YANET_CONFIG_STATE_TIMEOUT_DEFAULT;
		state_timeout.tcp_ack = YANET_CONFIG_STATE_TIMEOUT_DEFAULT;
		state_timeout.tcp_fin = YANET_CONFIG_STATE_TIMEOUT_DEFAULT;
		state_timeout.udp = YANET_CONFIG_STATE_TIMEOUT_DEFAULT;
		state_timeout.icmp = YANET_CONFIG_STATE_TIMEOUT_DEFAULT;
		state_timeout.other = YANET_CONFIG_STATE_TIMEOUT_DEFAULT;
	}

	/// @todo: uint8_t enabled;

	uint32_t pool_start;
	uint32_t pool_size{};
	tCounterId counter_id;
	uint8_t ipv4_dscp_flags;
	tVrfId vrf_lan;
	tVrfId vrf_wan;
	struct
	{
		uint16_t tcp_syn;
		uint16_t tcp_ack;
		uint16_t tcp_fin;
		uint16_t udp;
		uint16_t icmp;
		uint16_t other;
	} state_timeout;
	common::globalBase::tFlow flow;
};

struct tNat64stateless
{
	/// @todo: uint8_t enabled;

	uint8_t firewall; ///< @todo: FIREWALL
	common::globalBase::tFlow flow;
	ipv6_address_t defrag_farm_prefix;
	ipv6_address_t defrag_source_prefix;
	uint8_t farm;
	uint8_t ipv4DSCPFlags;

	/// @todo: ingressFlow;
	/// @todo: egressFlow;
};

struct nat46clat_t
{
	ipv6_address_t ipv6_source;
	ipv6_address_t ipv6_destination;
	tCounterId counter_id;
	uint8_t ipv4_dscp_flags;
	tVrfId vrf_lan;
	tVrfId vrf_wan;
	common::globalBase::tFlow flow;
};

static_assert(CONFIG_YADECAP_INTERFACES_SIZE <= 0xFFFF, "invalid size");

struct balancer_t
{
	/// @todo: uint8_t enabled;
	/// @todo: fragmentation

	// when communicating with reals
	ipv6_address_t source_ipv6;
	ipv4_address_t source_ipv4;
	uint8_t dscp_flags;

	common::globalBase::tFlow flow;
};

struct dregress_t
{
	/// @todo: uint8_t enabled;

	ipv4_address_t ipv4AddressSource;
	ipv6_address_t ipv6AddressSource;
	uint16_t udpDestinationPort;
	uint8_t onlyLongest;
	common::globalBase::tFlow flow;
};

struct nexthop ///< @todo
{
	tInterfaceId interfaceId : 16;
	uint16_t flags;
	tCounterId counter_id;
	ipv6_address_t neighbor_address;
	uint32_t labelExpTransport; ///< @todo: rename first
	uint32_t labelExpService; ///< @todo: rename second
	bool is_ipv6;
};

struct nexthop_tunnel_t
{
	tInterfaceId interface_id : 16;
	uint16_t flags;
	tCounterId counter_id;
	uint32_t label;
	ipv6_address_t nexthop_address;
	ipv6_address_t neighbor_address;
	bool is_ipv6;
};

static_assert(YANET_CONFIG_COUNTERS_SIZE <= 0xFFFFFF, "invalid YANET_CONFIG_COUNTERS_SIZE");

struct route_value_t
{
	route_value_t() = default;

	common::globalBase::eNexthopType type{common::globalBase::eNexthopType::controlPlane}; ///< @todo: DELETE

	union
	{
		struct
		{
			uint32_t ecmpCount;
			uint32_t nop;
			nexthop nexthops[CONFIG_YADECAP_GB_ECMP_SIZE];
		} interface;
	};
};

struct route_tunnel_value_t
{
	route_tunnel_value_t() = default;

	common::globalBase::eNexthopType type{common::globalBase::eNexthopType::controlPlane}; ///< @todo: DELETE

	union
	{
		struct
		{
			uint32_t weight_start;
			uint32_t weight_size;
			uint32_t nop;
			nexthop_tunnel_t nexthops[YANET_CONFIG_ROUTE_TUNNEL_ECMP_SIZE];
		} interface;
	};
};

static_assert(sizeof(route_tunnel_value_t) % 8 == 0, "invalid size of route_tunnel_value_t");

struct nat64stateful_lan_key
{
	uint32_t nat64stateful_id : 24;
	uint8_t proto;
	ipv6_address_t ipv6_source;
	ipv6_address_t ipv6_destination;
	uint16_t port_source;
	uint16_t port_destination;
};

struct nat64stateful_lan_value
{
	ipv4_address_t ipv4_source;
	uint16_t port_source;
	uint16_t timestamp_last_packet;
	uint32_t flags;
};

struct nat64stateful_wan_key
{
	uint32_t nat64stateful_id : 24;
	uint8_t proto;
	ipv4_address_t ipv4_source;
	ipv4_address_t ipv4_destination;
	uint16_t port_source;
	uint16_t port_destination;
};

struct nat64stateful_wan_value
{
	union
	{
		ipv6_address_t ipv6_source;

		struct
		{
			uint8_t nap[12];
			uint16_t port_destination;
			uint16_t timestamp_last_packet;
		};
	};

	ipv6_address_t ipv6_destination;
	uint32_t flags;
};

static_assert(YANET_CONFIG_NAT64STATEFULS_SIZE <= 0xFFFFFF, "invalid size");

struct nat64stateless_translation_t
{
	ipv6_address_t ipv6Address;

	union
	{
		ipv6_address_t ipv6DestinationAddress;

		struct
		{
			uint8_t nap1[12];
			ipv4_address_t ipv4Address;
		};
	};

	uint16_t diffPort;
	uint16_t nap3;

	union
	{
		tCounterId counter_id;

		struct
		{
			uint8_t flags : 8;
			uint32_t nap2 : 24;
		};
	};
};

static_assert(sizeof(nat64stateless_translation_t) % 8 == 0);
static_assert(YANET_CONFIG_COUNTERS_SIZE <= 0xFFFFFF, "invalid size");

struct tun64mapping_key_t
{
	tun64_id_t tun64Id;
	uint32_t ipv4Address;
};

struct tun64mapping_t
{
	tun64_id_t tun64Id;
	tCounterId counter_id;
	ipv6_address_t ipv6AddressDestination;
};
static_assert((sizeof(tun64mapping_t) + sizeof(tun64mapping_key_t)) % 8 == 0);

struct balancer_real_t
{
	ipv6_address_t destination;
	uint8_t flags;
	tCounterId counter_id;
};

struct balancer_real_state_t
{
	uint8_t flags;
	uint32_t weight : 24;
};

struct balancer_service_range_t
{
	uint32_t start;
	uint32_t size;
};

struct balancer_service_ring_t
{
	balancer_service_range_t ranges[YANET_CONFIG_BALANCER_SERVICES_SIZE];
	balancer_real_id_t reals[YANET_CONFIG_BALANCER_WEIGHTS_SIZE];
};

static_assert(YANET_CONFIG_COUNTERS_SIZE <= 0xFFFFFF, "invalid size");

struct balancer_service_t
{
	/// @todo

	union
	{
		struct
		{
			uint8_t flags : 8;
			tCounterId counter_id : 24;
		};

		uint32_t atomic1;
	};

	uint32_t real_start;
	uint32_t real_size;
	::balancer::scheduler scheduler;
	::balancer::forwarding_method forwarding_method;
	uint32_t wlc_power;

	/*
	        outer_source_network_flag:
	        zero byte stores the state for ipv4_router_source_network
	        first byte stores the state for ipv6_router_source_network
	*/
	uint8_t outer_source_network_flag;
	ipv4_prefix_t ipv4_outer_source_network;
	ipv6_prefix_t ipv6_outer_source_network;
};

static_assert(YANET_CONFIG_BALANCER_REALS_SIZE <= 0xFFFFFFFF, "invalid YANET_CONFIG_BALANCER_REALS_SIZE");
static_assert(YANET_CONFIG_BALANCER_WEIGHTS_SIZE <= 0xFFFFFFFF, "invalid YANET_CONFIG_BALANCER_WEIGHTS_SIZE");
static_assert(YANET_CONFIG_COUNTERS_SIZE <= 0xFFFFFF, "invalid YANET_CONFIG_COUNTERS_SIZE");

struct fw_state_config_t
{
	uint32_t tcp_timeout;
	uint32_t udp_timeout;
	uint32_t other_protocols_timeout;
	uint32_t sync_timeout;
};

/// Stateful firewall key for ipv4.
struct fw4_state_key_t
{
	uint16_t proto;
	uint16_t __nap;
	ipv4_address_t src_addr;
	ipv4_address_t dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
};

/// Stateful firewall key for ipv6.
struct fw6_state_key_t
{
	uint16_t proto;
	uint16_t __nap;
	ipv6_address_t src_addr;
	ipv6_address_t dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
};

enum class fw_state_type : uint8_t
{
	tcp = IPPROTO_TCP,
	udp = IPPROTO_UDP,
};

using fw_state_owner_e = common::fwstate::owner_e;

/// Stateful firewall value for UDP protocol.
struct fw_udp_state_value_t
{};

/// Stateful firewall value for TCP protocol.
struct fw_tcp_state_value_t
{
	uint8_t src_flags : 4;
	uint8_t dst_flags : 4;

	[[nodiscard]] uint8_t pack() const
	{
		return src_flags | (dst_flags << 4);
	}

	void unpack(uint8_t flags)
	{
		src_flags = flags & 15;
		dst_flags = flags >> 4;
	}
};

struct fw_state_value_t
{
	/// Transport protocol type.
	///
	/// Requires to distinguish between transport protocols to
	/// properly handle state "expire" condition.
	/// For example, UDP state is kept alive for a specific duration,
	/// while TCP requires state-machine handling (ideally).
	fw_state_type type;
	/// State owner.
	fw_state_owner_e owner;

	/// Additional transport protocol-specific state variables.
	union
	{
		fw_udp_state_value_t udp;
		fw_tcp_state_value_t tcp;
	};

	/// Unix time of when the last packet was seen.
	///
	/// Depending on transport protocol type this field is used (additionally
	/// to specific state variables if any) to figure out when it's time to
	/// collect inactive sessions.
	uint32_t last_seen;
	/// State timeout
	uint32_t state_timeout;
	/// Flow value of the corresponding rule.
	common::globalBase::tFlow flow;
	/// Unix time of when the last sync packet was emitted.
	///
	/// Must be updated during emitting a sync packet, no matter
	/// immediate or periodic.
	///
	/// In conjunction with the counter below, the periodic state
	/// update conditions are:
	///  - If "last_sync" >= some interval.
	///  - And if "packets_since_last_sync" since last sync packet > 0.
	uint32_t last_sync;
	/// Number of packets since last sync.
	///
	/// Note, that 32 bit counter seems enough even if sync interval is 1m,
	/// because then a packet rate should be ~143'000'000 PPS, which
	/// is still a big number.
	///
	/// Must be reset just before emitting a new sync packet.
	uint32_t packets_since_last_sync;
	/// Number of backward packets matched this state.
	uint64_t packets_backward;
	/// Number of forward packets matched this state.
	uint64_t packets_forward;
	/// Acl ID used to determine synchronization ports
	uint8_t acl_id;

	fw_state_value_t()
	{}
};

/// From FreeBSD `sys/netinet/ip_fw.h`.
///
/// Note that all fields except IPv6 addresses are little-endian.
struct fw_state_sync_frame_t
{
	uint32_t dst_ip;
	uint32_t src_ip;
	uint16_t dst_port;
	uint16_t src_port;
	uint8_t fib;
	uint8_t proto;
	uint8_t flags; // protocol-specific flags.
	uint8_t addr_type; // 4=ip4, 6=ip6.
	ipv6_address_t dst_ip6;
	ipv6_address_t src_ip6;
	uint32_t flow_id6;
	uint32_t extra;

	static fw_state_sync_frame_t from_state_key(const fw4_state_key_t& key)
	{
		fw_state_sync_frame_t sync_frame{};
		sync_frame.proto = uint8_t(key.proto);
		sync_frame.addr_type = 4;
		sync_frame.src_ip = key.dst_addr.address; // Note that ipfwsync keeps initial 5-tuple.
		sync_frame.dst_ip = key.src_addr.address;
		sync_frame.src_port = key.dst_port;
		sync_frame.dst_port = key.src_port;

		return sync_frame;
	}

	static fw_state_sync_frame_t from_state_key(const fw6_state_key_t& key)
	{
		fw_state_sync_frame_t sync_frame{};
		sync_frame.proto = uint8_t(key.proto);
		sync_frame.addr_type = 6;
		sync_frame.src_ip6 = key.dst_addr; // Note that ipfwsync keeps initial 5-tuple.
		sync_frame.dst_ip6 = key.src_addr;
		sync_frame.src_port = key.dst_port;
		sync_frame.dst_port = key.src_port;

		return sync_frame;
	}
};

struct fw_state_sync_config_t
{
	rte_ether_addr ether_address_destination;
	ipv6_address_t ipv6_address_source;
	ipv6_address_t ipv6_address_multicast;
	ipv6_address_t ipv6_address_unicast_source;
	ipv6_address_t ipv6_address_unicast;
	uint16_t port_multicast;
	uint16_t port_unicast;

	unsigned int flows_size;
	common::globalBase::tFlow flows[CONFIG_YADECAP_GB_ECMP_SIZE];
	common::globalBase::tFlow ingress_flow;
};

struct balancer_state_key_t
{
	uint8_t balancer_id;
	uint8_t protocol;
	uint8_t l3_balancing;
	uint8_t addr_type; // 4=ip4, 6=ip6.

	ipv6_address_t ip_source;
	ipv6_address_t ip_destination;

	uint16_t port_source;
	uint16_t port_destination;
};

static_assert(YANET_CONFIG_BALANCERS_SIZE <= 0x7F, "invalid size");

struct balancer_state_value_t
{
	uint32_t real_unordered_id;
	uint32_t timestamp_create; ///< @todo: 16bit
	uint32_t timestamp_last_packet;
	uint32_t timestamp_gc;
	uint32_t state_timeout;
};

struct state_timeout_config_t
{
	uint32_t tcp_syn_ack_timeout;
	uint32_t tcp_syn_timeout;
	uint32_t tcp_fin_timeout;
	uint32_t tcp_timeout;
	uint32_t udp_timeout;
	uint32_t default_timeout;
};

struct host_config_t
{
	ipv4_address_t ipv4_address{};
	ipv6_address_t ipv6_address{};
	bool show_real_address{};
};
}

}
