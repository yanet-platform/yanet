#pragma once

#include <nlohmann/json.hpp>

#include "balancer.h"
#include "scheduler.h"
#include "stream.h"
#include "type.h"

namespace controlplane
{

class state_timeout
{
public:
	state_timeout() :
	        tcp_syn(YANET_CONFIG_STATE_TIMEOUT_DEFAULT),
	        tcp_ack(YANET_CONFIG_STATE_TIMEOUT_DEFAULT),
	        tcp_fin(YANET_CONFIG_STATE_TIMEOUT_DEFAULT),
	        udp(YANET_CONFIG_STATE_TIMEOUT_DEFAULT),
	        icmp(YANET_CONFIG_STATE_TIMEOUT_DEFAULT),
	        other(YANET_CONFIG_STATE_TIMEOUT_DEFAULT)
	{
	}

	operator std::tuple<uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t>() const
	{
		return {tcp_syn, tcp_ack, tcp_fin, udp, icmp, other};
	}

public:
	uint16_t tcp_syn;
	uint16_t tcp_ack;
	uint16_t tcp_fin;
	uint16_t udp;
	uint16_t icmp;
	uint16_t other;
};

[[maybe_unused]] static void from_json(const nlohmann::json& json,
                                       controlplane::state_timeout& state_timeout)
{
	state_timeout.tcp_syn = json.value("tcp_syn", state_timeout.tcp_syn);
	state_timeout.tcp_ack = json.value("tcp_ack", state_timeout.tcp_ack);
	state_timeout.tcp_fin = json.value("tcp_fin", state_timeout.tcp_fin);
	state_timeout.udp = json.value("udp", state_timeout.udp);
	state_timeout.icmp = json.value("icmp", state_timeout.icmp);
	state_timeout.icmp = json.value("icmpv6", state_timeout.icmp);
	state_timeout.other = json.value("other", state_timeout.other);

	if (state_timeout.tcp_syn >= YANET_CONFIG_STATE_TIMEOUT_MAX)
	{
		state_timeout.tcp_syn = YANET_CONFIG_STATE_TIMEOUT_MAX - 1;
		YANET_LOG_WARNING("state timeout (tcp_syn) set to: %u\n", state_timeout.tcp_syn);
	}

	if (state_timeout.tcp_ack >= YANET_CONFIG_STATE_TIMEOUT_MAX)
	{
		state_timeout.tcp_ack = YANET_CONFIG_STATE_TIMEOUT_MAX - 1;
		YANET_LOG_WARNING("state timeout (tcp_ack) set to: %u\n", state_timeout.tcp_ack);
	}

	if (state_timeout.tcp_fin >= YANET_CONFIG_STATE_TIMEOUT_MAX)
	{
		state_timeout.tcp_fin = YANET_CONFIG_STATE_TIMEOUT_MAX - 1;
		YANET_LOG_WARNING("state timeout (tcp_fin) set to: %u\n", state_timeout.tcp_fin);
	}

	if (state_timeout.udp >= YANET_CONFIG_STATE_TIMEOUT_MAX)
	{
		state_timeout.udp = YANET_CONFIG_STATE_TIMEOUT_MAX - 1;
		YANET_LOG_WARNING("state timeout (udp) set to: %u\n", state_timeout.udp);
	}

	if (state_timeout.icmp >= YANET_CONFIG_STATE_TIMEOUT_MAX)
	{
		state_timeout.icmp = YANET_CONFIG_STATE_TIMEOUT_MAX - 1;
		YANET_LOG_WARNING("state timeout (icmp) set to: %u\n", state_timeout.icmp);
	}

	if (state_timeout.other >= YANET_CONFIG_STATE_TIMEOUT_MAX)
	{
		state_timeout.other = YANET_CONFIG_STATE_TIMEOUT_MAX - 1;
		YANET_LOG_WARNING("state timeout (other) set to: %u\n", state_timeout.other);
	}
}

namespace route
{
class interface_t
{
public:
	interface_t()
	{
	}

	/** @todo: tag:CP_MODULES
	void load(const nlohmann::json& json);
	nlohmann::json save() const;
	*/

	void pop(common::stream_in_t& stream)
	{
		stream.pop(interfaceId);
		stream.pop(ip_prefixes);
		stream.pop(neighborIPv4Address);
		stream.pop(neighborIPv6Address);
		stream.pop(static_neighbor_mac_address_v4);
		stream.pop(static_neighbor_mac_address_v6);
		stream.pop(nextModule);
		stream.pop(acl);
		stream.pop(aclId);
		stream.pop(flow);
	}

	void push(common::stream_out_t& stream) const
	{
		stream.push(interfaceId);
		stream.push(ip_prefixes);
		stream.push(neighborIPv4Address);
		stream.push(neighborIPv6Address);
		stream.push(static_neighbor_mac_address_v4);
		stream.push(static_neighbor_mac_address_v6);
		stream.push(nextModule);
		stream.push(acl);
		stream.push(aclId);
		stream.push(flow);
	}

public:
	tInterfaceId interfaceId;

	std::set<common::ip_prefix_t> ip_prefixes;
	std::optional<common::ipv4_address_t> neighborIPv4Address;
	std::optional<common::ipv6_address_t> neighborIPv6Address;
	std::optional<common::mac_address_t> static_neighbor_mac_address_v4; ///< @todo: no directly connected (only v4 and v6 neighbor)
	std::optional<common::mac_address_t> static_neighbor_mac_address_v6; ///< @todo: no directly connected (only v4 and v6 neighbor)
	std::string nextModule;
	std::string acl;
	tAclId aclId;
	common::globalBase::tFlow flow;
};

class config_t
{
public:
	config_t() :
	        vrf("default"),
	        tunnel_enabled(false)
	{
	}

	/** @todo: tag:CP_MODULES
	void load(const nlohmann::json& json);
	nlohmann::json save() const;
	*/

	void pop(common::stream_in_t& stream)
	{
		stream.pop(routeId);
		stream.pop(to_kernel_prefixes);
		stream.pop(vrf);
		stream.pop(tunnel_enabled);
		stream.pop(ignore_tables);
		stream.pop(ipv4_source_address);
		stream.pop(ipv6_source_address);
		stream.pop(udp_destination_port);
		stream.pop(local_prefixes);
		stream.pop(peers);
		stream.pop(interfaces);
	}

	void push(common::stream_out_t& stream) const
	{
		stream.push(routeId);
		stream.push(to_kernel_prefixes);
		stream.push(vrf);
		stream.push(tunnel_enabled);
		stream.push(ignore_tables);
		stream.push(ipv4_source_address);
		stream.push(ipv6_source_address);
		stream.push(udp_destination_port);
		stream.push(local_prefixes);
		stream.push(peers);
		stream.push(interfaces);
	}

public:
	tRouteId routeId;
	std::set<common::ip_prefix_t> to_kernel_prefixes;
	std::string vrf;
	bool tunnel_enabled;
	std::set<std::string> ignore_tables;
	common::ipv4_address_t ipv4_source_address;
	common::ipv6_address_t ipv6_source_address;
	uint16_t udp_destination_port;
	std::set<common::ip_prefix_t> local_prefixes; ///< for fallback to default
	std::map<uint32_t, std::string> peers;
	std::map<std::string, interface_t> interfaces;
};

}

namespace dregress
{

class config_t
{
public:
	/** @todo: tag:CP_MODULES
	void load(const nlohmann::json& json);
	nlohmann::json save() const;
	*/

	void pop(common::stream_in_t& stream)
	{
		stream.pop(dregressId);
		stream.pop(ipv6SourcePrefixes);
		stream.pop(ipv6DestinationPrefix);
		stream.pop(ipv4SourceAddress);
		stream.pop(ipv6SourceAddress);
		stream.pop(udpDestinationPort);
		stream.pop(onlyLongest);
		stream.pop(communities);
		stream.pop(localPrefixes);
		stream.pop(announces);
		stream.pop(ourAs);
		stream.pop(nextModule);
	}

	void push(common::stream_out_t& stream) const
	{
		stream.push(dregressId);
		stream.push(ipv6SourcePrefixes);
		stream.push(ipv6DestinationPrefix);
		stream.push(ipv4SourceAddress);
		stream.push(ipv6SourceAddress);
		stream.push(udpDestinationPort);
		stream.push(onlyLongest);
		stream.push(communities);
		stream.push(localPrefixes);
		stream.push(announces);
		stream.push(ourAs);
		stream.push(nextModule);
	}

public:
	dregress_id_t dregressId;
	std::set<common::ipv6_prefix_t> ipv6SourcePrefixes;
	common::ipv6_prefix_t ipv6DestinationPrefix;
	common::ipv4_address_t ipv4SourceAddress;
	common::ipv6_address_t ipv6SourceAddress;
	uint16_t udpDestinationPort;
	bool onlyLongest;
	std::map<common::community_t, std::string> communities;
	std::set<common::ip_prefix_t> localPrefixes;
	std::set<common::ip_prefix_t> announces;
	std::set<uint32_t> ourAs;
	std::string nextModule;
};

}

namespace balancer
{

YANET_UNUSED
static uint8_t to_proto(const std::string& string)
{
	if (string == "tcp")
	{
		return IPPROTO_TCP;
	}
	else if (string == "udp")
	{
		return IPPROTO_UDP;
	}

	return 0;
}

YANET_UNUSED
constexpr const char* from_proto(const uint8_t& proto)
{
	switch (proto)
	{
		case IPPROTO_TCP:
		{
			return "tcp";
		}
		case IPPROTO_UDP:
		{
			return "udp";
		}
	}

	return "unknown";
}

using real_t = std::tuple<common::ip_address_t,
                          uint16_t, ///< port
                          uint32_t>; ///< weight

using service_t = std::tuple<balancer_service_id_t,
                             common::ip_address_t, ///< vip
                             uint8_t, ///< proto
                             uint16_t, ///< vport
                             std::optional<std::string>, ///< version
                             ::balancer::scheduler,
                             ::balancer::scheduler_params,
                             ::balancer::forwarding_method,
                             uint8_t, ///< flags: mss_fix|ops
                             std::optional<common::ipv4_prefix_t>, ///< ipv4_outer_source_network
                             std::optional<common::ipv6_prefix_t>, ///< ipv6_outer_source_network
                             std::vector<real_t>>;

class config_t
{
public:
	config_t() :
	        reals_count(0)
	{
	}

	/** @todo: tag:CP_MODULES
	void load(const nlohmann::json& json);
	nlohmann::json save() const;
	*/

	void pop(common::stream_in_t& stream)
	{
		stream.pop(balancer_id);
		stream.pop(services);
		stream.pop(source_ipv6);
		stream.pop(source_ipv4);
		stream.pop(vip_to_balancers);
		stream.pop(default_wlc_power);
		stream.pop(next_module);
	}

	void push(common::stream_out_t& stream) const
	{
		stream.push(balancer_id);
		stream.push(services);
		stream.push(source_ipv6);
		stream.push(source_ipv4);
		stream.push(vip_to_balancers);
		stream.push(default_wlc_power);
		stream.push(next_module);
	}

public:
	balancer_id_t balancer_id;
	std::vector<service_t> services; ///< @todo: std::map<>

	// when communicating with reals
	common::ipv6_address_t source_ipv6;
	common::ipv4_address_t source_ipv4;
	uint32_t default_wlc_power;

	// table taken from unrdup.cfg: relation between VIP and balancers which serve it
	std::unordered_map<common::ip_address_t, std::unordered_set<common::ip_address_t>> vip_to_balancers;

	std::string next_module;
	common::globalBase::tFlow flow;

	uint64_t reals_count;
};

}

namespace tun64
{

class config_t
{
public:
	config_t() :
	        dscpMarkType(common::eDscpMarkType::never),
	        dscp(0),
	        srcRndEnabled(false)
	{
	}

	/** @todo: tag:CP_MODULES
       void load(const nlohmann::json& json);
       nlohmann::json save() const;
       */

	void pop(common::stream_in_t& stream)
	{
		stream.pop(tun64Id);
		stream.pop(dscpMarkType);
		stream.pop(dscp);
		stream.pop(ipv6SourceAddress);
		stream.pop(srcRndEnabled);
		stream.pop(prefixes);
		stream.pop(mappings);
		stream.pop(nextModule);
	}

	void push(common::stream_out_t& stream) const
	{
		stream.push(tun64Id);
		stream.push(dscpMarkType);
		stream.push(dscp);
		stream.push(ipv6SourceAddress);
		stream.push(srcRndEnabled);
		stream.push(prefixes);
		stream.push(mappings);
		stream.push(nextModule);
	}

public:
	tun64_id_t tun64Id;

	common::eDscpMarkType dscpMarkType;
	uint8_t dscp;

	common::ipv6_address_t ipv6SourceAddress;
	bool srcRndEnabled; /// < IPv6 Source address randomization

	std::set<common::ip_prefix_t> prefixes;
	std::map<common::ipv4_address_t,
	         std::tuple<common::ipv6_address_t,
	                    std::string>>
	        mappings;

	std::string nextModule;
	common::globalBase::tFlow flow;
};

}

namespace nat64stateful
{

class config_t
{
public:
	config_t() :
	        dscp_mark_type(common::eDscpMarkType::never),
	        dscp(0)
	{
	}

	void pop(common::stream_in_t& stream)
	{
		stream.pop(nat64stateful_id);
		stream.pop(dscp_mark_type);
		stream.pop(dscp);
		stream.pop(ipv6_prefixes);
		stream.pop(ipv4_prefixes);
		stream.pop(announces);
		stream.pop(next_module);
	}

	void push(common::stream_out_t& stream) const
	{
		stream.push(nat64stateful_id);
		stream.push(dscp_mark_type);
		stream.push(dscp);
		stream.push(ipv6_prefixes);
		stream.push(ipv4_prefixes);
		stream.push(announces);
		stream.push(next_module);
	}

public:
	nat64stateful_id_t nat64stateful_id;
	common::eDscpMarkType dscp_mark_type;
	uint8_t dscp;
	std::vector<common::ipv6_prefix_t> ipv6_prefixes;
	std::vector<common::ipv4_prefix_t> ipv4_prefixes;
	std::set<common::ip_prefix_t> announces;
	controlplane::state_timeout state_timeout;
	std::string next_module;
	common::globalBase::flow_t flow;
};

}

}
