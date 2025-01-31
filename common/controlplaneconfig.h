#pragma once

#include <nlohmann/json.hpp>

#include "balancer.h"
#include "scheduler.h"
#include "type.h"

namespace controlplane
{

class state_timeout
{
public:
	state_timeout() = default;

	operator std::tuple<uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t>() const
	{
		return {tcp_syn, tcp_ack, tcp_fin, udp, icmp, other};
	}

public:
	uint16_t tcp_syn{YANET_CONFIG_STATE_TIMEOUT_DEFAULT};
	uint16_t tcp_ack{YANET_CONFIG_STATE_TIMEOUT_DEFAULT};
	uint16_t tcp_fin{YANET_CONFIG_STATE_TIMEOUT_DEFAULT};
	uint16_t udp{YANET_CONFIG_STATE_TIMEOUT_DEFAULT};
	uint16_t icmp{YANET_CONFIG_STATE_TIMEOUT_DEFAULT};
	uint16_t other{YANET_CONFIG_STATE_TIMEOUT_DEFAULT};
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
	interface_t() = default;

	/** @todo: tag:CP_MODULES
	void load(const nlohmann::json& json);
	nlohmann::json save() const;
	*/

	SERIALIZABLE(interfaceId, ip_prefixes, neighborIPv4Address, neighborIPv6Address, static_neighbor_mac_address_v4, static_neighbor_mac_address_v6, nextModule, acl, aclId, flow);

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
	        vrf(YANET_RIB_VRF_DEFAULT),
	        tunnel_enabled(false)
	{
	}

	/** @todo: tag:CP_MODULES
	void load(const nlohmann::json& json);
	nlohmann::json save() const;
	*/

	SERIALIZABLE(routeId, to_kernel_prefixes, vrf, tunnel_enabled, ignore_tables, ipv4_source_address, ipv6_source_address, udp_destination_port, local_prefixes, peers, interfaces);

public:
	tRouteId routeId;
	std::set<common::ip_prefix_t> to_kernel_prefixes;
	std::string vrf{"default"};
	bool tunnel_enabled{};
	std::set<std::string> ignore_tables;
	common::ipv4_address_t ipv4_source_address;
	common::ipv6_address_t ipv6_source_address;
	uint16_t udp_destination_port;
	std::set<common::ip_prefix_t> local_prefixes; ///< for fallback to default
	std::map<uint32_t, std::string> peers;
	std::map<std::string, interface_t> interfaces;
	bool random_source{};
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

	SERIALIZABLE(dregressId, ipv6SourcePrefixes, ipv6DestinationPrefix, ipv4SourceAddress, ipv6SourceAddress, udpDestinationPort, onlyLongest, communities, localPrefixes, announces, ourAs, nextModule);

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

[[maybe_unused]] static uint8_t to_proto(const std::string& string)
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

[[maybe_unused]] constexpr const char* from_proto(const uint8_t& proto)
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
                          std::optional<uint16_t>, ///< port
                          uint32_t>; ///< weight

using service_t = std::tuple<balancer_service_id_t,
                             common::ip_address_t, ///< vip
                             uint8_t, ///< proto
                             std::optional<uint16_t>, ///< vport
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
	config_t() = default;

	/** @todo: tag:CP_MODULES
	void load(const nlohmann::json& json);
	nlohmann::json save() const;
	*/

	SERIALIZABLE(balancer_id, services, source_ipv6, source_ipv4, vip_to_balancers, default_wlc_power, next_module);

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

	uint64_t reals_count{};
};

}

namespace tun64
{

class config_t
{
public:
	config_t() = default;

	/** @todo: tag:CP_MODULES
       void load(const nlohmann::json& json);
       nlohmann::json save() const;
       */

	SERIALIZABLE(tun64Id, dscpMarkType, dscp, ipv6SourceAddress, srcRndEnabled, prefixes, mappings, nextModule);

public:
	tun64_id_t tun64Id;

	common::eDscpMarkType dscpMarkType{common::eDscpMarkType::never};
	uint8_t dscp{};

	common::ipv6_address_t ipv6SourceAddress;
	bool srcRndEnabled{}; /// < IPv6 Source address randomization

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
	config_t() = default;

	SERIALIZABLE(nat64stateful_id, dscp_mark_type, dscp, ipv6_prefixes, ipv4_prefixes, announces, next_module, vrf_lan_name, vrf_wan_name, vrf_lan, vrf_wan);

public:
	nat64stateful_id_t nat64stateful_id;
	common::eDscpMarkType dscp_mark_type{common::eDscpMarkType::never};
	uint8_t dscp{};
	std::vector<common::ipv6_prefix_t> ipv6_prefixes;
	std::vector<common::ipv4_prefix_t> ipv4_prefixes;
	std::set<common::ip_prefix_t> announces;
	std::string vrf_lan_name;
	std::string vrf_wan_name;
	tVrfId vrf_lan;
	tVrfId vrf_wan;
	controlplane::state_timeout state_timeout;
	std::string next_module;
	common::globalBase::flow_t flow;
};

}

}
