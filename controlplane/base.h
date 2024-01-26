#pragma once

#include <array>
#include <map>
#include <vector>

#include "common/controlplaneconfig.h"
#include "common/idp.h"
#include "common/nat46clat.h"
#include "common/type.h"
#include "libfwparser/fw_parser.h"

#include "type.h"

namespace controlplane
{

namespace base
{

class logical_port_t
{
public:
	logical_port_t() :
	        vlanId(0),
	        promiscuousMode(0)
	{
	}

public:
	tLogicalPortId logicalPortId;

	std::string physicalPort;
	tPortId physicalPortId;
	uint16_t vlanId;
	mac_address_t macAddress;
	uint8_t promiscuousMode;
	std::string nextModule;
	common::globalBase::tFlow flow;
};

class decap_t
{
public:
	decap_t() :
	        dscpMarkType(common::eDscpMarkType::never),
	        dscp(0)
	{
	}

	std::set<ipv6_prefix_t> prefixes() const
	{
		std::set<ipv6_prefix_t> prefixes;
		for (const auto& prefix : ipv6DestinationPrefixes)
		{
			prefixes.emplace(prefix.prefix);
		}
		return prefixes;
	}

public:
	tDecapId decapId;

	std::set<ipv6_prefix_with_announces_t> ipv6DestinationPrefixes;
	common::eDscpMarkType dscpMarkType;
	uint8_t dscp;
	uint8_t ipv6_enabled;
	std::string nextModule;
	common::globalBase::tFlow flow;
};

class nat64stateless_t
{
public:
	nat64stateless_t() :
	        dscpMarkType(common::eDscpMarkType::never),
	        dscp(0),
	        firewall(1),
	        farm(0)
	{
	}

public:
	tNat64statelessId nat64statelessId;

	common::eDscpMarkType dscpMarkType;
	uint8_t dscp;

	std::map<std::tuple<ipv6_address_t, ///< ipv6Address
	                    ipv6_address_t, ///< ipv6DestinationAddress
	                    std::optional<range_t>>, ///< ingressPortRange
	         std::tuple<ipv4_address_t,
	                    std::optional<range_t>, ///< egressPortRange
	                    tNat64statelessTranslationId>>
	        translations;

	uint8_t firewall;
	std::optional<ipv6_prefix_t> nat64_wkp_prefix;
	std::optional<ipv6_prefix_t> nat64_src_prefix;

	std::set<ip_prefix_with_announces_t> nat64_prefixes;

	std::string nextModule;
	common::globalBase::tFlow flow;

	std::optional<ipv6_address_t> defrag_farm_prefix;
	std::optional<ipv6_address_t> defrag_source_prefix;
	uint8_t farm;

	/// @todo: ingressFlow;
	/// @todo: egressFlow;
};

class acl_rule_network_ipv4_t
{
public:
	acl_rule_network_ipv4_t()
	{
	}

	acl_rule_network_ipv4_t(const std::set<ipv4_prefix_t>& sourcePrefixes,
	                        const std::set<ipv4_prefix_t>& destinationPrefixes) :
	        sourcePrefixes(sourcePrefixes),
	        destinationPrefixes(destinationPrefixes)
	{
	}

public:
	std::set<ipv4_prefix_t> sourcePrefixes;
	std::set<ipv4_prefix_t> destinationPrefixes;
};

class acl_rule_network_ipv6_t
{
public:
	acl_rule_network_ipv6_t()
	{
	}

	acl_rule_network_ipv6_t(const std::set<ipv6_prefix_t>& sourcePrefixes,
	                        const std::set<ipv6_prefix_t>& destinationPrefixes) :
	        sourcePrefixes(sourcePrefixes),
	        destinationPrefixes(destinationPrefixes)
	{
	}

public:
	std::set<ipv6_prefix_t> sourcePrefixes;
	std::set<ipv6_prefix_t> destinationPrefixes;
};

class acl_rule_transport_tcp_t
{
public:
	acl_rule_transport_tcp_t()
	{
	}

	acl_rule_transport_tcp_t(const ranges_t& sourcePorts,
	                         const ranges_t& destinationPorts) :
	        sourcePorts(sourcePorts),
	        destinationPorts(destinationPorts)
	{
	}

public:
	ranges_t sourcePorts;
	ranges_t destinationPorts;
	std::optional<std::pair<uint8_t, uint8_t>> flags;
};

class acl_rule_transport_udp_t
{
public:
	acl_rule_transport_udp_t()
	{
	}

	acl_rule_transport_udp_t(const ranges_t& sourcePorts,
	                         const ranges_t& destinationPorts) :
	        sourcePorts(sourcePorts),
	        destinationPorts(destinationPorts)
	{
	}

public:
	ranges_t sourcePorts;
	ranges_t destinationPorts;
};

class acl_rule_transport_icmpv4_t
{
public:
	acl_rule_transport_icmpv4_t() :
	        types(range_t{0x00, 0xFF}),
	        codes(range_t{0x00, 0xFF}),
	        identifiers(range_t{0x0000, 0xFFFF})
	{
	}

	acl_rule_transport_icmpv4_t(const ranges_t& types) :
	        types(types),
	        codes(range_t{0x00, 0xFF}),
	        identifiers(range_t{0x0000, 0xFFFF})
	{
	}

	acl_rule_transport_icmpv4_t(const ranges_t& types,
	                            const ranges_t& codes) :
	        types(types),
	        codes(codes),
	        identifiers(range_t{0x0000, 0xFFFF})
	{
	}

	acl_rule_transport_icmpv4_t(const ranges_t& types,
	                            const ranges_t& codes,
	                            const ranges_t& identifiers) :
	        types(types),
	        codes(codes),
	        identifiers(identifiers)
	{
	}

public:
	ranges_t types;
	ranges_t codes;
	ranges_t identifiers;
};

class acl_rule_transport_icmpv6_t
{
public:
	acl_rule_transport_icmpv6_t() :
	        types(range_t{0x00, 0xFF}),
	        codes(range_t{0x00, 0xFF}),
	        identifiers(range_t{0x0000, 0xFFFF})
	{
	}

	acl_rule_transport_icmpv6_t(const ranges_t& types) :
	        types(types),
	        codes(range_t{0x00, 0xFF}),
	        identifiers(range_t{0x0000, 0xFFFF})
	{
	}

	acl_rule_transport_icmpv6_t(const ranges_t& types,
	                            const ranges_t& codes) :
	        types(types),
	        codes(codes),
	        identifiers(range_t{0x0000, 0xFFFF})
	{
	}

	acl_rule_transport_icmpv6_t(const ranges_t& types,
	                            const ranges_t& codes,
	                            const ranges_t& identifiers) :
	        types(types),
	        codes(codes),
	        identifiers(identifiers)
	{
	}

public:
	ranges_t types;
	ranges_t codes;
	ranges_t identifiers;
};

class acl_rule_transport_other_t
{
public:
	acl_rule_transport_other_t()
	{
	}

	acl_rule_transport_other_t(const ranges_t& protocolTypes) :
	        protocolTypes(protocolTypes)
	{
	}

public:
	ranges_t protocolTypes;
};

class acl_rule_t
{
public:
	enum fragState ///< @todo: move
	{
		notFragmented = 0,
		firstFragment = 1,
		notFirstFragment = 2
	};

public:
	acl_rule_t()
	{
	}

	template<typename transport_T>
	acl_rule_t(const std::variant<acl_rule_network_ipv4_t, acl_rule_network_ipv6_t>& network,
	           const transport_T& transport,
	           const common::globalBase::tFlow& flow) :
	        network(network),
	        transport(transport),
	        flow(flow)
	{
	}

	template<typename transport_T>
	acl_rule_t(const std::variant<acl_rule_network_ipv4_t, acl_rule_network_ipv6_t>& network,
	           const fragState& fragState,
	           const transport_T& transport,
	           const common::globalBase::tFlow& flow) :
	        network(network),
	        fragment({fragState}),
	        transport(transport),
	        flow(flow)
	{
	}

	acl_rule_t(const std::variant<acl_rule_network_ipv4_t, acl_rule_network_ipv6_t>& network,
	           const common::globalBase::tFlow& flow) :
	        network(network),
	        flow(flow)
	{
	}

	acl_rule_t(const std::variant<acl_rule_network_ipv4_t, acl_rule_network_ipv6_t>& network,
	           const fragState& fragState,
	           const common::globalBase::tFlow& flow) :
	        network(network),
	        fragment({fragState}),
	        flow(flow)
	{
	}

	acl_rule_t(const std::variant<acl_rule_transport_tcp_t, acl_rule_transport_udp_t, acl_rule_transport_icmpv4_t, acl_rule_transport_icmpv6_t, acl_rule_transport_other_t>& transport,
	           const common::globalBase::tFlow& flow) :
	        transport(transport),
	        flow(flow)
	{
	}

	acl_rule_t(const common::globalBase::tFlow& flow) :
	        flow(flow)
	{
	}

public:
	std::optional<std::variant<acl_rule_network_ipv4_t,
	                           acl_rule_network_ipv6_t>>
	        network;

	std::optional<std::set<fragState>> fragment;

	std::optional<std::variant<acl_rule_transport_tcp_t,
	                           acl_rule_transport_udp_t,
	                           acl_rule_transport_icmpv4_t,
	                           acl_rule_transport_icmpv6_t,
	                           acl_rule_transport_other_t>>
	        transport;

	/// @todo: FIREWALL. std::optional<std::string> nextModule;
	std::optional<common::globalBase::tFlow> flow;
};

/// Describes FW states synchronization.
class acl_sync_config_t
{
public:
	/// Source IPv6 address for multicast packet.
	///
	/// Must be unique to be able to distinguish nodes. Also this field is
	/// used to discard self-messages if any.
	ipv6_address_t ipv6SourceAddress;
	/// Destination IPv6 multicast address.
	ipv6_address_t multicastIpv6Address;
	/// Source IPv6 unicast address.
	ipv6_address_t unicastIpv6SourceAddress;
	/// Destination IPv6 unicast address.
	ipv6_address_t unicastIpv6Address;
	/// UDP packet destination port.
	uint16_t multicastDestinationPort;
	/// UDP packet destination port for unicast.
	uint16_t unicastDestinationPort;
	/// List of logical interfaces (with vlan) where to send multicast packets.
	std::vector<std::string> logicalPorts;
	/// Next module for incoming multicast sync packets.
	std::string ingressNextModule;
};

class acl_t
{
public:
	acl_t()
	{
	}

public:
	tAclId aclId;

	ipfw::fw_config_ptr_t firewall;
	std::optional<acl_sync_config_t> synchronization;
	std::vector<std::string> nextModules;
	std::vector<acl_rule_t> nextModuleRules;

	std::set<common::ipv4_prefix_t> src4_early_decap;
	std::set<common::ipv4_prefix_t> dst4_early_decap;

	std::set<common::ipv6_prefix_t> src6_early_decap;
	std::set<common::ipv6_prefix_t> dst6_early_decap;
};

}

//

class base_rib
{
public:
	ip_prefix_t prefix;
	ip_address_t nexthop;
};

//

class base_t
{
public:
	base_t() :
	        interfacesCount(0),
	        nat64statelessTranslationsCount(0),
	        services_count(0),
	        reals_count(0),
	        tun64MappingsCount(0),
	        storeSamples(false),
	        serial(0),
	        nat64stateful_pool_size(0)
	{
		variables["balancer_real_timeout"] = 900;
	}

public:
	std::map<std::string, std::string> moduleTypes;
	tInterfaceId interfacesCount;
	tNat64statelessTranslationId nat64statelessTranslationsCount;
	balancer_service_id_t services_count;
	balancer_real_id_t reals_count;
	tun64_id_t tun64MappingsCount;
	std::map<tInterfaceId, std::string> interfaceNames; ///< @todo: per route
	std::map<tSocketId, std::set<tInterfaceId>> socket_interfaces; ///< @todo: per route

	std::map<std::string, base::logical_port_t> logicalPorts;
	std::map<std::string, route::config_t> routes;
	std::map<std::string, base::decap_t> decaps;
	std::map<std::string, nat64stateful::config_t> nat64statefuls;
	std::map<std::string, base::nat64stateless_t> nat64statelesses;
	std::map<std::string, nat46clat::config> nat46clats;
	std::map<std::string, base::acl_t> acls;
	std::map<std::string, dregress::config_t> dregresses;
	std::map<std::string, balancer::config_t> balancers;
	std::map<std::string, tun64::config_t> tunnels;
	std::vector<std::vector<uint32_t>> ids_map;
	std::map<uint32_t, std::vector<acl::rule_info_t>> rules;
	std::vector<acl::rule_info_t> dispatcher;
	acl::iface_map_t iface_map;
	acl::iface_map_t result_iface_map;
	std::vector<std::string> dump_id_to_tag;
	std::map<unsigned int, std::string> logicalport_id_to_name;
	bool storeSamples;
	uint32_t serial;

	std::map<std::string, common::uint64> variables;
	std::map<std::string, ///< vrf
	         std::map<common::ip_address_t,
	                  std::vector<std::string>>>
	        vrf_fqdns;

	uint32_t nat64stateful_pool_size;

	std::map<std::string, ///< vrf_name
	         std::vector<base_rib>>
	        rib;

	common::memory_manager::memory_group root_memory_group;
};

//

const base::acl_rule_network_ipv4_t acl_rule_network_ipv4_any = {{common::ipv4_prefix_default},
                                                                 {common::ipv4_prefix_default}};

const base::acl_rule_network_ipv6_t acl_rule_network_ipv6_any = {{common::ipv6_prefix_default},
                                                                 {common::ipv6_prefix_default}};

const base::acl_rule_transport_tcp_t acl_rule_transport_tcp_any = {range_t{0x0000, 0xFFFF}, range_t{0x0000, 0xFFFF}};
const base::acl_rule_transport_udp_t acl_rule_transport_udp_any = {range_t{0x0000, 0xFFFF}, range_t{0x0000, 0xFFFF}};
const base::acl_rule_transport_icmpv4_t acl_rule_transport_icmpv4_any = {};
const base::acl_rule_transport_icmpv6_t acl_rule_transport_icmpv6_any = {};

}
