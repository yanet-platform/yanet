#pragma once

#include "type.h"

namespace nat46clat
{

enum class module_counter : tCounterId
{
	lan_packets,
	lan_bytes,
	wan_packets,
	wan_bytes,
	enum_size
};

class config
{
public:
	config() = default;

	SERIALIZABLE(nat46clat_id, ipv6_source, ipv6_destination, dscp_mark_type, dscp, ipv6_prefixes, ipv4_prefixes, announces, next_module, vrf_lan_name, vrf_wan_name, vrf_lan, vrf_wan);

public:
	nat46clat_id_t nat46clat_id;
	common::ipv6_address_t ipv6_source;
	common::ipv6_address_t ipv6_destination;
	common::eDscpMarkType dscp_mark_type{common::eDscpMarkType::never};
	uint8_t dscp{};
	std::set<common::ipv6_prefix_t> ipv6_prefixes;
	std::set<common::ipv4_prefix_t> ipv4_prefixes;
	std::set<common::ip_prefix_t> announces;
	std::string vrf_lan_name;
	std::string vrf_wan_name;
	tVrfId vrf_lan;
	tVrfId vrf_wan;
	std::string next_module;
	common::globalBase::flow_t flow;
};
}
