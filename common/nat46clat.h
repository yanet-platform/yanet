#pragma once

#include "stream.h"
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
	config() :
	        dscp_mark_type(common::eDscpMarkType::never),
	        dscp(0)
	{
	}

	void pop(common::stream_in_t& stream)
	{
		stream.pop(nat46clat_id);
		stream.pop(ipv6_source);
		stream.pop(ipv6_destination);
		stream.pop(dscp_mark_type);
		stream.pop(dscp);
		stream.pop(ipv6_prefixes);
		stream.pop(ipv4_prefixes);
		stream.pop(announces);
		stream.pop(next_module);
	}

	void push(common::stream_out_t& stream) const
	{
		stream.push(nat46clat_id);
		stream.push(ipv6_source);
		stream.push(ipv6_destination);
		stream.push(dscp_mark_type);
		stream.push(dscp);
		stream.push(ipv6_prefixes);
		stream.push(ipv4_prefixes);
		stream.push(announces);
		stream.push(next_module);
	}

public:
	nat46clat_id_t nat46clat_id;
	common::ipv6_address_t ipv6_source;
	common::ipv6_address_t ipv6_destination;
	common::eDscpMarkType dscp_mark_type;
	uint8_t dscp;
	std::set<common::ipv6_prefix_t> ipv6_prefixes;
	std::set<common::ipv4_prefix_t> ipv4_prefixes;
	std::set<common::ip_prefix_t> announces;
	std::string next_module;
	common::globalBase::flow_t flow;
};

}
