#pragma once

#include "acl/rule.h"

namespace acl::compiler
{

class filter_transport
{
public:
	filter_transport(const ::acl::rule_t& unwind_rule);

	constexpr bool operator<(const filter_transport& second) const
	{
		return std::tie(protocol,
		                tcp_source,
		                tcp_destination,
		                tcp_flags,
		                udp_source,
		                udp_destination,
		                icmpv4_type_code,
		                icmpv4_identifier,
		                icmpv6_type_code,
		                icmpv6_identifier) <
		       std::tie(second.protocol,
		                second.tcp_source,
		                second.tcp_destination,
		                second.tcp_flags,
		                second.udp_source,
		                second.udp_destination,
		                second.icmpv4_type_code,
		                second.icmpv4_identifier,
		                second.icmpv6_type_code,
		                second.icmpv6_identifier);
	}

	inline bool protocol_contain(const uint8_t protocol_value) const
	{
		for (const auto& range : protocol.vector)
		{
			if (range.from() <= protocol_value &&
			    range.to() >= protocol_value)
			{
				return true;
			}
		}

		return false;
	}

public:
	common::acl::ranges_uint8_t protocol;
	common::acl::ranges_uint16_t tcp_source;
	common::acl::ranges_uint16_t tcp_destination;
	common::acl::ranges_uint8_t tcp_flags;
	common::acl::ranges_uint16_t udp_source;
	common::acl::ranges_uint16_t udp_destination;
	common::acl::ranges_uint16_t icmpv4_type_code;
	common::acl::ranges_uint16_t icmpv4_identifier;
	common::acl::ranges_uint16_t icmpv6_type_code;
	common::acl::ranges_uint16_t icmpv6_identifier;

protected:
	template<typename ranges_t,
	         typename ref_filter_t>
	void insert(ranges_t& ranges,
	            ref_filter_t& ref_ranges)
	{
		for (const auto& range : ref_ranges->ranges)
		{
			ranges.vector.emplace_back(range.from(), range.to());
		}
	}

	template<typename ranges_t>
	void insert_any(ranges_t& ranges)
	{
		ranges.insert_any();
	}
};

class filter_network_flag
{
public:
	filter_network_flag(const ::acl::rule_t& unwind_rule);

public:
	common::acl::ranges_uint8_t fragment;
};

}
