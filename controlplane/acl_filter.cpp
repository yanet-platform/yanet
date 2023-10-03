#include "acl_filter.h"

using namespace acl::compiler;

filter_transport::filter_transport(const ::acl::rule_t& unwind_rule)
{
	if (unwind_rule.filter->proto)
	{
		const filter_proto_t* proto_filter = unwind_rule.filter->proto.filter;

		if (proto_filter->type)
		{
			insert(protocol, proto_filter->type);

			for (const auto& range : proto_filter->type->ranges)
			{
				for (unsigned int proto = range.from();
				     proto <= range.to();
				     proto++)
				{
					if (proto == IPPROTO_TCP)
					{
						if (proto_filter->prm1)
						{
							insert(tcp_source, proto_filter->prm1);
						}
						else
						{
							insert_any(tcp_source);
						}

						if (proto_filter->prm2)
						{
							insert(tcp_destination, proto_filter->prm2);
						}
						else
						{
							insert_any(tcp_destination);
						}

						if (proto_filter->prm3)
						{
							insert(tcp_flags, proto_filter->prm3);
						}
						else
						{
							insert_any(tcp_flags);
						}
					}
					else if (proto == IPPROTO_UDP)
					{
						if (proto_filter->prm1)
						{
							insert(udp_source, proto_filter->prm1);
						}
						else
						{
							insert_any(udp_source);
						}

						if (proto_filter->prm2)
						{
							insert(udp_destination, proto_filter->prm2);
						}
						else
						{
							insert_any(udp_destination);
						}

						if (proto_filter->prm3)
						{
							throw std::runtime_error("filter prm3 not empty");
						}
					}
					else if (proto == IPPROTO_ICMP)
					{
						if (proto_filter->prm1)
						{
							insert(icmpv4_type_code, proto_filter->prm1);
						}
						else
						{
							insert_any(icmpv4_type_code);
						}

						if (proto_filter->prm2)
						{
							insert(icmpv4_identifier, proto_filter->prm2);
						}
						else
						{
							insert_any(icmpv4_identifier);
						}

						if (proto_filter->prm3)
						{
							throw std::runtime_error("filter prm3 not empty");
						}
					}
					else if (proto == IPPROTO_ICMPV6)
					{
						if (proto_filter->prm1)
						{
							insert(icmpv6_type_code, proto_filter->prm1);
						}
						else
						{
							insert_any(icmpv6_type_code);
						}

						if (proto_filter->prm2)
						{
							insert(icmpv6_identifier, proto_filter->prm2);
						}
						else
						{
							insert_any(icmpv6_identifier);
						}

						if (proto_filter->prm3)
						{
							throw std::runtime_error("filter prm3 not empty");
						}
					}
				}
			}
		}
		else
		{
			insert_any(protocol);
			insert_any(tcp_source);
			insert_any(tcp_destination);
			insert_any(tcp_flags);
			insert_any(udp_source);
			insert_any(udp_destination);
			insert_any(icmpv4_type_code);
			insert_any(icmpv4_identifier);
			insert_any(icmpv6_type_code);
			insert_any(icmpv6_identifier);
		}
	}
	else
	{
		insert_any(protocol);
		insert_any(tcp_source);
		insert_any(tcp_destination);
		insert_any(tcp_flags);
		insert_any(udp_source);
		insert_any(udp_destination);
		insert_any(icmpv4_type_code);
		insert_any(icmpv4_identifier);
		insert_any(icmpv6_type_code);
		insert_any(icmpv6_identifier);
	}
}

filter_network_flag::filter_network_flag(const ::acl::rule_t& unwind_rule)
{
	if (unwind_rule.filter->flags)
	{
		for (const auto& range : unwind_rule.filter->flags->ranges)
		{
			if (range.from() != range.to())
			{
				throw std::runtime_error("range not supported");
			}

			if (range.from() == controlplane::base::acl_rule_t::fragState::notFragmented)
			{
				/// @todo: fragment.emplace(0, YANET_NETWORK_FLAG_FRAGMENT | YANET_NETWORK_FLAG_NOT_FIRST_FRAGMENT);
				fragment.vector.emplace_back(0);
				fragment.vector.emplace_back(YANET_NETWORK_FLAG_HAS_EXTENSION);
			}
			else if (range.from() == controlplane::base::acl_rule_t::fragState::firstFragment)
			{
				/// @todo: fragment.emplace(YANET_NETWORK_FLAG_FRAGMENT, YANET_NETWORK_FLAG_FRAGMENT | YANET_NETWORK_FLAG_NOT_FIRST_FRAGMENT);
				fragment.vector.emplace_back(YANET_NETWORK_FLAG_FRAGMENT);
				fragment.vector.emplace_back(YANET_NETWORK_FLAG_FRAGMENT | YANET_NETWORK_FLAG_HAS_EXTENSION);
			}
			else if (range.from() == controlplane::base::acl_rule_t::fragState::notFirstFragment)
			{
				/// @todo: fragment.emplace(YANET_NETWORK_FLAG_FRAGMENT | YANET_NETWORK_FLAG_NOT_FIRST_FRAGMENT, YANET_NETWORK_FLAG_FRAGMENT | YANET_NETWORK_FLAG_NOT_FIRST_FRAGMENT);
				fragment.vector.emplace_back(YANET_NETWORK_FLAG_FRAGMENT | YANET_NETWORK_FLAG_NOT_FIRST_FRAGMENT);
				fragment.vector.emplace_back(YANET_NETWORK_FLAG_FRAGMENT | YANET_NETWORK_FLAG_NOT_FIRST_FRAGMENT | YANET_NETWORK_FLAG_HAS_EXTENSION);
			}
			else
			{
				throw std::runtime_error("unknown fragState");
			}
		}
	}
	else
	{
		fragment.vector.emplace_back(0, 255);
	}
}
