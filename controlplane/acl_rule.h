#pragma once

namespace acl::compiler
{

class rule_t
{
public:
	rule_t(const unsigned int rule_id) :
	        rule_id(rule_id)
	{
	}

public:
	unsigned int rule_id;
	unsigned int network_ipv4_source_filter_id;
	unsigned int network_ipv4_destination_filter_id;
	unsigned int network_ipv6_source_filter_id;
	unsigned int network_ipv6_destination_filter_id;
	unsigned int network_table_filter_id;
	unsigned int network_flags_filter_id;
	unsigned int transport_filter_id;
	unsigned int transport_table_filter_id;
	unsigned int via_filter_id;
	unsigned int value_filter_id;
	bool terminating;
};

}
