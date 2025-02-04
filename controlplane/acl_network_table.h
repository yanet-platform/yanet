#pragma once

#include "acl_base.h"
#include <map>
#include <set>

namespace acl::compiler
{

class network_table_t
{
public:
	network_table_t(acl::compiler_t* compiler);

public:
	using filter = std::tuple<unsigned int, ///< network_ipv4_source_filter_id
	                          unsigned int, ///< network_ipv4_destination_filter_id
	                          unsigned int, ///< network_ipv6_source_filter_id
	                          unsigned int>; ///< network_ipv6_destination_filter_id

	void clear();
	unsigned int collect(const unsigned int rule_id, const filter& filter);
	void prepare(const uint32_t height, const uint32_t width);
	void compile();
	void populate();
	void Remap();

public:
	acl::compiler_t* compiler;

	uint32_t width;
	GroupIds values;

	GroupIds remap;
	tAclGroupId group_id;

	std::vector<filter> filters;
	std::map<filter, unsigned int> filter_ids;
	std::vector<std::vector<unsigned int>> filter_id_to_rule_ids;
	std::vector<GroupIds> filter_id_to_group_ids;
	std::map<tAclGroupId, std::set<unsigned int>> group_id_to_filter_ids;

	std::vector<GroupIds> filter_id_to_group_ids_next;
	std::map<tAclGroupId, std::set<unsigned int>> group_id_to_filter_ids_next;

	std::vector<uint8_t> bitmask; /// @todo: bitmask_t
};

}
