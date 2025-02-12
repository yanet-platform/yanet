#pragma once

#include "acl_base.h"

#include "common/acl.h"

namespace acl::compiler
{

class total_table_t
{
public:
	total_table_t(acl::compiler_t* compiler);

public:
	using filter = std::tuple<unsigned int, ///< via_filter_id
	                          unsigned int>; ///< transport_table_filter_id

	void clear();
	void collect(const unsigned int rule_id, const filter& filter);
	void prepare();
	void compile();

public:
	FlatMap<common::acl::total_key_t, unsigned int> table;

private:
	acl::compiler_t* compiler;
	std::unordered_map<unsigned int, std::vector<filter>> acl_rules_by_filter_id;
	std::unordered_map<tAclGroupId, std::unordered_map<unsigned int, std::set<unsigned int>>> group_to_acl_rule_map;
};
}
