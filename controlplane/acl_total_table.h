#pragma once

#include "acl_base.h"

#include "common/acl.h"
#include "common/type.h"

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

	using AclRuleIdsMap = std::unordered_map<unsigned int, std::vector<tAclRuleId>>;
	std::unordered_map<unsigned int, AclRuleIdsMap> filter_id_acl_id_rule_ids;
};
}
