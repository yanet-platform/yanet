#pragma once

#include "acl/bitset.h"
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
	unsigned int collect(const unsigned int rule_id, const filter& filter);
	void prepare();
	void compile();
	void compile_thread(const unsigned int thread_id, const unsigned int threads_count);

public:
	acl::compiler_t* compiler;

	std::map<common::acl::total_key_t, tAclGroupId> table;

	std::vector<tAclGroupId> remap_group_ids;
	tAclGroupId group_id;

	std::vector<filter> filters;
	std::map<filter, unsigned int> filter_ids;
	std::vector<unsigned int> filter_id_by_rule_id;
	FlatSet<unsigned int> filled_filter_ids;

	std::vector<uint8_t> bitmask; /// @todo: bitmask_t

	std::unordered_map<bitset_t, tAclGroupId> map;
	std::map<tAclGroupId, bitset_t> reverse_map;
	std::map<tAclGroupId, bitset_t> reverse_map_next;
};

}
