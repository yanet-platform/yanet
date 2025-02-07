#pragma once

#include "acl/bitset.h"
#include "acl_base.h"
#include "ndarray.h"

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
	void remap();

public:
	acl::compiler_t* compiler;

	uint32_t width;
	/* dimension:
	 *   network_source
	 *   network_destination
	 */
	constexpr static unsigned int dimension = 2;

	NDArray<tAclGroupId, dimension> table;

	using DimensionArray = decltype(table)::DimensionArray;

	void table_insert(const DimensionArray& keys);
	void table_get(const DimensionArray& keys);

	std::vector<tAclGroupId> remap_group_ids;
	tAclGroupId group_id;

	std::vector<filter> filters;
	std::map<filter, unsigned int> filter_ids;
	std::vector<std::vector<unsigned int>> filter_id_rule_ids;
	std::vector<std::vector<tAclGroupId>> filter_id_group_ids;
	std::map<tAclGroupId, std::set<unsigned int>> group_id_filter_ids;

	std::vector<std::vector<tAclGroupId>> filter_id_group_ids_next;
	std::map<tAclGroupId, std::set<unsigned int>> group_id_filter_ids_next;

	std::vector<uint8_t> bitmask; /// @todo: bitmask_t
};

}
