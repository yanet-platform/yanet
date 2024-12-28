#pragma once

#include <thread>

#include "acl_base.h"
#include "acl_table.h"

#include "common/idp.h"

namespace acl::compiler
{

class transport_table_t;

namespace transport_table
{

/* dimension:
 *   network_flags
 *   protocol
 *   group1
 *   group2
 *   group3
 *   network_table
 */
constexpr static unsigned int dimension = 6;

class layer_t
{
public:
	table_t<dimension> table;
	std::vector<tAclGroupId> remap_network_table_group_ids;
};

class thread_t
{
public:
	thread_t(transport_table_t* transport_table, const unsigned int thread_id, const unsigned int threads_count);

public:
	void start();
	void join();

protected:
	void prepare();
	void compile();
	void populate();
	void result();

	void table_insert(transport_table::layer_t& layer, const std::array<size_t, dimension>& table_indexes, const std::vector<unsigned int>& network_table_group_ids);
	void table_get(transport_table::layer_t& layer, const std::array<size_t, dimension>& table_indexes, const std::vector<unsigned int>& network_table_group_ids);

public:
	transport_table_t* transport_table;
	unsigned int thread_id;
	unsigned int threads_count;

	std::thread thread;

	std::map<unsigned int, transport_table::layer_t> layers;

	tAclGroupId group_id;
	std::vector<tAclGroupId> remap_group_ids;
	std::set<tAclGroupId> bitmask; /// @todo: bitmask_t

	std::vector<std::vector<tAclGroupId>> filter_id_group_ids;
	std::map<tAclGroupId, std::set<unsigned int>> group_id_filter_ids;
	std::vector<std::vector<tAclGroupId>> transport_table_filter_id_group_ids;
	// FIXME: I have a strong feeling that a containter with all groups should be already presented somewhere.
	// Even if it does not, maybe all I need is a vector, since we don't have to order groups.
	std::set<tAclGroupId> all_groups;

	common::idp::updateGlobalBase::acl_transport_table::request acl_transport_table;

	std::optional<std::exception_ptr> exception;
};

}

class transport_table_t
{
public:
	transport_table_t(acl::compiler_t* compiler, const unsigned int threads_count = 1);

public:
	using filter = std::tuple<unsigned int, ///< network_table_filter_id
	                          unsigned int, ///< network_flags_filter_id
	                          unsigned int>; ///< transport_filter_id

	void clear();
	unsigned int collect(const unsigned int rule_id, const filter& filter);
	void prepare();
	void compile();
	void populate();
	void remap();

public:
	acl::compiler_t* compiler;
	unsigned int threads_count;

	std::vector<transport_table::thread_t> threads;

	std::vector<filter> filters;
	std::map<filter, unsigned int> filter_ids;
	std::vector<std::vector<unsigned int>> filter_id_rule_ids;
};

}
