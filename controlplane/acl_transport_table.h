#pragma once

#include <thread>
#include <utility>

#include "acl_base.h"
#include "ndarray.h"

#include "common/idp.h"

namespace acl::compiler
{

class transport_table_t;

namespace transport_table
{

struct Layer
{
	/* dimension:
	 *   network_flags
	 *   protocol
	 *   group1
	 *   group2
	 *   group3
	 *   network_table
	 */
	static constexpr auto Dimension = 6;

	NDArray<tAclGroupId, Dimension> table;
	GroupIds remap_network_table;
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

	using DimensionArray = decltype(std::declval<Layer>().table)::DimensionArray;

	// keys has dims #0..4 set
	void table_insert(transport_table::Layer& layer, DimensionArray& keys, const GroupIds& network_table_group_ids);

	// keys has dims #0..4 set
	void table_get(transport_table::Layer& layer, DimensionArray& keys, const GroupIds& network_table_group_ids);

public:
	transport_table_t* transport_table;
	unsigned int thread_id;
	unsigned int threads_count;

	std::thread thread;

	std::map<unsigned int, transport_table::Layer> layers;

	tAclGroupId group_id;
	GroupIds remap;
	std::set<tAclGroupId> bitmask; /// @todo: bitmask_t

	std::vector<GroupIds> filter_id_to_group_ids;
	std::map<tAclGroupId, std::set<tAclFilterId>> group_id_to_filter_ids;
	std::vector<GroupIds> transport_table_filter_id_to_group_ids;

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
	std::map<filter, tAclFilterId> filter_ids;
	std::vector<std::vector<unsigned int>> filter_id_to_rule_ids;
};

}
