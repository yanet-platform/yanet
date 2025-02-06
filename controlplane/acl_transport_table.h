#pragma once

#include <thread>
#include <utility>

#include "acl/bitset.h"
#include "acl_base.h"
#include "ndarray.h"

#include "common/acl.h"
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
	NDArray<tAclGroupId, dimension> table;
	// TODO: try to use absl flat_hash_map or similar, since we do not need iterator stability
	std::unordered_map<tAclGroupId, tAclGroupId> remap_network_table_group_ids;

	void prepare_remap_map(
	        const std::vector<unsigned int>& network_table_group_ids_vec,
	        unsigned int transport_layers_shift)
	{
		remap_network_table_group_ids.reserve(network_table_group_ids_vec.size());

		for (tAclGroupId i = 0; i < network_table_group_ids_vec.size(); ++i)
		{
			tAclGroupId compressed = network_table_group_ids_vec[i] >> transport_layers_shift;

			remap_network_table_group_ids[compressed] = i;
		}
	}

	tAclGroupId lookup_remap_map(
	        tAclGroupId network_table_group_id,
	        unsigned int transport_layers_shift) const
	{
		tAclGroupId compressed = network_table_group_id >> transport_layers_shift;

		const auto it = remap_network_table_group_ids.find(compressed);
		return (it != remap_network_table_group_ids.end()) ? it->second : 0;
	}
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

	using DimensionArray = decltype(std::declval<layer_t>().table)::DimensionArray;

	// keys has dims #0..4 set
	void table_insert(transport_table::layer_t& layer, DimensionArray& keys, const std::vector<unsigned int>& network_table_group_ids);

	// keys has dims #0..4 set
	void table_get(transport_table::layer_t& layer, DimensionArray& keys, const std::vector<unsigned int>& network_table_group_ids);

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
