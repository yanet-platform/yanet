#pragma once

#include "acl/bitset.h"
#include "acl/network.h"
#include "acl_base.h"
#include "acl_tree.h"

namespace acl::compiler
{

template<typename type_t>
class network_t
{
public:
	network_t(acl::compiler_t* compiler) :
	        compiler(compiler)
	{
		clear();
	}

public:
	using filter = std::set<::acl::network_t>;

	void clear()
	{
		tree.clear();
		remap.clear();
		group_id = 1;
		filters.clear();
		filter_ids.clear();
		filter_to_rule_ids.clear();
		filter_to_group_ids.clear();
		bitmask.clear();
		map.clear();
		reverse_map.clear();
		reverse_map_next.clear();
		collisions = 0;
	}

	unsigned int collect(const filter& filter)
	{
		auto it = filter_ids.find(filter);
		if (it == filter_ids.end())
		{
			for (const auto& network : filter)
			{
				tree.collect(network.addr, network.mask);
			}

			filters.emplace_back(filter);
			/// @todo: filter_rule_ids
			it = filter_ids.emplace_hint(it, filter, filter_ids.size());
		}

		return it->second;
	}

	void prepare()
	{
		tree.prepare();
		filter_to_group_ids.resize(filter_ids.size());
	}

	void compile()
	{
		for (unsigned int filter_id = 0;
		     filter_id < filters.size();
		     filter_id++)
		{
			remap.resize(0);
			remap.resize(group_id, 0);

			for (const auto& network : filters[filter_id])
			{
				tree.insert(network.addr, network.mask, group_id, remap);
			}
		}

		tree.merge(group_id);
	}

	void populate()
	{
		for (unsigned int filter_id = 0;
		     filter_id < filters.size();
		     filter_id++)
		{
			bitmask.resize(0);
			bitmask.resize(group_id, 0);

			for (const auto& network : filters[filter_id])
			{
				tree.get(network.addr, network.mask, bitmask);
			}

			for (unsigned int i = 0;
			     i < bitmask.size();
			     i++)
			{
				if (bitmask[i])
				{
					filter_to_group_ids[filter_id].emplace_back(i);
					reverse_map.try_emplace(i, bitset_t(filters.size()));
				}
			}
		}
	}

	void Remap(tAclGroupId& shared_group_id)
	{
		for (unsigned int filter_id = 0;
		     filter_id < filters.size();
		     filter_id++)
		{
			for (const auto& group_id : filter_to_group_ids[filter_id])
			{
				reverse_map.find(group_id)->second.insert(filter_id);
			}
		}

		remap.resize(0);
		remap.resize(group_id, 0);

		for (const auto& [group_id, filter_bitmask] : reverse_map)
		{
			auto it = map.find(filter_bitmask);
			if (it == map.end())
			{
				map.emplace_hint(it, filter_bitmask, group_id);

				remap[group_id] = shared_group_id;
				shared_group_id++;
			}
			else
			{
				/// dont panic. this is fine

				remap[group_id] = remap[it->second];
				collisions++;
			}
		}

		tree.Remap(remap);

		for (auto& group_ids : filter_to_group_ids)
		{
			for (auto& group_id : group_ids)
			{
				group_id = remap[group_id];
			}
		}

		for (const auto& [group_id, filter_bitmask] : reverse_map)
		{
			reverse_map_next.emplace(remap[group_id], filter_bitmask);
		}
		reverse_map.swap(reverse_map_next);

		tree.saved_group_ids.clear();
		group_id = shared_group_id;
	}

	const GroupIds& get_group_ids_by_filter(const filter& filter) const
	{
		const auto filter_id = filter_ids.find(filter)->second;
		return filter_to_group_ids[filter_id];
	}

	GroupIds get_group_ids_by_prefix(const ::acl::network_t& network)
	{
		GroupIds result;

		bitmask.resize(0);
		bitmask.resize(group_id, 0);

		tree.get(network.addr, network.mask, bitmask);

		for (unsigned int i = 0;
		     i < bitmask.size();
		     i++)
		{
			if (bitmask[i])
			{
				result.emplace_back(i);
			}
		}

		return result;
	}

	tAclGroupId get_group_ids_by_address(const type_t& address)
	{
		return tree.lookup(address);
	}

public:
	acl::compiler_t* compiler;

	tree_t<type_t, 8> tree;

	GroupIds remap;
	tAclGroupId group_id;

	std::vector<filter> filters;
	std::map<filter, unsigned int> filter_ids;
	std::vector<std::vector<unsigned int>> filter_to_rule_ids;

	std::vector<GroupIds> filter_to_group_ids;

	std::vector<uint8_t> bitmask; /// @todo: bitmask_t

	std::unordered_map<bitset_t, tAclGroupId> map;
	std::map<tAclGroupId, bitset_t> reverse_map;
	std::map<tAclGroupId, bitset_t> reverse_map_next;

	unsigned int collisions;
};

}
