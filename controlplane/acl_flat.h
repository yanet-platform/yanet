#pragma once

#include "acl/bitset.h"
#include "acl_base.h"

#include "common/acl.h"

namespace acl::compiler
{

/*
 * collect: 3-5
 *   filter_ids: [...XXX..]
 *
 * collect: 1,7
 *   filter_ids: [...XXX..]
 *               [.X.....X]
 *
 * collect: 1-4
 *   filter_ids: [...XXX..]
 *               [.X.....X]
 *               [ XXXX...]
 *
 * collect: 5
 *   filter_ids: [...XXX..]
 *               [.X.....X]
 *               [ XXXX...]
 *               [ ....X..]
 *
 * compile:
 *   values: [...111..]
 *   values: [.2.111.2]
 *   values: [.34551.2]
 *   values: [.34556.2]
 *
 * remap:
 *   values: [12344516]
 */

template<typename type_t>
class flat_t
{
public:
	flat_t()
	{
		clear();
	}

public:
	using filter = common::acl::ranges_t<type_t>;

	constexpr static unsigned int bits = 8 * sizeof(type_t);

	void clear()
	{
		values.fill(0);
		remap_group_ids.clear();
		group_id = 1;
		filters.clear();
		filter_ids.clear();
		filter_id_group_ids.clear();
		used_group_ids_set.clear();
		used_group_ids_vec.clear();
	}

	unsigned int collect(const filter& filter)
	{
		auto it = filter_ids.find(filter);
		if (it == filter_ids.end())
		{
			filters.emplace_back(filter);
			it = filter_ids.emplace_hint(it, filter, filter_ids.size());
		}

		return it->second;
	}

	void prepare()
	{
		filter_id_group_ids.resize(filter_ids.size());
	}

	void compile()
	{
		for (unsigned int filter_id = 0;
		     filter_id < filters.size();
		     filter_id++)
		{
			remap_group_ids.clear();
			remap_group_ids.resize(group_id, 0);

			for (const auto& range : filters[filter_id].vector)
			{
				if (range.from() == 0 &&
				    range.to() == (1u << bits) - 1)
				{
					continue;
				}

				for (unsigned int i = range.from();
				     i <= range.to();
				     i++)
				{
					if (values[i] < remap_group_ids.size()) ///< check: don't override self rule
					{
						auto& remap_group_id = remap_group_ids[values[i]];
						if (!remap_group_id)
						{
							remap_group_id = group_id;
							group_id++;
						}

						values[i] = remap_group_id;
					}
				}
			}
		}

		remap();
	}

	void populate()
	{
		for (unsigned int filter_id = 0;
		     filter_id < filters.size();
		     filter_id++)
		{
			FlatSet<tAclGroupId> group_ids;

			for (const auto& range : filters[filter_id].vector)
			{
				if (range.from() == 0 &&
				    range.to() == (1u << bits) - 1)
				{
					for (tAclGroupId group_id = 1;
					     group_id < this->group_id;
					     group_id++)
					{
						group_ids.emplace(group_id);
					}
					break;
				}

				for (unsigned int i = range.from();
				     i <= range.to();
				     i++)
				{
					group_ids.emplace(values[i]);
				}
			}

			for (const auto group_id : group_ids)
			{
				filter_id_group_ids[filter_id].emplace_back(group_id);
				used_group_ids_set.emplace(group_id);
			}
		}

		for (const auto group_id : used_group_ids_set)
		{
			used_group_ids_vec.emplace_back(group_id);
		}
	}

	tAclGroupId get(const type_t& i) const
	{
		return values[i];
	}

	const std::vector<tAclGroupId>& get_group_ids_by_filter(const filter& filter) const
	{
		const auto filter_id = filter_ids.find(filter)->second;
		return filter_id_group_ids[filter_id];
	}

public:
	std::array<tAclGroupId, 1u << bits> values;

	std::vector<tAclGroupId> remap_group_ids;
	tAclGroupId group_id;

	std::vector<filter> filters;
	std::map<filter, unsigned int> filter_ids;
	std::vector<std::vector<tAclGroupId>> filter_id_group_ids;

	FlatSet<tAclGroupId> used_group_ids_set;
	std::vector<tAclGroupId> used_group_ids_vec;

protected:
	void remap()
	{
		remap_group_ids.clear();
		remap_group_ids.resize(group_id, 0);

		group_id = 1;

		for (unsigned int i = 0;
		     i < 1u << bits;
		     i++)
		{
			auto& remap_group_ip = remap_group_ids[values[i]];
			if (!remap_group_ip)
			{
				remap_group_ip = group_id;
				group_id++;
			}

			values[i] = remap_group_ip;
		}

		if (group_id > (1u << bits))
		{
			throw std::runtime_error("overflow group_id");
		}
	}
};

}
