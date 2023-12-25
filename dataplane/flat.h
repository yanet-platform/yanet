#pragma once

#include <inttypes.h>

#include <vector>

#include "common/define.h"
#include "common/result.h"
#include "common/type.h"

namespace dataplane
{

template<typename type_t>
class flat
{
public:
	constexpr static unsigned int bits = 8 * sizeof(type_t);

	class updater
	{
	public:
		updater()
		{
			clear();
		}

	public:
		void clear()
		{
			group_id = 1;
			values.fill(0);
		}

		template<typename ranges_t>
		void insert(const ranges_t& ranges)
		{
			remap.resize(0);
			remap.resize(group_id, 0);

			for (const auto& range : ranges.vector)
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
					if (values[i] < remap.size()) ///< check: don't override self rule
					{
						auto& remap_group_ip = remap[values[i]];
						if (!remap_group_ip)
						{
							remap_group_ip = group_id;
							group_id++;
						}

						values[i] = remap_group_ip;
					}
				}
			}
		}

		eResult normalize(type_t (&array)[1u << bits])
		{
			remap.resize(0);
			remap.resize(group_id, 0);
			group_id = 1;

			for (unsigned int i = 0;
			     i < 1u << bits;
			     i++)
			{
				auto& remap_group_ip = remap[values[i]];
				if (!remap_group_ip)
				{
					remap_group_ip = group_id;
					group_id++;
				}

				array[i] = remap_group_ip;
			}

			if (group_id > (1u << bits))
			{
				YANET_LOG_ERROR("overflow group_id: %u of %u\n", group_id, (1u << bits));
				return eResult::invalidCount;
			}

			return eResult::success;
		}

	public:
		tAclGroupId group_id;
		std::vector<tAclGroupId> remap;
		std::array<tAclGroupId, 1u << bits> values;
	};

public:
	template<typename ranges_t> ///< @todo: common::acl::ranges_t
	eResult update(updater& updater,
	               const std::vector<ranges_t>& rule)
	{
		eResult result = eResult::success;

		updater.clear();

		for (const auto& ranges : rule)
		{
			updater.insert(ranges);
		}

		result = updater.normalize(array);
		if (result != eResult::success)
		{
			return result;
		}

		return result;
	}

public:
	type_t array[1u << bits];
};

}
