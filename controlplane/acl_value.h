#pragma once

#include "acl_base.h"

#include "common/acl.h"
#include "common/type.h"

namespace acl::compiler
{

class value_t
{
public:
	value_t();

public:
	using action_t = common::globalBase::eActionType;
	using value_filter = std::vector<std::variant<common::globalBase::flow_t, common::acl::action_t>>;

	void clear();
	unsigned int collect(const value_filter& filter);
	unsigned int collect(const tAclGroupId prev_id, const tAclGroupId id);
	void compile();

public:
	std::vector<common::acl::value_t> values;

	std::vector<value_filter> filters;
	std::map<value_filter, unsigned int> filter_ids;

	// std::array<std::vector<common::acl::action_array_t>, YANET_CONFIG_ACL_VALUE_ACTIONS_SIZE> actions;
	// std::array<std::map<common::acl::action_array_t, unsigned int>, YANET_CONFIG_ACL_VALUE_ACTIONS_SIZE> action_ids;
	common::globalBase::tActions<std::vector<common::acl::action_array_t>> actions;
	common::globalBase::tActions<std::map<common::acl::action_array_t, unsigned int>> action_ids;


private:
	class action_ids_array
	{
	public:
		action_ids_array() :
		        action(action_t::size),
		        size(0),
		        max_size(0)
		{
			values.fill(0);
		};

		action_ids_array(action_t action) :
		        action(action),
		        size(0)
		{
			values.fill(0);

			switch (action)
			{
				case action_t::dump:
					max_size = eActionType_max_size(action_t::dump);
					break;
				case action_t::count:
					max_size = eActionType_max_size(action_t::count);
					break;
				default:
					max_size = 0;
			}
		};

	public:
		void add(const uint32_t action_id)
		{
			if (size < max_size)
			{
				values[size] = action_id;
				size++;
			}
		}

	public:
		action_t action;
		common::acl::action_array_t values;

	private:
		size_t size;
		size_t max_size;
	};

private:
	uint32_t collect(const action_ids_array& filter);
};
}
