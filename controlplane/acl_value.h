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
	using filter = std::vector<std::variant<common::globalBase::flow_t, common::acl::action_t>>;

	void clear();
	unsigned int collect(const filter& filter);
	unsigned int collect(const tAclGroupId prev_id, const tAclGroupId id);
	void compile();

public:
	std::vector<common::acl::value_t> vector;

	std::vector<filter> filters;
	std::map<filter, tAclFilterId> filter_ids;
};

}
