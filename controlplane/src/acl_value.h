#pragma once

#include "acl_base.h"

#include "common/type.h"
#include "common/acl.h"

namespace acl::compiler
{

class value_t
{
public:
	value_t();

public:
	using filter = common::globalBase::flow_t;

	void clear();
	unsigned int collect(const filter& filter);
	void compile();

public:
	std::vector<common::acl::value_t> vector;

	std::vector<filter> filters;
	std::map<filter, unsigned int> filter_ids;
};

}
