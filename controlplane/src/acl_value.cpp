#include "acl_value.h"
#include "acl_compiler.h"

using namespace acl::compiler;

value_t::value_t()
{
	clear();
}

void value_t::clear()
{
	vector.clear();
	filters.clear();
	filter_ids.clear();

	{
		/// @todo: find default_flow
		common::globalBase::flow_t default_flow;
		default_flow.type = common::globalBase::eFlowType::drop;
		collect(default_flow);
	}
}

unsigned int value_t::collect(const filter& filter)
{
	auto it = filter_ids.find(filter);
	if (it == filter_ids.end())
	{
		filters.emplace_back(filter);
		it = filter_ids.emplace_hint(it, filter, filter_ids.size());
	}

	return it->second;
}

void value_t::compile()
{
	for (const auto& filter : filters)
	{
		common::acl::value_t value;
		value.flow = filter;
		vector.emplace_back(std::move(value));
	}
}
