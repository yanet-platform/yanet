#pragma once

#include <stdint.h>
#include <string.h>

namespace latch
{

void dataplane_update(
             std::string name,
	     uint32_t state)
{
	common::idp::debug_latch_update::id id = common::idp::debug_latch_update::id::size;
	if (name == "GB_PREUPDATE")
	{
		id = common::idp::debug_latch_update::id::global_base_pre_update;
	}
	else if (name == "GB_POSTUPDATE")
	{
		id = common::idp::debug_latch_update::id::global_base_post_update;
	}
	else if (name == "GB_SWITCH")
	{
		id = common::idp::debug_latch_update::id::global_base_switch;
	}
	else if (name == "GB_UPDATE_BALANCER")
	{
		id = common::idp::debug_latch_update::id::global_base_update_balancer;
	}
	else if (name == "BALANCER_UPDATE")
	{
		id = common::idp::debug_latch_update::id::balancer_update;
	}

	common::idp::debug_latch_update::request request(id, state);

	interface::dataPlane dataplane;
	dataplane.debug_latch_update(request);
}

}
