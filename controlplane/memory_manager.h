#pragma once

#include "base.h"
#include "module.h"
#include "type.h"

#include "common/idataplane.h"

namespace controlplane::memory_manager
{

class memory_manager : public module_t
{
public:
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;

protected:
	interface::dataPlane dataplane;
};

}
