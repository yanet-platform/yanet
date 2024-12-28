#include "memory_manager.h"

using namespace controlplane::memory_manager;

void memory_manager::reload([[maybe_unused]] const base_t& base_prev,
                            const base_t& base_next,
                            [[maybe_unused]] common::idp::updateGlobalBase::request& globalbase)
{
	dataplane.memory_manager_update(base_next.root_memory_group);
}
