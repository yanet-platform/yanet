#include "memory_manager.h"

using namespace controlplane::memory_manager;

void memory_manager::reload(const base_t& base_prev,
                            const base_t& base_next,
                            common::idp::updateGlobalBase::request& globalbase)
{
	(void)base_prev;
	(void)globalbase;
	dataplane.memory_manager_update(base_next.root_memory_group);
}
