#pragma once

#include "base.h"
#include "counter.h"
#include "module.h"
#include "type.h"

#include "common/generation.h"
#include "common/icp.h"
#include "common/idataplane.h"
#include "common/nat46clat.h"

namespace nat46clat
{

using module_counter_key_t = std::string; ///< module_name

//

class generation_config
{
public:
	void update(const controlplane::base_t& base_prev, const controlplane::base_t& base_next);

public:
	std::map<std::string, nat46clat::config> config_nat46clats;
	common::icp::nat46clat_announce::response announces;
};

//

class manager : public module_t
{
public:
	eResult init() override;
	void reload_before() override;
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;
	void reload_after() override;

	common::icp::nat46clat_config::response nat46clat_config() const;
	common::icp::nat46clat_announce::response nat46clat_announce() const;
	common::icp::nat46clat_stats::response nat46clat_stats() const;

	void compile(common::idp::updateGlobalBase::request& globalbase, nat46clat::generation_config& generation_config);

protected:
	void counters_gc_thread();

protected:
	interface::dataPlane dataplane;
	generation_manager<nat46clat::generation_config> generations_config;

	counter_t<nat46clat::module_counter_key_t, (size_t)nat46clat::module_counter::enum_size> module_counters;
};

}
