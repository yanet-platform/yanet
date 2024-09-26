#pragma once

#include "base.h"
#include "counter.h"
#include "module.h"
#include "type.h"

#include "common/controlplaneconfig.h"
#include "common/counters.h"
#include "common/generation.h"
#include "common/icp.h"
#include "common/idataplane.h"

namespace nat64stateful
{

using module_counter_key_t = std::string; ///< module_name

class generation_config_t
{
public:
	void update([[maybe_unused]] const controlplane::base_t& base_prev,
	            const controlplane::base_t& base_next)
	{
		config_nat64statefuls = base_next.nat64statefuls;

		for (const auto& [name, nat64stateful] : base_next.nat64statefuls)
		{
			for (const auto& prefix : nat64stateful.announces)
			{
				announces.emplace(name, prefix);
			}
		}
	}

public:
	std::map<std::string, controlplane::nat64stateful::config_t> config_nat64statefuls;
	common::icp::nat64stateful_announce::response announces;
};

}

class nat64stateful_t : public module_t
{
public:
	eResult init() override;
	void reload_before() override;
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;
	void reload_after() override;

	common::icp::nat64stateful_config::response nat64stateful_config() const;
	common::icp::nat64stateful_announce::response nat64stateful_announce() const;

	void compile(common::idp::updateGlobalBase::request& globalbase, nat64stateful::generation_config_t& generation_config);

protected:
	void counters_gc_thread();

protected:
	interface::dataPlane dataplane;
	generation_manager<nat64stateful::generation_config_t> generations_config;

	friend class telegraf_t;
	counter_t<nat64stateful::module_counter_key_t, (size_t)nat64stateful::module_counter::size> module_counters;
};
