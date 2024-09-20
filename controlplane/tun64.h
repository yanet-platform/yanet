#pragma once

#include "base.h"
#include "counter.h"
#include "module.h"
#include "type.h"

#include "common/controlplaneconfig.h"
#include "common/generation.h"
#include "common/icp.h"
#include "common/idataplane.h"

namespace tun64
{

class generation_config_t
{
public:
	void update(const controlplane::base_t& base_prev,
	            const controlplane::base_t& base_next)
	{
		(void)base_prev;

		config_tunnels = base_next.tunnels;
	}

public:
	std::map<std::string, controlplane::tun64::config_t> config_tunnels;

	common::icp::tun64_tunnels::response tunnels;
	common::icp::tun64_prefixes::response prefixes;
	common::icp::tun64_mappings::mapping mappings;
};

}

class tun64_t : public module_t
{
public:
	tun64_t() = default;
	~tun64_t() override = default;

	eResult init() override;
	void reload_before() override;
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;
	void reload_after() override;

	common::icp::tun64_config::response tun64_config() const;
	common::icp::tun64_tunnels::response tun64_tunnels() const;
	common::icp::tun64_mappings::response tun64_mappings() const;
	common::icp::tun64_prefixes::response tun64_prefixes() const;

	void compile(common::idp::updateGlobalBase::request& globalbase, tun64::generation_config_t& generation_config);

protected:
	void counters_gc_thread();

protected:
	interface::dataPlane dataplane;
	generation_manager<tun64::generation_config_t> generations_config;

	friend class telegraf_t;
	counter_t<std::string, 6> tunnel_counters;
	counter_t<std::tuple<std::string, common::ipv4_address_t>, 4> mappings_counters;
};
