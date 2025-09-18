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
#include "libprotobuf/controlplane.pb.h"

#include <queue>

namespace proxy
{

using service_counter_key_t = proxy_service_id_t;

class generation_config_t
{
public:
	void update([[maybe_unused]] const controlplane::base_t& base_prev,
	            const controlplane::base_t& base_next)
	{
		config_proxies = base_next.proxies;
	}

public:
	std::map<std::string, controlplane::proxy::config_t> config_proxies;
};

}

class proxy_t : public module_t, common::icp_proto::BalancerService
{
public:
    proxy_t() = default;
	~proxy_t() override = default;

	eResult init() override;
	void reload_before() override;
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;
	void reload_after() override;

	void compile(common::idp::updateGlobalBase::request& globalbase, proxy::generation_config_t& generation_config);

protected:
	interface::dataPlane dataplane;
	generation_manager<proxy::generation_config_t> generations_config;

    void counters_gc_thread();
    common::icp::proxy_counters::response proxy_counters(const common::icp::proxy_counters::request& request) const;
	common::icp::proxy_connections::response proxy_connections(const common::icp::proxy_connections::request& request) const;
	common::icp::proxy_syn::response proxy_syn(const common::icp::proxy_syn::request& request) const;
	common::icp::proxy_tables::response proxy_tables(const common::icp::proxy_tables::request& request) const;
	common::icp::proxy_buckets::response proxy_buckets(const common::icp::proxy_buckets::request& request) const;
	common::icp::proxy_debug_counters_id::response proxy_debug_counters_id(const common::icp::proxy_debug_counters_id::request& request);
	common::icp::proxy_blacklist::response proxy_blacklist(const common::icp::proxy_blacklist::request& request);
	common::icp::proxy_blacklist_add::response proxy_blacklist_add(const common::icp::proxy_blacklist_add::request& request);

    std::map<std::string, proxy_id_t> modules;
    std::map<std::tuple<common::ip_address_t, tPortId, uint8_t>, proxy_service_id_t> services;
    counter_t<proxy::service_counter_key_t, (size_t)proxy::service_counter::size> service_counters;
};
